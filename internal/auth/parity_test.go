package auth

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"protonvpn-wg-confgen/internal/api"
	"protonvpn-wg-confgen/internal/config"
	"protonvpn-wg-confgen/internal/vpn"
)

// The goldens are raw requests recorded from Proton's own packages, see
// test/parity/official.py. These tests run the same calls through this client
// against a raw socket and require the bytes to match.
const goldenDir = "../../test/parity/testdata"

// recorder is a raw TCP server: it keeps every request exactly as received and
// answers like the mock the goldens were recorded against.
type recorder struct {
	listener net.Listener
	mu       sync.Mutex
	requests [][]byte
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })

	authInfo, err := os.ReadFile(filepath.Join(goldenDir, "auth_info_response.json"))
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			r.serve(conn, authInfo)
		}
	}()
	return r
}

func (r *recorder) serve(conn net.Conn, authInfo []byte) {
	defer func() { _ = conn.Close() }()

	// Tee what the HTTP parser consumes, so the raw bytes survive parsing.
	var raw bytes.Buffer
	req, err := http.ReadRequest(bufio.NewReader(io.TeeReader(conn, &raw)))
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, req.Body)

	r.mu.Lock()
	r.requests = append(r.requests, bytes.Clone(raw.Bytes()))
	r.mu.Unlock()

	status, payload := "200 OK", []byte(`{"Code": 1000}`)
	switch req.URL.Path {
	case "/auth/info":
		payload = authInfo
	case "/auth":
		status, payload = "422 Unprocessable Entity", []byte(`{"Code": 8002, "Error": "Incorrect login credentials. Please try again"}`)
	case "/auth/2fa":
		payload = []byte(`{"Code": 1000, "Scopes": ["vpn"]}`)
	case "/auth/refresh":
		payload = []byte(`{"Code": 1000, "AccessToken": "TOKEN2", "RefreshToken": "REFRESH2", "Scopes": ["vpn"]}`)
	}
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", status, len(payload), payload)
}

func (r *recorder) url() string { return "http://" + r.listener.Addr().String() }

func (r *recorder) take(t *testing.T, n int) [][]byte {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) != n {
		t.Fatalf("recorded %d requests, want %d", len(r.requests), n)
	}
	out := r.requests
	r.requests = nil
	return out
}

var (
	hostLine     = regexp.MustCompile(`(?m)^Host: 127\.0\.0\.1:\d+\r$`)
	timezoneLine = regexp.MustCompile(`(?m)^x-pm-timezone: [^\r]*\r\n`)
	archSuffix   = regexp.MustCompile(`(?m)^(x-pm-appversion: [^+\r]+\+)[^\r]+\r$`)
	srpValue     = regexp.MustCompile(`"(ClientEphemeral|ClientProof)": "([^"]*)"`)
)

// normalize removes what legitimately differs between two runs: the port, the
// machine's timezone and CPU, and the random SRP values. SRP values keep their
// length, so Content-Length is still compared.
func normalize(raw []byte, hasTimezone bool) string {
	s := hostLine.ReplaceAllString(string(raw), "Host: 127.0.0.1:PORT\r")
	s = archSuffix.ReplaceAllString(s, "${1}ARCH\r")
	if hasTimezone {
		s = timezoneLine.ReplaceAllString(s, "x-pm-timezone: ZONE\r\n")
	} else {
		s = timezoneLine.ReplaceAllString(s, "")
	}
	return srpValue.ReplaceAllStringFunc(s, func(m string) string {
		parts := srpValue.FindStringSubmatch(m)
		return `"` + parts[1] + `": "<` + strconv.Itoa(len(parts[2])) + ` chars>"`
	})
}

// systemHasTimezone reports whether this machine can resolve a timezone name.
// The official client omits the header when it cannot, and so does this one.
func systemHasTimezone() bool {
	path, err := filepath.EvalSymlinks("/etc/localtime")
	return err == nil && strings.Contains(filepath.ToSlash(path), "zoneinfo/")
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join(goldenDir, name+".http")) //nolint:gosec // G304: fixed testdata path
	if err != nil {
		t.Fatal(err)
	}
	hasTimezone := systemHasTimezone()
	if g, w := normalize(got, hasTimezone), normalize(want, hasTimezone); g != w {
		t.Errorf("%s differs from the official client\n got: %q\nwant: %q", name, g, w)
	}
}

// TestLoginMatchesOfficialClient covers a fresh password login: the transport
// probe, the SRP parameters request and the SRP proof.
func TestLoginMatchesOfficialClient(t *testing.T) {
	rec := newRecorder(t)
	cfg := &config.Config{APIURL: rec.url(), Username: "parityuser", Password: "parity-password", NoSession: true}

	if _, err := NewClient(cfg).Authenticate(); err == nil {
		t.Fatal("the mock rejects the password, login should fail")
	}

	requests := rec.take(t, 3)
	for i, name := range []string{"ping", "auth_info", "auth"} {
		assertGolden(t, name, requests[i])
	}
}

// TestAuthenticatedRequestsMatchOfficialClient covers an established session:
// a plain GET, the 2FA submission and the token refresh.
func TestAuthenticatedRequestsMatchOfficialClient(t *testing.T) {
	rec := newRecorder(t)
	cfg := &config.Config{APIURL: rec.url(), Username: "parityuser", NoSession: true}
	session := &api.Session{UID: "UIDVALUE", AccessToken: "TOKENVALUE", RefreshToken: "REFRESHVALUE"}
	client := NewClient(cfg)

	if _, err := vpn.NewClient(cfg, session).GetServers(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.submit2FA(session, "123456"); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshSession(client.httpClient, cfg.APIURL, session); err != nil {
		t.Fatal(err)
	}

	requests := rec.take(t, 3)
	for i, name := range []string{"logicals", "auth_2fa", "auth_refresh"} {
		assertGolden(t, name, requests[i])
	}
}

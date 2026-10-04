package api

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"protonvpn-wg-confgen/internal/constants"
)

// NewHTTPClient returns a client that speaks HTTP/1.1 only. The official Linux
// client uses aiohttp, which has no HTTP/2 support, so negotiating h2 would be
// a visible difference. An empty TLSNextProto map is how net/http disables it.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:        http.ProxyFromEnvironment,
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
	}
}

// localTimezone returns the IANA name of the system timezone, e.g.
// "Europe/Zurich", or "" when it cannot be resolved. It mirrors the official
// client's get_local_timezone: the name is read from where /etc/localtime
// points, and nothing is guessed, since a wrong zone is worse than none.
func localTimezone() string {
	path, err := filepath.EvalSymlinks("/etc/localtime")
	if err != nil {
		return ""
	}
	_, name, found := strings.Cut(filepath.ToSlash(path), "zoneinfo/")
	if !found {
		return ""
	}
	// tzdata ships copies of the database under posix/ and right/.
	return strings.TrimPrefix(strings.TrimPrefix(name, "posix/"), "right/")
}

// setRaw sets a header without canonicalizing its name. Header.Set would send
// "X-Pm-Appversion"; the official client sends these lowercase.
func setRaw(req *http.Request, name, value string) {
	req.Header[name] = []string{value}
}

// NewRequest builds a Proton API request with the headers every endpoint expects.
// A nil body sends no payload. A nil session omits the credentials, which is
// what the pre-authentication endpoints need.
func NewRequest(method, url string, body any, session *Session) (*http.Request, error) {
	var payload io.Reader = http.NoBody
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		return nil, err
	}

	// The header set follows the official Linux client: aiohttp's defaults
	// (Accept, Accept-Encoding, and Content-Type only when there is a body)
	// plus what python-proton-core and python-proton-vpn-api-core add. The
	// client also sends x-pm-locale, but only with a non-English catalog active.
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	setRaw(req, "x-pm-appversion", constants.AppVersion())
	req.Header.Set("User-Agent", constants.UserAgent())
	if tz := localTimezone(); tz != "" {
		setRaw(req, "x-pm-timezone", tz)
	}

	if session != nil {
		req.Header.Set("Authorization", "Bearer "+session.AccessToken)
		setRaw(req, "x-pm-uid", session.UID)
	}

	return req, nil
}

// Human verification headers, replayed after a code 9001 challenge has been
// solved. Names and semantics follow Proton's own client, see addHVToRequest in
// github.com/ProtonMail/go-proton-api.
const (
	//nolint:gosec // G101: header names, not credentials
	hvTokenHeader = "x-pm-human-verification-token"
	//nolint:gosec // G101: header names, not credentials
	hvTokenTypeHeader = "x-pm-human-verification-token-type"
)

// SetHumanVerification attaches a solved human verification token to a request.
// The token is the HumanVerificationToken handed back in the 9001 response, and
// method is the verification method used to satisfy it. Does nothing when the
// token is empty.
func SetHumanVerification(req *http.Request, token, method string) {
	if token == "" {
		return
	}
	setRaw(req, hvTokenHeader, token)
	setRaw(req, hvTokenTypeHeader, method)
}

// Do executes req and decodes the JSON response into out.
//
// The response is decoded regardless of status code: the API reports its own
// failures in the body (a Code plus an Error message), and those are far more
// useful than the HTTP status. Callers are expected to check the decoded Code.
// The status is only surfaced when the body is not JSON at all.
func Do(client *http.Client, req *http.Request, out any) error {
	// The request URL is built from the operator's own -api-url flag, so it is
	// not attacker-controlled input.
	resp, err := client.Do(req) //nolint:gosec // G704: URL is operator-supplied, not remote input
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	// Accept-Encoding is set explicitly, which turns off net/http's transparent
	// decompression, so undo the encoding here.
	var reader io.Reader = resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		if reader, err = gzip.NewReader(resp.Body); err != nil {
			return err
		}
	case "deflate":
		if reader, err = zlib.NewReader(resp.Body); err != nil {
			return err
		}
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, out); err != nil {
		// Not JSON - a gateway error page or similar. Echo a snippet, otherwise
		// this surfaces as an opaque "invalid character '<'".
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		return fmt.Errorf("unexpected response (HTTP %d): %s", resp.StatusCode, snippet)
	}
	return nil
}

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"protonvpn-wg-confgen/internal/constants"
)

// TestInteractivePrompts runs the binary in a real terminal, a pty or a
// Windows pseudo console: terminal input is what differs most between
// platforms. The username and password must be read from it, the password
// without echo, and a full address typed at the prompt must be shortened like
// --username is.
func TestInteractivePrompts(t *testing.T) {
	usernames := make(chan string, 1)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == constants.AuthInfoPath {
			var body struct{ Username string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			usernames <- body.Username
		}
		_, _ = w.Write([]byte(`{"Code":2001}`))
	}))
	defer api.Close()

	bin := filepath.Join(t.TempDir(), "pwg")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil { //nolint:gosec // test build into a temp dir
		t.Fatalf("build: %v\n%s", err, out)
	}

	term := startInTerminal(t, bin, "--api-url", api.URL, "--no-session", "--list-configs")
	term.expect(t, "Username:")
	term.send(t, "alice@proton.me\r")
	term.expect(t, "Password:")
	time.Sleep(500 * time.Millisecond) // the prompt prints before echo is turned off
	term.send(t, "s3cret-pw\r")
	term.expect(t, "failed to get auth info")

	if strings.Contains(term.screen(), "s3cret-pw") {
		t.Error("the password was echoed")
	}
	select {
	case got := <-usernames:
		if got != "alice" {
			t.Errorf("username sent as %q, want alice", got)
		}
	default:
		t.Error("no auth info request")
	}
}

// terminal collects what the program prints to its terminal.
type terminal struct {
	mu    sync.Mutex
	out   bytes.Buffer
	input func(string) error
}

func (tm *terminal) Write(p []byte) (int, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.out.Write(p)
}

func (tm *terminal) send(t *testing.T, s string) {
	t.Helper()
	if err := tm.input(s); err != nil {
		t.Fatal(err)
	}
}

// Escape sequences and whitespace go: a Windows pseudo console redraws text
// with cursor movements and may turn spaces into them.
var terminalNoise = regexp.MustCompile(`\x1b\[[0-9;?]*[\x20-\x2f]*[\x40-\x7e]|\x1b\][^\x07]*\x07|\s+`)

func (tm *terminal) screen() string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return terminalNoise.ReplaceAllString(tm.out.String(), "")
}

func (tm *terminal) expect(t *testing.T, s string) {
	t.Helper()
	want := terminalNoise.ReplaceAllString(s, "")
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if strings.Contains(tm.screen(), want) {
			return
		}
	}
	t.Fatalf("no %q on the terminal, got:\n%s", s, tm.out.String())
}

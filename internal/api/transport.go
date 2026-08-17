package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"protonvpn-wg-confgen/internal/constants"
)

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

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-pm-appversion", constants.AppVersion)
	req.Header.Set("User-Agent", constants.UserAgent)

	if session != nil {
		req.Header.Set("Authorization", "Bearer "+session.AccessToken)
		req.Header.Set("x-pm-uid", session.UID)
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
	req.Header.Set(hvTokenHeader, token)
	req.Header.Set(hvTokenTypeHeader, method)
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

	body, err := io.ReadAll(resp.Body)
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

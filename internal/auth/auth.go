// Package auth handles ProtonVPN authentication using the SRP protocol.
package auth

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"protonvpn-wg-confgen/internal/api"
	"protonvpn-wg-confgen/internal/config"
	"protonvpn-wg-confgen/internal/constants"
	"protonvpn-wg-confgen/pkg/timeutil"

	"github.com/ProtonMail/go-srp"
	"golang.org/x/term"
)

// Client handles ProtonVPN authentication
type Client struct {
	config       *config.Config
	httpClient   *http.Client
	sessionStore *SessionStore
}

// NewClient creates a new authentication client
func NewClient(cfg *config.Config) *Client {
	return &Client{
		config:       cfg,
		sessionStore: NewSessionStore(),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
					MinVersion:         tls.VersionTLS12,
				},
			},
		},
	}
}

// handleSessionRefresh attempts to refresh a session and save it if successful
func (c *Client) handleSessionRefresh(savedSession *api.Session, reason string) (*api.Session, error) {
	fmt.Println(reason)
	refreshedSession, err := RefreshSession(c.httpClient, c.config.APIURL, savedSession)
	if err != nil {
		fmt.Printf("Token refresh failed: %v\n", err)
		fmt.Println("Re-authenticating with password...")
		fmt.Println("(Your trusted device status for MFA will be preserved)")
		_ = c.sessionStore.Delete()
		return nil, err
	}

	fmt.Println("Session refreshed successfully!")
	// Check if refresh token was rotated
	if savedSession.RefreshToken != refreshedSession.RefreshToken {
		fmt.Println("Refresh token was rotated")
	}

	// Save the refreshed session
	if !c.config.NoSession {
		sessionDuration, _ := timeutil.ParseSessionDuration(c.config.SessionDuration)
		if err := c.sessionStore.Save(refreshedSession, c.config.Username, sessionDuration); err != nil {
			fmt.Printf("Warning: Failed to save refreshed session: %v\n", err)
		}
	}

	return refreshedSession, nil
}

// tryExistingSession attempts to use an existing saved session
func (c *Client) tryExistingSession() (*api.Session, error) {
	savedSession, timeUntilExpiry, err := c.sessionStore.Load(c.config.Username)
	if err != nil {
		fmt.Printf("Warning: Failed to load saved session: %v\n", err)
		return nil, err
	}

	if savedSession == nil {
		return nil, nil
	}

	// Determine what to do with the saved session
	switch {
	case c.config.ForceRefresh:
		reason := fmt.Sprintf("Forcing session refresh (current session expires in %s)", timeutil.HumanizeDuration(timeUntilExpiry))
		return c.handleSessionRefresh(savedSession, reason)

	case timeUntilExpiry < time.Duration(constants.SessionRefreshDays)*24*time.Hour && timeUntilExpiry > 0:
		reason := fmt.Sprintf("Session expires soon (in %s), attempting refresh...", timeutil.HumanizeDuration(timeUntilExpiry))
		return c.handleSessionRefresh(savedSession, reason)

	case VerifySession(c.httpClient, c.config.APIURL, savedSession):
		fmt.Printf("Using saved session (expires in %s)\n", timeutil.HumanizeDuration(timeUntilExpiry))
		return savedSession, nil

	default:
		fmt.Println("Saved session invalid, re-authenticating...")
		_ = c.sessionStore.Delete()
		return nil, nil
	}
}

// Authenticate performs the full authentication flow
func (c *Client) Authenticate() (*api.Session, error) {
	if err := c.ensureUsername(); err != nil {
		return nil, err
	}

	// Try existing session unless clearing or disabled
	if session := c.handleExistingSession(); session != nil {
		return session, nil
	}

	if err := c.ensurePassword(); err != nil {
		return nil, err
	}

	// Perform fresh authentication
	session, err := c.performFreshAuth()
	if err != nil {
		return nil, err
	}

	// Handle session scope upgrade if needed
	if err := c.upgradeSessionIfNeeded(session); err != nil {
		return nil, err
	}

	c.saveSessionIfEnabled(session)
	return session, nil
}

// handleExistingSession handles session clearing or reuse
func (c *Client) handleExistingSession() *api.Session {
	if c.config.ClearSession {
		fmt.Println("Clearing saved session...")
		_ = c.sessionStore.Delete()
		return nil
	}

	if c.config.NoSession {
		return nil
	}

	session, err := c.tryExistingSession()
	if err == nil && session != nil {
		return session
	}
	return nil
}

// performFreshAuth performs SRP authentication and returns a new session
func (c *Client) performFreshAuth() (*api.Session, error) {
	authInfo, err := c.getAuthInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get auth info: %w", err)
	}

	clientProofs, err := c.generateSRPProofs(authInfo)
	if err != nil {
		return nil, err
	}

	authReq := c.buildAuthRequest(authInfo, clientProofs)

	// Handle 2FA if needed
	if authInfo.TwoFA.Enabled == constants.EnabledTrue && authInfo.TwoFA.TOTP == constants.EnabledTrue {
		code, err := c.get2FACode()
		if err != nil {
			return nil, err
		}
		authReq["TwoFactorCode"] = code
	}

	session, err := c.sendAuthRequest(authReq)
	if err != nil {
		return nil, err
	}

	// Verify server proof
	if session.ServerProof != base64.StdEncoding.EncodeToString(clientProofs.ExpectedServerProof) {
		return nil, fmt.Errorf("server proof verification failed")
	}

	return session, nil
}

// generateSRPProofs generates SRP client proofs for authentication
func (c *Client) generateSRPProofs(authInfo *api.AuthInfoResponse) (*srp.Proofs, error) {
	auth, err := srp.NewAuth(
		authInfo.Version,
		c.config.Username,
		[]byte(c.config.Password),
		authInfo.Salt,
		authInfo.Modulus,
		authInfo.ServerEphemeral,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SRP auth: %w", err)
	}

	proofs, err := auth.GenerateProofs(2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SRP proofs: %w", err)
	}
	return proofs, nil
}

// buildAuthRequest builds the authentication request payload
func (c *Client) buildAuthRequest(authInfo *api.AuthInfoResponse, proofs *srp.Proofs) map[string]interface{} {
	return map[string]interface{}{
		"Username":          c.config.Username,
		"ClientEphemeral":   base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		"ClientProof":       base64.StdEncoding.EncodeToString(proofs.ClientProof),
		"SRPSession":        authInfo.SRPSession,
		"PersistentCookies": 0,
	}
}

// upgradeSessionIfNeeded upgrades session with 2FA if VPN scope is missing
func (c *Client) upgradeSessionIfNeeded(session *api.Session) error {
	hasVPNScope, hasTwoFactorScope := c.checkSessionScopes(session)

	if hasVPNScope || !hasTwoFactorScope {
		return nil
	}

	fmt.Println("Session lacks VPN scope - 2FA verification required to upgrade session...")
	code, err := c.get2FACode()
	if err != nil {
		return fmt.Errorf("failed to get 2FA code: %w", err)
	}

	updatedScopes, err := c.submit2FA(session, code)
	if err != nil {
		return fmt.Errorf("2FA verification failed: %w", err)
	}
	session.Scopes = updatedScopes
	fmt.Println("2FA verified - session upgraded with VPN scope")
	return nil
}

// checkSessionScopes checks if session has VPN and twofactor scopes
func (c *Client) checkSessionScopes(session *api.Session) (hasVPN, hasTwoFactor bool) {
	for _, scope := range session.Scopes {
		switch scope {
		case "vpn":
			hasVPN = true
		case "twofactor":
			hasTwoFactor = true
		}
	}
	return
}

// saveSessionIfEnabled saves the session if persistence is enabled
func (c *Client) saveSessionIfEnabled(session *api.Session) {
	if c.config.NoSession {
		return
	}

	sessionDuration, err := timeutil.ParseSessionDuration(c.config.SessionDuration)
	if err != nil {
		fmt.Printf("Warning: Invalid session duration, using default: %v\n", err)
		sessionDuration = 0
	}

	if err := c.sessionStore.Save(session, c.config.Username, sessionDuration); err != nil {
		fmt.Printf("Warning: Failed to save session: %v\n", err)
	}
}

func (c *Client) ensureUsername() error {
	if c.config.Username == "" {
		fmt.Print("Username (without @protonmail.com): ")
		reader := bufio.NewReader(os.Stdin)
		username, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading username: %w", err)
		}
		c.config.Username = strings.TrimSpace(username)
		if c.config.Username == "" {
			return fmt.Errorf("username cannot be empty")
		}
	}
	return nil
}

func (c *Client) ensurePassword() error {
	if c.config.Password == "" {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("error reading password: %w", err)
		}
		c.config.Password = string(passwordBytes)
	}
	return nil
}

func (c *Client) get2FACode() (string, error) {
	fmt.Print("2FA Code: ")
	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("error reading 2FA code: %w", err)
	}
	code = strings.TrimSpace(code)

	// Validate that code is numeric (TOTP codes are 6 digits)
	if code == "" {
		return "", fmt.Errorf("2FA code cannot be empty")
	}

	for _, c := range code {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("2FA code must be numeric (TOTP only).\n" +
				"FIDO2/WebAuthn security keys are not supported.\n" +
				"Please ensure you have TOTP (authenticator app) configured as your 2FA method")
		}
	}

	return code, nil
}

func (c *Client) getAuthInfo() (*api.AuthInfoResponse, error) {
	reqBody := map[string]interface{}{
		"Username": c.config.Username,
		"Intent":   "Proton",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.config.APIURL+"/core/v4/auth/info", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(respBody))
	}

	var authInfo api.AuthInfoResponse
	if err := json.Unmarshal(respBody, &authInfo); err != nil {
		return nil, fmt.Errorf("failed to parse auth info: %w", err)
	}

	if authInfo.Code != CodeSuccess {
		return nil, fmt.Errorf("failed to get auth info, code: %d", authInfo.Code)
	}

	// Validate required fields
	if authInfo.Modulus == "" {
		return nil, fmt.Errorf("received empty modulus from auth info")
	}
	if authInfo.ServerEphemeral == "" {
		return nil, fmt.Errorf("received empty server ephemeral from auth info")
	}

	return &authInfo, nil
}

func (c *Client) sendAuthRequest(authReq map[string]interface{}) (*api.Session, error) {
	body, err := json.Marshal(authReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.config.APIURL+"/core/v4/auth", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentication HTTP error %d: %s", resp.StatusCode, string(respBody))
	}

	var session api.Session
	if err := json.Unmarshal(respBody, &session); err != nil {
		return nil, err
	}

	// Handle mailbox password request (2-password mode)
	// Code 10013 means the account uses legacy 2-password mode which requires a separate mailbox password
	// VPN doesn't need mailbox decryption, but the auth flow requires completing it
	if session.Code == CodeMailboxPasswordError {
		return nil, fmt.Errorf("your account uses legacy 2-password mode which is not supported.\n" +
			"Please switch to single-password mode:\n" +
			"  1. Go to account.proton.me\n" +
			"  2. Settings → All settings → Account and password → Passwords\n" +
			"  3. Switch to 'One-password mode'\n" +
			"This is recommended by Proton for most users and is required for this tool")
	}

	if session.Code != CodeSuccess {
		return nil, NewError(session.Code)
	}

	return &session, nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-pm-appversion", constants.AppVersion)
	req.Header.Set("User-Agent", constants.UserAgent)
}

// submit2FA submits a 2FA code to upgrade the session with additional scopes (like VPN)
func (c *Client) submit2FA(session *api.Session, code string) ([]string, error) {
	reqBody := map[string]interface{}{
		"TwoFactorCode": code,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.config.APIURL+"/core/v4/auth/2fa", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Need to include auth headers for 2FA upgrade
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session.AccessToken))
	req.Header.Set("x-pm-uid", session.UID)
	req.Header.Set("x-pm-appversion", constants.AppVersion)
	req.Header.Set("User-Agent", constants.UserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("2FA HTTP error %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response to get updated scopes
	var twoFAResp struct {
		Code   int      `json:"Code"`
		Scopes []string `json:"Scopes"`
		Error  string   `json:"Error,omitempty"`
	}
	if err := json.Unmarshal(respBody, &twoFAResp); err != nil {
		return nil, fmt.Errorf("failed to parse 2FA response: %w", err)
	}

	if twoFAResp.Code != CodeSuccess {
		if twoFAResp.Error != "" {
			return nil, fmt.Errorf("2FA failed (code %d): %s", twoFAResp.Code, twoFAResp.Error)
		}
		return nil, NewError(twoFAResp.Code)
	}

	return twoFAResp.Scopes, nil
}

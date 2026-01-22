// Package vpn manages VPN certificate generation and server interactions.
package vpn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"protonvpn-wg-confgen/internal/api"
	"protonvpn-wg-confgen/internal/config"
	"protonvpn-wg-confgen/internal/constants"
	"protonvpn-wg-confgen/pkg/timeutil"

	"github.com/ProtonVPN/go-vpn-lib/ed25519"
)

// Client handles VPN operations
type Client struct {
	config     *config.Config
	session    *api.Session
	httpClient *http.Client
}

// NewClient creates a new VPN client
func NewClient(cfg *config.Config, session *api.Session) *Client {
	return &Client{
		config:     cfg,
		session:    session,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// GetCertificate generates a VPN certificate
func (c *Client) GetCertificate(keyPair *ed25519.KeyPair) (*api.VPNInfo, error) {
	publicKeyPEM, err := keyPair.PublicKeyPKIXPem()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key PEM: %w", err)
	}

	// Use provided device name or generate one
	deviceName := c.config.DeviceName
	if deviceName == "" {
		deviceName = fmt.Sprintf("WireGuard-%s-%d", c.config.Username, time.Now().Unix())
	}

	// Parse duration
	durationStr, err := timeutil.ParseToMinutes(c.config.Duration)
	if err != nil {
		return nil, fmt.Errorf("failed to parse duration: %w", err)
	}

	// Build certificate request matching official ProtonVPN API format
	// Feature keys from: python-proton-vpn-api-core/proton/vpn/session/fetcher.py
	certReq := map[string]interface{}{
		"ClientPublicKey":     publicKeyPEM,
		"ClientPublicKeyMode": "EC",
		"Mode":                "persistent", // Create persistent configuration
		"DeviceName":          deviceName,
		"Duration":            durationStr,
		"Features": map[string]interface{}{
			"NetShieldLevel": 0,                          // NetShield disabled
			"RandomNAT":      false,                      // Moderate NAT disabled
			"PortForwarding": false,                      // Port forwarding disabled
			"SplitTCP":       c.config.EnableAccelerator, // VPN Accelerator (called SplitTCP in API)
		},
	}

	certJSON, err := json.Marshal(certReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.config.APIURL+"/vpn/v1/certificate", bytes.NewBuffer(certJSON))
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var vpnInfo api.VPNInfo
	if err := json.Unmarshal(body, &vpnInfo); err != nil {
		return nil, err
	}

	if !constants.IsSuccessCode(vpnInfo.Code) {
		// Include the actual API error message if available
		if vpnInfo.Error != "" {
			return nil, fmt.Errorf("VPN certificate error (code %d): %s", vpnInfo.Code, vpnInfo.Error)
		}
		return nil, fmt.Errorf("failed to get VPN certificate, code: %d", vpnInfo.Code)
	}

	return &vpnInfo, nil
}

// GetServers fetches the list of VPN servers
func (c *Client) GetServers() ([]api.LogicalServer, error) {
	req, err := http.NewRequest(http.MethodGet, c.config.APIURL+"/vpn/v1/logicals", http.NoBody)
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response api.LogicalsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	if !constants.IsSuccessCode(response.Code) {
		return nil, fmt.Errorf("API returned error code: %d", response.Code)
	}

	return response.LogicalServers, nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.session.AccessToken))
	req.Header.Set("x-pm-uid", c.session.UID)
	req.Header.Set("x-pm-appversion", constants.AppVersion)
	req.Header.Set("User-Agent", constants.UserAgent)
}

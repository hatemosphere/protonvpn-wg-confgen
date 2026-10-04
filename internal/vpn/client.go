// Package vpn manages VPN certificate generation and server interactions.
package vpn

import (
	"fmt"
	"net/http"
	"time"

	"protonvpn-wg-confgen/internal/api"
	"protonvpn-wg-confgen/internal/config"
	"protonvpn-wg-confgen/internal/constants"
	"protonvpn-wg-confgen/internal/timeutil"

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
		httpClient: api.NewHTTPClient(10 * time.Second),
	}
}

// doJSON performs an authenticated request and decodes the JSON response into out.
func (c *Client) doJSON(method, url string, body api.Body, out any) error {
	req, err := api.NewRequest(method, url, body, c.session)
	if err != nil {
		return err
	}
	return api.Do(c.httpClient, req, out)
}

// requestCertificate posts a certificate request and validates the response code.
func (c *Client) requestCertificate(certReq api.Body) (*api.VPNInfo, error) {
	var vpnInfo api.VPNInfo
	if err := c.doJSON(http.MethodPost, c.config.APIURL+constants.CertificatePath, certReq, &vpnInfo); err != nil {
		return nil, err
	}

	if !constants.IsSuccessCode(vpnInfo.Code) {
		if vpnInfo.Error != "" {
			return nil, fmt.Errorf("certificate error (code %d): %s", vpnInfo.Code, vpnInfo.Error)
		}
		return nil, fmt.Errorf("certificate request failed, code: %d", vpnInfo.Code)
	}

	return &vpnInfo, nil
}

// GetCertificate generates a VPN certificate
func (c *Client) GetCertificate(keyPair *ed25519.KeyPair) (*api.VPNInfo, error) {
	publicKeyPEM, err := keyPair.PublicKeyPKIXPem()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key PEM: %w", err)
	}

	durationStr, err := timeutil.ParseToMinutes(c.config.Duration)
	if err != nil {
		return nil, fmt.Errorf("failed to parse duration: %w", err)
	}

	// The official client sends exactly ClientPublicKey, Duration and Features,
	// in that order (fetcher.py). A session certificate adds only the key mode.
	certReq := api.Body{
		{Key: "ClientPublicKey", Value: publicKeyPEM},
		{Key: "Duration", Value: durationStr},
		{Key: "Features", Value: featuresBody(c.certificateFeatures())},
		{Key: "ClientPublicKeyMode", Value: constants.PublicKeyMode},
	}

	// Mode and DeviceName register the certificate on the account, which is the
	// dashboard's flow rather than the Linux client's. NoSave omits them.
	if !c.config.NoSave {
		certReq = append(certReq,
			api.Field{Key: "Mode", Value: constants.CertMode},
			api.Field{Key: "DeviceName", Value: c.deviceName()})
	}

	return c.requestCertificate(certReq)
}

// RenewCertificate renews an existing persistent certificate by reusing its public key.
// Unlike GetCertificate, this does not generate a new key pair and sends Renew: true.
// current is the certificate's features as reported by the API; they are kept
// unless the matching flag was given explicitly. A nil current falls back to
// the flags entirely.
func (c *Client) RenewCertificate(publicKeyPEM, deviceName string, current *api.RequestFeatures) (*api.VPNInfo, error) {
	durationStr, err := timeutil.ParseToMinutes(c.config.Duration)
	if err != nil {
		return nil, fmt.Errorf("failed to parse duration: %w", err)
	}

	return c.requestCertificate(api.Body{
		{Key: "ClientPublicKey", Value: publicKeyPEM},
		{Key: "Duration", Value: durationStr},
		{Key: "Features", Value: featuresBody(c.renewalFeatures(current))},
		{Key: "ClientPublicKeyMode", Value: constants.PublicKeyMode},
		{Key: "Mode", Value: constants.CertMode},
		{Key: "DeviceName", Value: deviceName},
		{Key: "Renew", Value: true},
	})
}

// featuresBody orders the features as fetcher.py's _convert_features does.
func featuresBody(features map[string]any) api.Body {
	body := make(api.Body, 0, len(features))
	for _, key := range []string{featRandomNAT, featSplitTCP, featPortForwarding, featNetShield} {
		if value, ok := features[key]; ok {
			body = append(body, api.Field{Key: key, Value: value})
		}
	}
	return body
}

// Request-side feature keys, from python-proton-vpn-api-core's fetcher.py.
const (
	featNetShield      = "NetShieldLevel"
	featRandomNAT      = "RandomNAT"
	featPortForwarding = "PortForwarding"
	featSplitTCP       = "SplitTCP"
)

// renewalFeatures starts from the certificate's reported features and lets
// explicitly passed flags override individual values.
func (c *Client) renewalFeatures(current *api.RequestFeatures) map[string]any {
	flags := c.certificateFeatures()
	if current == nil {
		return flags
	}
	features := map[string]any{
		featNetShield:      current.NetShieldLevel,
		featRandomNAT:      current.RandomNAT,
		featPortForwarding: current.PortForwarding,
		featSplitTCP:       current.SplitTCP,
	}
	for flagName, key := range map[string]string{
		"netshield":       featNetShield,
		"moderate-nat":    featRandomNAT,
		"port-forwarding": featPortForwarding,
		"accelerator":     featSplitTCP,
	} {
		if c.config.Explicit[flagName] {
			features[key] = flags[key]
		}
	}
	return features
}

// GetServers fetches the list of VPN servers
func (c *Client) GetServers() ([]api.LogicalServer, error) {
	var response api.LogicalsResponse
	if err := c.doJSON(http.MethodGet, c.config.APIURL+constants.LogicalsPath, nil, &response); err != nil {
		return nil, err
	}

	if !constants.IsSuccessCode(response.Code) {
		return nil, fmt.Errorf("API returned error code: %d", response.Code)
	}

	return response.LogicalServers, nil
}

// ListCertificates fetches all persistent certificates on the account, paginating via BeginID.
func (c *Client) ListCertificates() ([]api.VPNCertificate, error) {
	const pageSize = 50
	var all []api.VPNCertificate
	var beginID string

	for {
		u := fmt.Sprintf("%s%s/all?Mode=%s&Limit=%d", c.config.APIURL, constants.CertificatePath, constants.CertMode, pageSize)
		if beginID != "" {
			u += "&BeginID=" + beginID
		}

		var page api.CertListResponse
		if err := c.doJSON(http.MethodGet, u, nil, &page); err != nil {
			return nil, err
		}
		if !constants.IsSuccessCode(page.Code) {
			if page.Error != "" {
				return nil, fmt.Errorf("list certificates error (code %d): %s", page.Code, page.Error)
			}
			return nil, fmt.Errorf("list certificates failed, code: %d", page.Code)
		}

		all = append(all, page.Certificates...)
		if len(page.Certificates) < pageSize {
			break
		}
		beginID = page.Certificates[len(page.Certificates)-1].SerialNumber
	}

	return all, nil
}

// deviceName returns the configured device name, generating one if unset.
func (c *Client) deviceName() string {
	if c.config.DeviceName != "" {
		return c.config.DeviceName
	}
	return fmt.Sprintf("WireGuard-%s-%d", c.config.Username, time.Now().Unix())
}

func (c *Client) certificateFeatures() map[string]any {
	return map[string]any{
		featNetShield: c.config.NetShield,
		// Proton's API field is inverted: RandomNAT=false enables Moderate NAT.
		featRandomNAT:      !c.config.ModerateNAT,
		featPortForwarding: c.config.PortForwarding,
		featSplitTCP:       c.config.EnableAccelerator,
	}
}

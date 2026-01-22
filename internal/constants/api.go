// Package constants defines constants used throughout the application.
package constants

// API endpoints
const (
	DefaultAPIURL   = "https://vpn-api.proton.me"
	AuthInfoPath    = "/core/v4/auth/info"
	AuthPath        = "/core/v4/auth"
	RefreshPath     = "/auth/refresh"
	CertificatePath = "/vpn/v1/certificate"
	LogicalsPath    = "/vpn/v1/logicals"
)

// API version headers - can be overridden at build time via ldflags:
// go build -ldflags "-X .../internal/constants.AppVersion=linux-vpn@X.Y.Z"
var (
	AppVersion = "linux-vpn@4.13.1"
	UserAgent  = "ProtonVPN/4.13.1 (Linux; Ubuntu)"
)

// API response codes
// Reference: proton-python-client/proton/api.py checks for codes 1000 and 1001
const (
	APICodeSuccess     = 1000
	APICodeMultiStatus = 1001 // Also indicates success in some contexts
)

// IsSuccessCode checks if an API response code indicates success
func IsSuccessCode(code int) bool {
	return code == APICodeSuccess || code == APICodeMultiStatus
}

// Server/feature status values
const (
	StatusOnline = 1
	EnabledTrue  = 1
)

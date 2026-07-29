package constants

import "time"

// Certificate defaults
const (
	// MinCertDuration is the shortest duration the API accepts (code 2001 below this).
	MinCertDuration = 10 * time.Minute

	DefaultCertDuration = "365d"
	MaxCertDuration     = 365 // days
	CertMode            = "persistent"
	PublicKeyMode       = "EC"

	// Session (non-persistent) certificates are capped at 7 days by the API,
	// which silently clamps anything longer instead of returning an error.
	DefaultSessionCertDuration = "7d"
	MaxSessionCertDuration     = 7 // days
)

// Server selection defaults
const (
	DefaultP2POnly = true
)

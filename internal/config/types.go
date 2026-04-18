package config

import "fmt"

// Config holds all configuration options
type Config struct {
	// Authentication
	Username string
	Password string

	// Server selection
	Countries      []string
	P2PServersOnly bool
	SecureCoreOnly bool
	FreeOnly       bool

	// Output configuration
	OutputFile       string
	ClientPrivateKey string
	DeviceName       string

	// Network configuration
	DNSServers        []string
	AllowedIPs        []string
	EnableAccelerator bool
	EnableIPv6        bool

	// Certificate configuration
	Duration string

	// Session management
	ClearSession    bool
	NoSession       bool
	ForceRefresh    bool
	SessionDuration string

	// Advanced configuration
	APIURL string
	Debug  bool

	// Management mode
	ListConfigs bool
}

// ValidateCredentials checks if we have the required credentials
func (c *Config) ValidateCredentials() error {
	if c.Username == "" {
		return fmt.Errorf("username is required")
	}
	return nil
}

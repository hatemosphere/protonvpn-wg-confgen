// Package config handles command-line argument parsing and configuration management.
package config

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"protonvpn-wg-confgen/internal/constants"
	"protonvpn-wg-confgen/pkg/validation"
)

// Parse parses command-line flags and returns a Config
func Parse() (*Config, error) {
	cfg := &Config{}

	var countriesFlag string
	var dnsServersFlag string
	var allowedIPsFlag string

	// Set default DNS and allowed IPs based on IPv6 support
	defaultDNS := constants.DefaultDNSIPv4
	defaultAllowedIPs := constants.DefaultAllowedIPsIPv4

	// Authentication flags
	flag.StringVar(&cfg.Username, "username", "", "ProtonVPN username")
	flag.StringVar(&cfg.Password, "password", "", "ProtonVPN password (will prompt if not provided)")

	// Server selection flags
	flag.StringVar(&countriesFlag, "countries", "", "Comma-separated list of country codes (e.g., US,NL,CH)")
	flag.BoolVar(&cfg.P2PServersOnly, "p2p-only", constants.DefaultP2POnly, "Use only P2P-enabled servers")
	flag.BoolVar(&cfg.SecureCoreOnly, "secure-core", false, "Use only Secure Core servers (multi-hop through privacy-friendly countries)")
	flag.BoolVar(&cfg.FreeOnly, "free-only", false, "Use only Free tier servers (tier 0)")

	// Output configuration
	flag.StringVar(&cfg.OutputFile, "output", "protonvpn.conf", "Output WireGuard configuration file")
	flag.StringVar(&cfg.DeviceName, "device-name", "", "Device name for WireGuard config (auto-generated if empty)")

	// Network configuration
	flag.BoolVar(&cfg.EnableIPv6, "ipv6", false, "Enable IPv6 support")
	flag.StringVar(&dnsServersFlag, "dns", "", "Comma-separated list of DNS servers (defaults based on IPv6 setting)")
	flag.StringVar(&allowedIPsFlag, "allowed-ips", "", "Comma-separated list of allowed IPs (defaults based on IPv6 setting)")
	flag.BoolVar(&cfg.EnableAccelerator, "accelerator", true, "Enable VPN accelerator")

	// Certificate configuration
	flag.StringVar(&cfg.Duration, "duration", constants.DefaultCertDuration, "Certificate duration (e.g., 30m, 24h, 7d, 1h30m). Max: 365d")

	// Session management
	flag.BoolVar(&cfg.ClearSession, "clear-session", false, "Clear saved session and force re-authentication")
	flag.BoolVar(&cfg.NoSession, "no-session", false, "Don't save or use session persistence")
	flag.BoolVar(&cfg.ForceRefresh, "force-refresh", false, "Force session refresh even if not expired")
	flag.StringVar(&cfg.SessionDuration, "session-duration", "0", "Session cache duration (e.g., 12h, 24h, 7d). 0 = no expiration")

	// Advanced configuration
	flag.StringVar(&cfg.APIURL, "api-url", constants.DefaultAPIURL, "ProtonVPN API URL")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug output")

	flag.Parse()

	// Validate required flags
	if countriesFlag == "" {
		return nil, fmt.Errorf("countries flag is required")
	}

	// Parse and validate country codes
	cfg.Countries = parseCountries(countriesFlag)
	for _, country := range cfg.Countries {
		if !validation.IsValidCountryCode(country) {
			return nil, fmt.Errorf("invalid country code: %s", country)
		}
	}

	// Set defaults based on IPv6 setting
	if cfg.EnableIPv6 {
		defaultDNS = fmt.Sprintf("%s,%s", constants.DefaultDNSIPv4, constants.DefaultDNSIPv6)
		defaultAllowedIPs = fmt.Sprintf("%s,%s", constants.DefaultAllowedIPsIPv4, constants.DefaultAllowedIPsIPv6)
	}

	// Use defaults if flags are empty
	if dnsServersFlag == "" {
		dnsServersFlag = defaultDNS
	}
	if allowedIPsFlag == "" {
		allowedIPsFlag = defaultAllowedIPs
	}

	// Parse lists (with space trimming)
	cfg.DNSServers = parseCommaSeparatedList(dnsServersFlag)
	cfg.AllowedIPs = parseCommaSeparatedList(allowedIPsFlag)

	// Clean up username
	cfg.Username = validation.CleanUsername(cfg.Username)

	return cfg, nil
}

// parseCommaSeparatedList parses a comma-separated string into a trimmed slice
func parseCommaSeparatedList(input string) []string {
	parts := strings.Split(input, ",")
	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// parseCountries parses and normalizes country codes
func parseCountries(countriesFlag string) []string {
	return parseCommaSeparatedList(strings.ToUpper(countriesFlag))
}

// PrintUsage prints usage information
func PrintUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s -username <username> -countries <country-codes> [options]\n\n", os.Args[0])
	flag.PrintDefaults()
}

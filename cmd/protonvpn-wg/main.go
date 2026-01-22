// Package main provides the command-line interface for generating ProtonVPN WireGuard configurations.
package main

import (
	"fmt"
	"os"
	"strings"

	"protonvpn-wg-confgen/internal/api"
	"protonvpn-wg-confgen/internal/auth"
	"protonvpn-wg-confgen/internal/config"
	"protonvpn-wg-confgen/internal/vpn"
	"protonvpn-wg-confgen/pkg/wireguard"

	"github.com/ProtonVPN/go-vpn-lib/ed25519"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Parse configuration
	cfg, err := config.Parse()
	if err != nil {
		config.PrintUsage()
		return err
	}

	// Authenticate
	authClient := auth.NewClient(cfg)
	session, err := authClient.Authenticate()
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	fmt.Println("Authentication successful!")

	// Generate key pair
	keyPair, err := ed25519.NewKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}
	cfg.ClientPrivateKey = keyPair.ToX25519Base64()

	// Create VPN client
	vpnClient := vpn.NewClient(cfg, session)

	// Get VPN certificate
	vpnInfo, err := vpnClient.GetCertificate(keyPair)
	if err != nil {
		return fmt.Errorf("failed to get VPN certificate: %w", err)
	}

	// Get server list
	servers, err := vpnClient.GetServers()
	if err != nil {
		return fmt.Errorf("failed to get servers: %w", err)
	}

	// Select best server
	selector := vpn.NewServerSelector(cfg)
	server, err := selector.SelectBest(servers)
	if err != nil {
		return err
	}

	// Build feature list string
	features := api.GetFeatureNames(server.Features)
	featureStr := ""
	if len(features) > 0 {
		featureStr = fmt.Sprintf(", Features: %s", strings.Join(features, ", "))
	}

	fmt.Printf("Selected server: %s (Country: %s, City: %s, Tier: %s, Load: %d%%, Score: %.2f, Servers: %d%s)\n",
		server.Name, server.ExitCountry, server.City, api.GetTierName(server.Tier),
		server.Load, server.Score, len(server.Servers), featureStr)

	// Get best physical server
	physicalServer := vpn.GetBestPhysicalServer(server)
	if physicalServer == nil {
		return fmt.Errorf("no physical servers available")
	}

	// Generate WireGuard configuration
	generator := wireguard.NewConfigGenerator(cfg)
	if err := generator.Generate(server, physicalServer, cfg.ClientPrivateKey); err != nil {
		return fmt.Errorf("failed to generate WireGuard config: %w", err)
	}

	fmt.Printf("WireGuard configuration written to: %s\n", cfg.OutputFile)

	// Note about persistence
	if vpnInfo.DeviceName != "" {
		fmt.Printf("Device name: %s (visible in ProtonVPN dashboard)\n", vpnInfo.DeviceName)
	}

	// Show final success
	fmt.Printf("\nSuccessfully generated config for %s\n", server.ExitCountry)

	return nil
}

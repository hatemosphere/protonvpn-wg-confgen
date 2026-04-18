// Package main provides the command-line interface for generating ProtonVPN WireGuard configurations.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

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
	cfg, err := config.Parse()
	if err != nil {
		config.PrintUsage()
		return err
	}

	authClient := auth.NewClient(cfg)
	session, err := authClient.Authenticate()
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	fmt.Println("Authentication successful!")

	vpnClient := vpn.NewClient(cfg, session)

	if cfg.ListConfigs {
		return listConfigs(vpnClient)
	}
	return generateConfig(cfg, vpnClient)
}

func generateConfig(cfg *config.Config, vpnClient *vpn.Client) error {
	keyPair, err := ed25519.NewKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}
	cfg.ClientPrivateKey = keyPair.ToX25519Base64()

	vpnInfo, err := vpnClient.GetCertificate(keyPair)
	if err != nil {
		return fmt.Errorf("failed to get VPN certificate: %w", err)
	}

	servers, err := vpnClient.GetServers()
	if err != nil {
		return fmt.Errorf("failed to get servers: %w", err)
	}

	selector := vpn.NewServerSelector(cfg)
	server, err := selector.SelectBest(servers)
	if err != nil {
		return err
	}

	features := api.GetFeatureNames(server.Features)
	featureStr := ""
	if len(features) > 0 {
		featureStr = fmt.Sprintf(", Features: %s", strings.Join(features, ", "))
	}

	fmt.Printf("Selected server: %s (Country: %s, City: %s, Tier: %s, Load: %d%%, Score: %.2f, Servers: %d%s)\n",
		server.Name, server.ExitCountry, server.City, api.GetTierName(server.Tier),
		server.Load, server.Score, len(server.Servers), featureStr)

	physicalServer := vpn.GetBestPhysicalServer(server)
	if physicalServer == nil {
		return fmt.Errorf("no physical servers available")
	}

	generator := wireguard.NewConfigGenerator(cfg)
	if err := generator.Generate(server, physicalServer, cfg.ClientPrivateKey, vpnInfo); err != nil {
		return fmt.Errorf("failed to generate WireGuard config: %w", err)
	}

	fmt.Printf("WireGuard configuration written to: %s\n", cfg.OutputFile)
	if vpnInfo.DeviceName != "" {
		fmt.Printf("Device name: %s (visible in ProtonVPN dashboard)\n", vpnInfo.DeviceName)
	}
	fmt.Printf("\nSuccessfully generated config for %s\n", server.ExitCountry)
	return nil
}

func listConfigs(vpnClient *vpn.Client) error {
	certs, err := vpnClient.ListCertificates()
	if err != nil {
		return fmt.Errorf("failed to list configurations: %w", err)
	}
	if len(certs) == 0 {
		fmt.Println("No persistent configurations found.")
		return nil
	}

	fmt.Printf("%-40s  %-30s  %-20s  %s\n", "SerialNumber", "DeviceName", "Expires", "Fingerprint")
	fmt.Println(strings.Repeat("-", 120))
	for _, c := range certs {
		exp := time.Unix(c.ExpirationTime, 0).UTC().Format("2006-01-02 15:04 UTC")
		name := c.DeviceName
		if name == "" {
			name = "-"
		}
		fmt.Printf("%-40s  %-30s  %-20s  %s\n", c.SerialNumber, name, exp, c.ClientKeyFingerprint)
	}
	fmt.Printf("\nTotal: %d\n", len(certs))
	return nil
}

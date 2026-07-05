// Package main provides the command-line interface for generating ProtonVPN WireGuard configurations.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"protonvpn-wg-confgen/internal/api"
	"protonvpn-wg-confgen/internal/auth"
	"protonvpn-wg-confgen/internal/config"
	"protonvpn-wg-confgen/internal/constants"
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

	switch {
	case cfg.ListConfigs:
		return listConfigs(vpnClient)
	case cfg.ListServers:
		return listServers(cfg, vpnClient)
	case cfg.RenewSerial != "":
		return renewSerial(cfg, vpnClient)
	default:
		return generateConfig(cfg, vpnClient)
	}
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
	mode := vpnInfo.Mode
	if mode == "" {
		mode = "session"
	}
	fmt.Printf("Certificate: %s, expires %s\n",
		mode, time.Unix(vpnInfo.ExpirationTime, 0).UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Printf("\nSuccessfully generated config for %s\n", server.ExitCountry)
	return nil
}

func listServers(cfg *config.Config, vpnClient *vpn.Client) error {
	servers, err := vpnClient.GetServers()
	if err != nil {
		return fmt.Errorf("failed to get servers: %w", err)
	}

	// Filter and sort servers
	var filtered []api.LogicalServer
	for i := range servers {
		s := &servers[i]
		if s.Status != constants.StatusOnline {
			continue
		}

		// Country filter
		if len(cfg.Countries) > 0 {
			match := false
			for _, c := range cfg.Countries {
				if s.ExitCountry == c {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		// Tier filter
		if cfg.FreeOnly {
			if s.Tier != api.TierFree {
				continue
			}
		} else {
			if s.Tier == api.TierFree {
				continue
			}
		}

		// P2P filter
		if cfg.P2PServersOnly && !cfg.SecureCoreOnly && !cfg.FreeOnly && s.Features&api.FeatureP2P == 0 {
			continue
		}

		// Secure Core filter
		if cfg.SecureCoreOnly && s.Features&api.FeatureSecureCore == 0 {
			continue
		}

		filtered = append(filtered, servers[i])
	}

	if len(filtered) == 0 {
		if len(cfg.Countries) > 0 {
			return fmt.Errorf("no online servers found for countries: %v", cfg.Countries)
		}
		return fmt.Errorf("no online servers found")
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].ExitCountry != filtered[j].ExitCountry {
			return filtered[i].ExitCountry < filtered[j].ExitCountry
		}
		return filtered[i].Score < filtered[j].Score
	})

	fmt.Printf("%-7s  %-14s  %-18s  %5s  %6s  %-10s  %s\n",
		"Country", "Server", "City", "Load", "Score", "Tier", "Features")
	fmt.Println(strings.Repeat("-", 100))

	for i := range filtered {
		s := &filtered[i]
		features := api.GetFeatureNames(s.Features)
		featureStr := ""
		if len(features) > 0 {
			featureStr = strings.Join(features, ", ")
		} else {
			featureStr = "-"
		}

		fmt.Printf("%-7s  %-14s  %-18s  %3d%%  %6.2f  %-10s  %s\n",
			s.ExitCountry, s.Name, s.City, s.Load, s.Score,
			api.GetTierName(s.Tier), featureStr)
	}

	// Count unique countries
	seen := map[string]struct{}{}
	for i := range filtered {
		seen[filtered[i].ExitCountry] = struct{}{}
	}
	fmt.Printf("\n%d servers found across %d countries.\n", len(filtered), len(seen))
	return nil
}

func renewSerial(cfg *config.Config, vpnClient *vpn.Client) error {
	certs, err := vpnClient.ListCertificates()
	if err != nil {
		return fmt.Errorf("failed to list certificates: %w", err)
	}

	var target *api.VPNCertificate
	for i := range certs {
		if certs[i].SerialNumber == cfg.RenewSerial {
			target = &certs[i]
			break
		}
	}

	if target == nil {
		return fmt.Errorf("certificate with SerialNumber %s not found (use -list-configs to see available certificates)", cfg.RenewSerial)
	}

	if target.ClientKey == "" {
		return fmt.Errorf("certificate %s has no public key data", cfg.RenewSerial)
	}

	deviceName := target.DeviceName
	if deviceName == "" {
		return fmt.Errorf("certificate %s has no device name", cfg.RenewSerial)
	}

	vpnInfo, err := vpnClient.RenewCertificate(target.ClientKey, deviceName)
	if err != nil {
		return fmt.Errorf("failed to renew certificate: %w", err)
	}

	fmt.Printf("Certificate renewed: %s\n", cfg.RenewSerial)
	fmt.Printf("Device name: %s\n", deviceName)
	fmt.Printf("New expiry: %s\n", time.Unix(vpnInfo.ExpirationTime, 0).UTC().Format("2006-01-02 15:04 UTC"))
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

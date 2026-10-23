package vpn

import (
	"cmp"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"

	"protonvpn-wg-confgen/internal/api"
	"protonvpn-wg-confgen/internal/config"
	"protonvpn-wg-confgen/internal/constants"
)

// ServerSelector handles server selection logic
type ServerSelector struct {
	config *config.Config
}

// NewServerSelector creates a new server selector
func NewServerSelector(cfg *config.Config) *ServerSelector {
	return &ServerSelector{config: cfg}
}

// EligibleServers returns the online servers matching the configured filters,
// preserving input order. An empty country list matches every country, which is
// what the listing mode uses; selection always has at least one country set.
func EligibleServers(cfg *config.Config, servers []api.LogicalServer) []api.LogicalServer {
	filtered := make([]api.LogicalServer, 0, len(servers))
	for i := range servers {
		if isEligible(cfg, &servers[i]) {
			filtered = append(filtered, servers[i])
		}
	}
	return filtered
}

func isEligible(cfg *config.Config, server *api.LogicalServer) bool {
	if !isEnabled(server) {
		return false
	}
	// Free tier is opt-in: -free-only selects it exclusively, otherwise it is excluded.
	if cfg.FreeOnly != (server.Tier == api.TierFree) {
		return false
	}
	if len(cfg.Countries) > 0 && !slices.Contains(cfg.Countries, server.ExitCountry) {
		return false
	}
	// The P2P filter does not apply to Secure Core or Free tier selections.
	if cfg.P2PServersOnly && !cfg.SecureCoreOnly && !cfg.FreeOnly && server.Features&api.FeatureP2P == 0 {
		return false
	}
	return !cfg.SecureCoreOnly || server.Features&api.FeatureSecureCore != 0
}

// isEnabled mirrors LogicalServer.enabled in the official client: the logical
// server is online and so is at least one of its physical servers.
func isEnabled(server *api.LogicalServer) bool {
	return server.Status == constants.StatusOnline &&
		slices.ContainsFunc(server.Servers, func(p api.PhysicalServer) bool { return p.Status == constants.StatusOnline })
}

// SelectBest selects the best server based on configuration
func (s *ServerSelector) SelectBest(servers []api.LogicalServer) (*api.LogicalServer, error) {
	// If a specific server is requested, find it by exact name match
	if s.config.ServerName != "" {
		for i := range servers {
			if servers[i].Name == s.config.ServerName && servers[i].Status == constants.StatusOnline {
				return &servers[i], nil
			}
		}
		return nil, fmt.Errorf("server %q not found or offline", s.config.ServerName)
	}

	// The official clients' fastest-in-country pick never lands on Secure Core
	// or Tor servers unless those are what was asked for.
	filtered := slices.DeleteFunc(EligibleServers(s.config, servers), func(server api.LogicalServer) bool {
		return server.Features&api.FeatureTor != 0 ||
			(!s.config.SecureCoreOnly && server.Features&api.FeatureSecureCore != 0)
	})

	if s.config.Debug {
		s.printDebugServerList(filtered)
	}

	if len(filtered) == 0 {
		return nil, s.buildNoServersError()
	}

	// Lowest score wins, as in the official clients (get_fastest_in_country on
	// Linux, getBestScoreServer on Android). The sort is stable so that ties go
	// to the server listed first, which is what their min() and sortedBy do.
	slices.SortStableFunc(filtered, func(a, b api.LogicalServer) int {
		return cmp.Compare(a.Score, b.Score)
	})

	return &filtered[0], nil
}

func (s *ServerSelector) buildNoServersError() error {
	errMsg := fmt.Sprintf("no suitable servers found for countries: %v", s.config.Countries)

	if s.config.SecureCoreOnly {
		errMsg += " with Secure Core"
	} else if s.config.P2PServersOnly {
		errMsg += " with P2P support"
	}

	return errors.New(errMsg)
}

// GetBestPhysicalServer returns an online physical server, or nil if the
// logical server has none. Returning an offline server would produce a config
// pointing at a dead endpoint.
func GetBestPhysicalServer(server *api.LogicalServer) *api.PhysicalServer {
	var online []*api.PhysicalServer
	for i := range server.Servers {
		if server.Servers[i].Status == constants.StatusOnline {
			online = append(online, &server.Servers[i])
		}
	}
	if len(online) == 0 {
		return nil
	}
	// The official clients pick at random among the online ones, which spreads
	// users across the hosts behind a logical server.
	return online[rand.IntN(len(online))] //nolint:gosec // G404: load spreading, not a secret
}

// printDebugServerList prints a debug list of filtered servers
func (s *ServerSelector) printDebugServerList(servers []api.LogicalServer) {
	fmt.Printf("\nDEBUG: Found %d servers after filtering:\n", len(servers))
	fmt.Println("==================================================================================")
	fmt.Printf("%-15s | %-18s | %-12s | Load | Score | Features\n", "Server", "City", "Tier")
	fmt.Println("----------------------------------------------------------------------------------")

	for i := range servers {
		features := api.GetFeatureNames(servers[i].Features)
		featureStr := "-"
		if len(features) > 0 {
			featureStr = strings.Join(features, ", ")
		}

		fmt.Printf("%-15s | %-18s | %-12s | %3d%% | %.2f | %s\n",
			servers[i].Name,
			servers[i].City,
			api.GetTierName(servers[i].Tier),
			servers[i].Load,
			servers[i].Score,
			featureStr)
	}

	fmt.Println("==================================================================================")
}

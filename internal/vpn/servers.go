package vpn

import (
	"errors"
	"fmt"
	"sort"
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

// SelectBest selects the best server based on configuration
func (s *ServerSelector) SelectBest(servers []api.LogicalServer) (*api.LogicalServer, error) {
	filtered := s.filterServers(servers)

	if s.config.Debug {
		s.printDebugServerList(filtered)
	}

	if len(filtered) == 0 {
		return nil, s.buildNoServersError()
	}

	// Sort servers: first by score (descending), then by load (ascending)
	sort.Slice(filtered, func(i, j int) bool {
		// If scores are different, higher score wins
		if filtered[i].Score != filtered[j].Score {
			return filtered[i].Score > filtered[j].Score
		}
		// If scores are equal, lower load wins
		return filtered[i].Load < filtered[j].Load
	})

	return &filtered[0], nil
}

func (s *ServerSelector) filterServers(servers []api.LogicalServer) []api.LogicalServer {
	var filtered []api.LogicalServer

	for i := range servers {
		if s.isServerEligible(&servers[i]) {
			filtered = append(filtered, servers[i])
		}
	}

	return filtered
}

func (s *ServerSelector) isServerEligible(server *api.LogicalServer) bool {
	// Skip offline servers
	if server.Status != constants.StatusOnline {
		return false
	}

	// Filter by tier based on -free-only flag
	if s.config.FreeOnly {
		// When free-only is enabled, only accept Free tier servers
		if server.Tier != api.TierFree {
			return false
		}
	} else {
		// Otherwise, filter out free tier servers
		if server.Tier == api.TierFree {
			return false
		}
	}

	// Filter by P2P support if requested (but not when using Secure Core or Free tier)
	if s.config.P2PServersOnly && !s.config.SecureCoreOnly && !s.config.FreeOnly && server.Features&api.FeatureP2P == 0 {
		return false
	}

	// Filter by Secure Core if requested
	if s.config.SecureCoreOnly && server.Features&api.FeatureSecureCore == 0 {
		return false
	}

	// Filter by country
	if !s.isCountryMatch(server) {
		return false
	}

	// Skip servers with no physical servers
	if len(server.Servers) == 0 {
		return false
	}

	return true
}

func (s *ServerSelector) isCountryMatch(server *api.LogicalServer) bool {
	for _, country := range s.config.Countries {
		if server.ExitCountry == country {
			return true
		}
	}
	return false
}

func (s *ServerSelector) buildNoServersError() error {
	errMsg := fmt.Sprintf("No suitable servers found for countries: %v", s.config.Countries)

	if s.config.SecureCoreOnly {
		errMsg += " with Secure Core"
	} else if s.config.P2PServersOnly {
		errMsg += " with P2P support"
	}

	return errors.New(errMsg)
}

// GetBestPhysicalServer returns the best physical server from a logical server
func GetBestPhysicalServer(server *api.LogicalServer) *api.PhysicalServer {
	if len(server.Servers) == 0 {
		return nil
	}

	// Find the first online physical server
	for i := range server.Servers {
		if server.Servers[i].Status == constants.StatusOnline {
			return &server.Servers[i]
		}
	}

	// If no online servers, return the first one
	return &server.Servers[0]
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

package vpn

import (
	"testing"

	"protonvpn-wg-confgen/internal/api"
	"protonvpn-wg-confgen/internal/config"
	"protonvpn-wg-confgen/internal/constants"
)

const (
	nlServer = "NL#1"
	chServer = "CH#1"
	usServer = "US#1"
	brServer = "BR#1"
)

// server builds an online logical server with one online physical server.
func server(country string, tier, features int) api.LogicalServer {
	return api.LogicalServer{
		Name:        country + "#1",
		ExitCountry: country,
		Tier:        tier,
		Features:    features,
		Status:      constants.StatusOnline,
		Servers:     []api.PhysicalServer{{Status: constants.StatusOnline}},
	}
}

func TestEligibleServers(t *testing.T) {
	var (
		plusP2P    = server("NL", api.TierPlus, api.FeatureP2P)
		plusPlain  = server("NL", api.TierPlus, 0)
		plusCore   = server("CH", api.TierPlus, api.FeatureSecureCore)
		freePlain  = server("US", api.TierFree, 0)
		offline    = api.LogicalServer{Name: "off", ExitCountry: "NL", Tier: api.TierPlus, Status: 0, Servers: []api.PhysicalServer{{}}}
		noPhysical = api.LogicalServer{Name: "empty", ExitCountry: "NL", Tier: api.TierPlus, Status: constants.StatusOnline}
	)
	all := []api.LogicalServer{plusP2P, plusPlain, plusCore, freePlain, offline, noPhysical}

	tests := []struct {
		name string
		cfg  config.Config
		want []string
	}{
		{
			// Offline and physical-server-less entries never survive, and free
			// tier is excluded unless asked for.
			name: "defaults exclude offline, empty and free",
			want: []string{nlServer, nlServer, chServer},
		},
		{
			name: "country filter",
			cfg:  config.Config{Countries: []string{"CH"}},
			want: []string{chServer},
		},
		{
			name: "empty country list matches everything",
			cfg:  config.Config{Countries: nil},
			want: []string{nlServer, nlServer, chServer},
		},
		{
			name: "free-only swaps the tier filter rather than widening it",
			cfg:  config.Config{FreeOnly: true},
			want: []string{usServer},
		},
		{
			name: "p2p-only",
			cfg:  config.Config{P2PServersOnly: true},
			want: []string{nlServer},
		},
		{
			// P2P is suppressed by secure-core and by free-only, otherwise those
			// combinations would filter each other down to nothing.
			name: "secure-core suppresses the p2p filter",
			cfg:  config.Config{P2PServersOnly: true, SecureCoreOnly: true},
			want: []string{chServer},
		},
		{
			name: "free-only suppresses the p2p filter",
			cfg:  config.Config{P2PServersOnly: true, FreeOnly: true},
			want: []string{usServer},
		},
		{
			name: "secure-core alone",
			cfg:  config.Config{SecureCoreOnly: true},
			want: []string{chServer},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EligibleServers(&tt.cfg, all)
			names := make([]string, len(got))
			for i := range got {
				names[i] = got[i].Name
			}
			if len(names) != len(tt.want) {
				t.Fatalf("got %v, want %v", names, tt.want)
			}
			for i := range names {
				if names[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", names, tt.want)
				}
			}
		})
	}
}

func TestGetBestPhysicalServer(t *testing.T) {
	online := api.PhysicalServer{ID: "on", Status: constants.StatusOnline}
	down := api.PhysicalServer{ID: "down", Status: 0}

	tests := []struct {
		name string
		in   []api.PhysicalServer
		want string // "" means nil
	}{
		{name: "picks the first online", in: []api.PhysicalServer{down, online}, want: "on"},
		{name: "no physical servers", in: nil},
		// An offline endpoint would yield a config pointing at a dead server.
		{name: "all offline yields nil", in: []api.PhysicalServer{down, down}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetBestPhysicalServer(&api.LogicalServer{Servers: tt.in})
			if tt.want == "" {
				if got != nil {
					t.Fatalf("got %+v, want nil", got)
				}
				return
			}
			if got == nil || got.ID != tt.want {
				t.Fatalf("got %+v, want ID %q", got, tt.want)
			}
		})
	}
}

func selectBest(t *testing.T, cfg *config.Config, servers ...api.LogicalServer) string {
	t.Helper()
	got, err := NewServerSelector(cfg).SelectBest(servers)
	if err != nil {
		t.Fatal(err)
	}
	return got.Name
}

func scored(name, country, host string, score float64, features int) api.LogicalServer {
	s := server(country, api.TierPlus, features)
	s.Name, s.HostCountry, s.Score = name, host, score
	return s
}

// TestSelectBestMatchesOfficialClients pins the pick to what the Linux and
// Android clients do for a country: lowest score, ties to the first listed,
// never Secure Core or Tor unless asked for, never a server with no online host.
func TestSelectBestMatchesOfficialClients(t *testing.T) {
	cfg := config.Config{Countries: []string{"BR"}}

	if got := selectBest(t, &cfg,
		scored(brServer, "BR", "", 2.0, 0),
		scored("BR#2", "BR", "", 1.0, 0),
	); got != "BR#2" {
		t.Errorf("lowest score: got %s", got)
	}

	// Load no longer breaks ties; list order does, as with min() and sortedBy.
	first, second := scored(brServer, "BR", "", 1.0, 0), scored("BR#2", "BR", "", 1.0, 0)
	first.Load, second.Load = 90, 10
	if got := selectBest(t, &cfg, first, second); got != brServer {
		t.Errorf("tie: got %s, want the first listed", got)
	}

	if got := selectBest(t, &cfg,
		scored("BR#TOR", "BR", "", 0.1, api.FeatureTor),
		scored("CH-BR#1", "BR", "", 0.2, api.FeatureSecureCore),
		scored(brServer, "BR", "", 1.0, 0),
	); got != brServer {
		t.Errorf("Tor and Secure Core must be skipped: got %s", got)
	}

	down := scored("BR#DOWN", "BR", "", 0.1, 0)
	down.Servers[0].Status = 0
	if got := selectBest(t, &cfg, down, scored(brServer, "BR", "", 1.0, 0)); got != brServer {
		t.Errorf("a server whose hosts are all offline must be skipped: got %s", got)
	}
}

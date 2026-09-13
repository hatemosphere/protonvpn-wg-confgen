package vpn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ProtonVPN/go-vpn-lib/ed25519"

	"protonvpn-wg-confgen/internal/api"
	"protonvpn-wg-confgen/internal/config"
)

func TestCertificateNetShield(t *testing.T) {
	for level := range 3 {
		for _, renew := range []bool{false, true} {
			t.Run(fmt.Sprintf("level=%d/renew=%t", level, renew), func(t *testing.T) {
				var got struct {
					Features map[string]any
					Renew    bool
				}
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Error(err)
					}
					_, _ = w.Write([]byte(`{"Code":1000}`))
				}))
				defer srv.Close()
				client := NewClient(&config.Config{APIURL: srv.URL, Duration: "365d", NetShield: level, PortForwarding: true}, nil)
				key, err := ed25519.NewKeyPair()
				if err != nil {
					t.Fatal(err)
				}
				if renew {
					_, err = client.RenewCertificate("test-public-key", "test-device", nil)
				} else {
					_, err = client.GetCertificate(key)
				}
				if err != nil {
					t.Fatal(err)
				}
				if got.Features["NetShieldLevel"] != float64(level) || got.Features["PortForwarding"] != true || got.Renew != renew {
					t.Fatalf("unexpected certificate features: %+v", got)
				}
			})
		}
	}
}

func TestCertificateFeatures(t *testing.T) {
	tests := []struct {
		name               string
		cfg                config.Config
		wantRandomNAT      bool
		wantPortForwarding bool
	}{
		{
			name:          "strict NAT by default",
			wantRandomNAT: true,
		},
		{
			name:          "moderate NAT disables random NAT",
			cfg:           config.Config{ModerateNAT: true},
			wantRandomNAT: false,
		},
		{
			name:               "port forwarding",
			cfg:                config.Config{PortForwarding: true},
			wantRandomNAT:      true,
			wantPortForwarding: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(&tt.cfg, nil)
			features := client.certificateFeatures()

			if got := features["RandomNAT"]; got != tt.wantRandomNAT {
				t.Errorf("RandomNAT = %v, want %v", got, tt.wantRandomNAT)
			}
			if got := features["PortForwarding"]; got != tt.wantPortForwarding {
				t.Errorf("PortForwarding = %v, want %v", got, tt.wantPortForwarding)
			}
		})
	}
}

// TestRenewalPreservesFeatures pins the renew contract: the certificate's
// reported features are kept and translated back into request form, and only
// flags given explicitly on the command line override them.
func TestRenewalPreservesFeatures(t *testing.T) {
	// A cert created with NetShield 2, Moderate NAT on, port forwarding on,
	// accelerator off. Note moderate-nat reports as the inverse of RandomNAT.
	current := &api.CertFeatures{NetshieldLevel: 2, ModerateNAT: true, PortForwarding: true, VPNAccelerator: false}

	tests := []struct {
		name    string
		cfg     config.Config
		current *api.CertFeatures
		want    map[string]any
	}{
		{
			// Flag defaults would say NetShield 0 / RandomNAT true / PF off /
			// SplitTCP on; none may leak through when nothing was passed.
			name:    "nothing explicit keeps the certificate as is",
			cfg:     config.Config{EnableAccelerator: true},
			current: current,
			want:    map[string]any{featNetShield: 2, featRandomNAT: false, featPortForwarding: true, featSplitTCP: false},
		},
		{
			name:    "explicit flag overrides only that feature",
			cfg:     config.Config{EnableAccelerator: true, NetShield: 0, Explicit: map[string]bool{"netshield": true}},
			current: current,
			want:    map[string]any{featNetShield: 0, featRandomNAT: false, featPortForwarding: true, featSplitTCP: false},
		},
		{
			name:    "explicit moderate-nat off flips RandomNAT back on",
			cfg:     config.Config{EnableAccelerator: true, ModerateNAT: false, Explicit: map[string]bool{"moderate-nat": true}},
			current: current,
			want:    map[string]any{featNetShield: 2, featRandomNAT: true, featPortForwarding: true, featSplitTCP: false},
		},
		{
			name:    "no reported features falls back to flags",
			cfg:     config.Config{EnableAccelerator: true, NetShield: 1, PortForwarding: true},
			current: nil,
			want:    map[string]any{featNetShield: 1, featRandomNAT: true, featPortForwarding: true, featSplitTCP: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewClient(&tt.cfg, nil).renewalFeatures(tt.current)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("%s = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

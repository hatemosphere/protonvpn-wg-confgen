package vpn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ProtonVPN/go-vpn-lib/ed25519"

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
					_, err = client.RenewCertificate("test-public-key", "test-device")
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

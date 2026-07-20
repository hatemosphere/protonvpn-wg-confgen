package vpn

import (
	"testing"

	"protonvpn-wg-confgen/internal/config"
)

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

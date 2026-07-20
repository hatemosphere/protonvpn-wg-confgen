package config

import "testing"

func TestValidateFeatureFlags(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "defaults"},
		{name: "port forwarding", cfg: Config{PortForwarding: true}},
		{name: "moderate NAT", cfg: Config{ModerateNAT: true}},
		{
			name:    "mutually exclusive features",
			cfg:     Config{PortForwarding: true, ModerateNAT: true},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFeatureFlags(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateFeatureFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

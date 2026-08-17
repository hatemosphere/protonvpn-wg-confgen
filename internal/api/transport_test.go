package api

import (
	"net/http"
	"testing"
)

func TestSetHumanVerification(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		method    string
		wantToken string
		wantType  string
	}{
		{
			name: "empty token leaves the request untouched",
		},
		{
			name:      "token and method are replayed verbatim",
			token:     "abc123",
			method:    "captcha",
			wantToken: "abc123",
			wantType:  "captcha",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "https://example.invalid", http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			SetHumanVerification(req, tt.token, tt.method)

			if got := req.Header.Get(hvTokenHeader); got != tt.wantToken {
				t.Errorf("%s = %q, want %q", hvTokenHeader, got, tt.wantToken)
			}
			if got := req.Header.Get(hvTokenTypeHeader); got != tt.wantType {
				t.Errorf("%s = %q, want %q", hvTokenTypeHeader, got, tt.wantType)
			}
		})
	}
}

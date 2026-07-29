// Package validation provides input validation utilities.
package validation

import (
	"strings"
)

// CleanUsername removes email domain suffixes from username.
// ProtonVPN usernames don't include the email domain.
func CleanUsername(username string) string {
	username = strings.TrimSpace(username)
	username = strings.TrimSuffix(username, "@protonmail.com")
	username = strings.TrimSuffix(username, "@proton.me")
	username = strings.TrimSuffix(username, "@pm.me")
	return username
}

// IsValidCountryCode checks if a country code is valid (2 letters).
func IsValidCountryCode(code string) bool {
	return len(code) == 2 && isAlpha(code)
}

// isAlpha checks if a string contains only alphabetic characters.
func isAlpha(s string) bool {
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

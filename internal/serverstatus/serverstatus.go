// Package serverstatus scores servers from the v2 server list, a port of
// Proton's proton-vpn-binary-status library, which the official clients use
// once their BinaryServerStatus feature flag is on. The v2 list carries no
// loads or scores; they come from a binary status file and are combined with
// the caller's location, so that nearby and in-country servers rank first.
//
// Source: https://github.com/ProtonVPN/proton-vpn-binary-status (commit
// c751e8c), built with its default features: jitter on, legacy off.
package serverstatus

import (
	"encoding/binary"
	"errors"
	"math"
	"math/rand/v2"
	"strings"
)

// Location is a point in degrees. The library keeps coordinates as 32-bit
// floats, and the precision loss is part of the scores it produces.
type Location struct {
	Latitude  float32 `json:"Latitude"`
	Longitude float32 `json:"Longitude"`
}

// StatusReference ties a logical server to its entry in the status file.
type StatusReference struct {
	Index   uint32  `json:"Index"`
	Penalty float64 `json:"Penalty"` // computed by the backend
	Cost    uint8   `json:"Cost"`    // 1 for servers that are expensive to route to
}

// Logical is what scoring needs from a v2 logical server.
type Logical struct {
	StatusReference StatusReference
	EntryLocation   Location
	ExitLocation    Location
	ExitCountry     string
}

// Load is a server's computed state. A lower Score is better.
type Load struct {
	Enabled         bool
	Visible         bool
	Autoconnectable bool
	Load            uint8
	Score           float64
}

const (
	statusEnabled         = 1 << 0
	statusVisible         = 1 << 1
	statusAutoconnectable = 1 << 2

	entrySize = 6 // status u8, load u8, partial score f32 little endian

	scoreNormalization    = 10_000.0  // Mbps
	bandwidthPerKm        = 738_000.0 // Mbps * km
	partialScoreCeiling   = 0.99
	normalizedJitterRange = -(100.0 / scoreNormalization)
	earthRadiusKm         = 6_371.0
)

var header = [4]byte{1, 0, 0, 0}

// jitter spreads clients with identical inputs across near-equal servers, as
// the library does; tests replace it to get deterministic scores.
var jitter = func() float64 {
	return (rand.Float64() - 0.5) * normalizedJitterRange //nolint:gosec // G404: load spreading, not a secret
}

type serverStatus struct {
	status       uint8
	load         uint8
	partialScore float32
}

// ComputeLoads scores each logical server against the status file. user is
// the caller's location, nil when unknown; userCountry is its two-letter
// code, "" when unknown, which counts every server as in-country.
func ComputeLoads(logicals []Logical, statusFile []byte, user *Location, userCountry string) ([]Load, error) {
	if len(statusFile) < len(header) || [4]byte(statusFile[:4]) != header {
		return nil, errors.New("server status file has an invalid header")
	}
	entries := statusFile[len(header):]
	if len(entries)%entrySize != 0 {
		return nil, errors.New("server status file is corrupt")
	}

	loads := make([]Load, len(logicals))
	for i := range logicals {
		l := &logicals[i]
		s := statusAt(entries, l.StatusReference.Index)
		loads[i] = Load{
			Enabled:         s.status&statusEnabled != 0,
			Visible:         s.status&statusVisible != 0,
			Autoconnectable: s.status&statusAutoconnectable != 0,
			Load:            s.load,
			Score:           score(l, s, user, userCountry, jitter()),
		}
	}
	return loads, nil
}

// statusAt returns the entry at index. Entries that are missing or out of
// range read as the zero status, i.e. disabled and hidden.
func statusAt(entries []byte, index uint32) serverStatus {
	offset := int(index) * entrySize
	if offset+entrySize > len(entries) {
		return serverStatus{}
	}
	e := entries[offset : offset+entrySize]
	s := serverStatus{
		status:       e[0],
		load:         e[1],
		partialScore: math.Float32frombits(binary.LittleEndian.Uint32(e[2:])),
	}
	if s.load > 100 || s.partialScore < 0 || s.partialScore > 1 {
		return serverStatus{}
	}
	return s
}

func score(l *Logical, s serverStatus, user *Location, userCountry string, jitter float64) float64 {
	partial := float64(s.partialScore)
	// Rust's f64::max, which unlike math.Max ignores a NaN operand.
	capped := distanceScore(l, user)
	if partial > capped {
		capped = partial
	}
	base := min(max(capped+jitter, 0), 1)
	return base + penalty(l, s.status, partial, userCountry)
}

func normalize(mbps float64) float64 {
	return (scoreNormalization - mbps) / scoreNormalization
}

// distanceScore estimates the bandwidth the route allows from its length:
// caller to entry, then entry to exit, which only differ for Secure Core.
func distanceScore(l *Logical, user *Location) float64 {
	km := 0.0
	if user != nil {
		km = distance(*user, l.EntryLocation) + distance(l.EntryLocation, l.ExitLocation)
	}
	return normalize(bandwidthPerKm / math.Max(1, km))
}

func penalty(l *Logical, status uint8, partial float64, userCountry string) float64 {
	sameCountry := userCountry == "" || strings.EqualFold(userCountry, l.ExitCountry)

	p := l.StatusReference.Penalty
	if status&statusEnabled == 0 || status&statusVisible == 0 {
		p += 1000
	}
	if !sameCountry || partial >= partialScoreCeiling {
		p++
	}
	if !sameCountry && l.StatusReference.Cost == 1 {
		p += 3
	}
	return p
}

// distance is the haversine great-circle distance in km.
func distance(a, b Location) float64 {
	const rad = math.Pi / 180
	lat1, lon1 := float64(a.Latitude)*rad, float64(a.Longitude)*rad
	lat2, lon2 := float64(b.Latitude)*rad, float64(b.Longitude)*rad
	return haversine(lat1, lon1, lat2, lon2)
}

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	sq := func(x float64) float64 { return x * x }
	h := sq(math.Sin((lat2-lat1)/2)) + math.Cos(lat1)*math.Cos(lat2)*sq(math.Sin((lon2-lon1)/2))
	return earthRadiusKm * 2 * math.Asin(math.Sqrt(h))
}

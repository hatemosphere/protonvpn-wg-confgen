package serverstatus

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

// The vectors and fixtures below come from proton-vpn-binary-status's own
// tests, so that this port is held to the same expectations as the original.

func TestDistanceBetweenCities(t *testing.T) {
	cities := []struct {
		name     string
		lat, lon float64
	}{
		{"Geneva", 46.204391, 6.143158},
		{"Paris", 48.864716, 2.349014},
		{"Wellington", -41.28664, 174.77557},
		{"Zurich", 47.36667, 8.55},
		{"New York", 40.730610, -73.935242},
	}
	for _, tc := range []struct {
		a, b int
		km   float64
	}{
		{0, 1, 410.55498572415354},
		{0, 2, 18952.24386743237},
		{0, 3, 224.22549168303365},
		{0, 4, 6210.329769582576},
		{1, 2, 18984.85817822091},
		{1, 3, 489.37749906455656},
		{1, 4, 5830.710905402295},
		{2, 3, 18730.398033198726},
		{2, 4, 14409.66518127578},
		{3, 4, 6318.845334665826},
	} {
		const rad = math.Pi / 180
		a, b := cities[tc.a], cities[tc.b]
		got := haversine(a.lat*rad, a.lon*rad, b.lat*rad, b.lon*rad)
		if math.Abs(got-tc.km) > 1e-9 {
			t.Errorf("%s -> %s = %v km, want %v", a.name, b.name, got, tc.km)
		}
	}
}

func TestPenalty(t *testing.T) {
	const on = statusEnabled | statusVisible
	for _, tc := range []struct {
		name          string
		statusPenalty float64
		cost          uint8
		partial       float64
		user, server  string
		status        uint8
		want          float64
	}{
		{"optimal", 0, 0, 0.5, "FR", "FR", on, 0},
		{"backend penalty", 123, 0, 0.5, "FR", "FR", on, 123},
		{"load near ceiling", 0, 0, 0.99, "FR", "FR", on, 1},
		{"other country", 0, 0, 0.5, "FR", "GB", on, 1},
		{"other country, costly", 0, 1, 0.5, "FR", "GB", on, 4},
		{"hidden", 0, 0, 0.5, "FR", "FR", statusEnabled, 1000},
		{"disabled", 0, 0, 0.5, "FR", "FR", statusVisible, 1000},
		{"disabled and hidden", 0, 0, 0.5, "FR", "FR", 0, 1000},
		{"unknown user country", 0, 0, 0.5, "", "FR", on, 0},
	} {
		l := Logical{StatusReference: StatusReference{Penalty: tc.statusPenalty, Cost: tc.cost}, ExitCountry: tc.server}
		if got := penalty(&l, tc.status, tc.partial, tc.user); got != tc.want {
			t.Errorf("%s: penalty = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestScore(t *testing.T) {
	on := serverStatus{status: statusEnabled | statusVisible, partialScore: 0.5}

	// In the same country and far enough away for distance to dominate.
	paris := Location{48.8566, 2.3522}
	toulouse := Location{43.6047, 1.4442}
	l := Logical{EntryLocation: paris, ExitLocation: paris, ExitCountry: "FR"}
	if got, want := score(&l, on, &toulouse, "FR", 0), distanceScore(&l, &toulouse); got != want {
		t.Errorf("Toulouse -> Paris score = %v, want %v", got, want)
	}

	// Close enough for the load to dominate, but across a border.
	annecy := Location{45.8992, 6.1294}
	geneva := Location{46.2044, 6.1432}
	l = Logical{EntryLocation: annecy, ExitLocation: annecy, ExitCountry: "FR"}
	if got := score(&l, on, &geneva, "CH", 0); got != 1.5 {
		t.Errorf("Geneva -> Annecy score = %v, want 1.5", got)
	}

	if got, want := distanceScore(&l, nil), 1-bandwidthPerKm/scoreNormalization; got != want {
		t.Errorf("distance score without a user location = %v, want %v", got, want)
	}
}

func TestStatusFile(t *testing.T) {
	statusFile := []byte{
		1, 0, 0, 0,
		0, 0, 0, 0, 0, 0, // disabled, hidden
		1, 0, 0, 0, 0, 0, // enabled, hidden
		2, 0, 0, 0, 0, 0, // disabled, visible
		7, 42, 0, 0, 0, 0, // enabled, visible, autoconnectable
		3, 101, 0, 0, 0, 0, // load out of range: read as unknown
	}
	logicals := make([]Logical, 6) // the last one is past the end of the file
	for i := range logicals {
		logicals[i].StatusReference.Index = uint32(i)
	}
	loads, err := ComputeLoads(logicals, statusFile, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Load{
		{},
		{Enabled: true},
		{Visible: true},
		{Enabled: true, Visible: true, Autoconnectable: true, Load: 42},
		{},
		{},
	}
	for i := range want {
		got := loads[i]
		got.Score = 0
		if got != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got, want[i])
		}
	}

	for _, bad := range [][]byte{nil, {1, 0, 0}, {2, 0, 0, 0}, {1, 0, 0, 0, 1}} {
		if _, err := ComputeLoads(nil, bad, nil, ""); err == nil {
			t.Errorf("status file %v accepted", bad)
		}
	}
}

// TestScoresMatchV1 checks that scores computed from a v2 server list agree
// with the scores the backend put in the v1 list fetched at the same time, as
// seen from Los Angeles. Loads are whole percentages, so scores can differ by
// up to 1% of the 10 Gbps normalization range.
func TestScoresMatchV1(t *testing.T) {
	jitter = func() float64 { return 0 }

	var v1 struct {
		LogicalServers []struct {
			Name        string
			Score       float64
			ScoreJitter float64 // bps
		}
	}
	var v2 struct {
		LogicalServers []struct {
			Name string
			Logical
		}
	}
	readJSON(t, "testdata/v1_logicals.json", &v1)
	readJSON(t, "testdata/v2_logicals.json", &v2)
	statusFile, err := os.ReadFile("testdata/status.bin")
	if err != nil {
		t.Fatal(err)
	}

	logicals := make([]Logical, len(v2.LogicalServers))
	for i, s := range v2.LogicalServers {
		logicals[i] = s.Logical
	}
	loads, err := ComputeLoads(logicals, statusFile, &Location{34.0544, -118.244}, "US")
	if err != nil {
		t.Fatal(err)
	}
	scores := make(map[string]float64, len(loads))
	for i, s := range v2.LogicalServers {
		scores[s.Name] = loads[i].Score
	}

	if len(v1.LogicalServers) == 0 {
		t.Fatal("no servers in fixture")
	}
	for _, a := range v1.LogicalServers {
		b, ok := scores[a.Name]
		if !ok {
			t.Errorf("%s missing from the v2 list", a.Name)
			continue
		}
		// The v1 score carries the backend's jitter; apply it to ours.
		whole, frac := math.Modf(b)
		b = whole + min(max(frac-a.ScoreJitter/1e6/scoreNormalization, 0), 1)
		if math.Abs(a.Score-b) > 0.01 {
			t.Errorf("%s: v2 score %.6f, v1 score %.6f", a.Name, b, a.Score)
		}
	}
}

func readJSON(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: fixed testdata path
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}

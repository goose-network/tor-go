package guard

import (
	"testing"
	"time"
)

// makeEligible builds n eligible guards with distinct IDs and increasing
// bandwidth.
func makeEligible(n int) []EligibleGuard {
	out := make([]EligibleGuard, n)
	for i := 0; i < n; i++ {
		// Distinct single-byte-ish hex IDs.
		id := []byte{byte('a' + i/26), byte('a' + i%26)}
		out[i] = EligibleGuard{
			ID:       string(id) + "00000000000000000000000000000000000000",
			Bandwidth: uint64(1000 + i*10),
		}
	}
	return out
}

func TestExpandSampleRespectsMaxSize(t *testing.T) {
	m := NewManager(Params{MaxSampleSize: 5, MinFilteredSampleSize: 20, MaxSampleThresholdPercent: 20})
	// 100 eligible guards; max sample is min(5, 20% of 100=20, but capped at 5) = 5.
	// However maxSampleSize floors at MinFilteredSampleSize (20), so the cap is 20.
	// With MaxSampleSize=5 and MinFilteredSampleSize=20, the floor wins → 20.
	m.ExpandSample(makeEligible(100), time.Now())
	if got := len(m.Sampled()); got != 20 {
		t.Fatalf("sampled = %d, want 20 (min filtered floor)", got)
	}
}

func TestExpandSampleThresholdPercent(t *testing.T) {
	// 100 eligible, threshold 20%, max 60, min 20 → 20% of 100 = 20.
	m := NewManager(Params{MaxSampleSize: 60, MinFilteredSampleSize: 20, MaxSampleThresholdPercent: 20})
	m.ExpandSample(makeEligible(100), time.Now())
	if got := len(m.Sampled()); got != 20 {
		t.Fatalf("sampled = %d, want 20", got)
	}
}

func TestExpandSampleSmallEligible(t *testing.T) {
	// Only 10 eligible; threshold 20% → 2, but floored at min 20 → capped at 10.
	m := NewManager(Params{MaxSampleSize: 60, MinFilteredSampleSize: 20, MaxSampleThresholdPercent: 20})
	m.ExpandSample(makeEligible(10), time.Now())
	if got := len(m.Sampled()); got != 10 {
		t.Fatalf("sampled = %d, want 10 (all eligible)", got)
	}
}

func TestExpandSampleIdempotent(t *testing.T) {
	m := NewManager(Params{MaxSampleSize: 60, MinFilteredSampleSize: 20})
	elig := makeEligible(100)
	m.ExpandSample(elig, time.Now())
	first := m.Sampled()
	m.ExpandSample(elig, time.Now())
	second := m.Sampled()
	if len(first) != len(second) {
		t.Fatalf("second expand changed sample size: %d → %d", len(first), len(second))
	}
	// Same set of IDs.
	seen := map[string]bool{}
	for _, g := range second {
		seen[g.ID] = true
	}
	for _, g := range first {
		if !seen[g.ID] {
			t.Fatalf("guard %s disappeared on re-expand", g.ID)
		}
	}
}

func TestPickPrimaryFirst(t *testing.T) {
	m := NewManager(Params{NPrimaryGuards: 3, MinFilteredSampleSize: 10})
	m.ExpandSample(makeEligible(50), time.Now())
	primaries := m.Primary()
	if len(primaries) == 0 {
		t.Fatal("no primary guards")
	}
	sel := m.PickForCircuit(makeEligible(50), time.Now())
	if sel == nil {
		t.Fatal("PickForCircuit returned nil")
	}
	if !sel.UsableOnCompletion {
		t.Error("primary pick should be usable on completion")
	}
	// The chosen guard must be one of the primaries.
	isPrimary := false
	for _, g := range primaries {
		if g.ID == sel.Guard.ID {
			isPrimary = true
		}
	}
	if !isPrimary {
		t.Fatalf("picked non-primary guard %s", sel.Guard.ID)
	}
}

func TestConfirmOnSuccess(t *testing.T) {
	m := NewManager(Params{NPrimaryGuards: 3, MinFilteredSampleSize: 10})
	m.ExpandSample(makeEligible(50), time.Now())
	sel := m.PickForCircuit(makeEligible(50), time.Now())
	if sel == nil {
		t.Fatal("nil selection")
	}
	if len(m.Confirmed()) != 0 {
		t.Fatal("expected no confirmed guards before success")
	}
	m.NoteConnectionSuccess(sel.Guard.ID, time.Now())
	if len(m.Confirmed()) != 1 {
		t.Fatalf("expected 1 confirmed guard, got %d", len(m.Confirmed()))
	}
	if m.Confirmed()[0].ID != sel.Guard.ID {
		t.Error("confirmed guard is not the one that succeeded")
	}
}

func TestFailureThenRetry(t *testing.T) {
	m := NewManager(Params{NPrimaryGuards: 3, MinFilteredSampleSize: 10})
	m.ExpandSample(makeEligible(50), time.Now())
	sel := m.PickForCircuit(makeEligible(50), time.Now())
	now := time.Now()
	m.NoteConnectionFailure(sel.Guard.ID, now)
	g := m.Lookup(sel.Guard.ID)
	if g.IsReachable != ReachableNo {
		t.Fatalf("expected ReachableNo after failure, got %d", g.IsReachable)
	}
	if g.FailingSince.IsZero() {
		t.Error("FailingSince not set")
	}
	// Immediately after, the guard is not retriable (delay not elapsed for
	// non-primary: 1 hour). For a primary guard the delay is 10 minutes.
	// Simulate time passing past the retry delay.
	later := now.Add(2 * time.Hour)
	// Pick again; the failed guard should become maybe-reachable via
	// considerRetry and may be reselected.
	_ = m.PickForCircuit(makeEligible(50), later)
	g = m.Lookup(sel.Guard.ID)
	if g.IsReachable == ReachableNo {
		t.Error("guard still ReachableNo after retry delay elapsed")
	}
}

func TestUpdateListingDropsUnlisted(t *testing.T) {
	m := NewManager(Params{MinFilteredSampleSize: 5, RemoveUnlistedAfterDays: 20})
	m.ExpandSample(makeEligible(20), time.Now())
	sampled := m.Sampled()
	if len(sampled) == 0 {
		t.Fatal("no sampled guards")
	}
	// Mark only the first guard as still listed.
	listed := map[string]bool{sampled[0].ID: true}
	// SampledOn is now; the unlisted cutoff (20 days) has not elapsed, so
	// guards are kept but unfiltered.
	dropped := m.UpdateListing(listed, time.Now())
	if dropped != 0 {
		t.Fatalf("expected 0 dropped (cutoff not elapsed), got %d", dropped)
	}
	for _, g := range m.Sampled() {
		if g.ID == sampled[0].ID {
			if !g.IsFilteredGuard {
				t.Error("listed guard should remain filtered")
			}
		} else {
			if g.IsFilteredGuard {
				t.Error("unlisted guard should be unfiltered")
			}
		}
	}
	// Now advance past the cutoff: unlisted guards should be dropped.
	oldSampledOn := time.Now().Add(-30 * 24 * time.Hour)
	m.mu.Lock()
	for _, g := range m.sampled {
		g.SampledOn = oldSampledOn
	}
	m.mu.Unlock()
	dropped = m.UpdateListing(listed, time.Now())
	if dropped != len(sampled)-1 {
		t.Fatalf("expected %d dropped, got %d", len(sampled)-1, dropped)
	}
	if len(m.Sampled()) != 1 {
		t.Fatalf("expected 1 sampled guard left, got %d", len(m.Sampled()))
	}
}

func TestRetrySchedule(t *testing.T) {
	now := time.Now()
	// Primary, failing < 6h → 10 min.
	if d := retrySchedule(now.Add(-time.Hour), now, true); d != 10*time.Minute {
		t.Errorf("primary <6h: got %v, want 10m", d)
	}
	// Non-primary, failing < 6h → 1 h.
	if d := retrySchedule(now.Add(-time.Hour), now, false); d != time.Hour {
		t.Errorf("non-primary <6h: got %v, want 1h", d)
	}
	// Primary, 6h..4d → 90 min.
	if d := retrySchedule(now.Add(-2*24*time.Hour), now, true); d != 90*time.Minute {
		t.Errorf("primary 6h-4d: got %v, want 90m", d)
	}
	// Non-primary, 4d..7d → 18 h (tier {SEVEN_DAYS, 4h, 18h}).
	if d := retrySchedule(now.Add(-5*24*time.Hour), now, false); d != 18*time.Hour {
		t.Errorf("non-primary 4d-7d: got %v, want 18h", d)
	}
	// Non-primary, 6h..4d → 4 h (tier {FOUR_DAYS, 90m, 4h}).
	if d := retrySchedule(now.Add(-2*24*time.Hour), now, false); d != 4*time.Hour {
		t.Errorf("non-primary 6h-4d: got %v, want 4h", d)
	}
	// Primary, > 7d → 9 h.
	if d := retrySchedule(now.Add(-10*24*time.Hour), now, true); d != 9*time.Hour {
		t.Errorf("primary >7d: got %v, want 9h", d)
	}
}

func TestPickExpandsWhenEmpty(t *testing.T) {
	m := NewManager(Params{MinFilteredSampleSize: 5})
	// No ExpandSample called yet; PickForCircuit should expand and return.
	sel := m.PickForCircuit(makeEligible(20), time.Now())
	if sel == nil {
		t.Fatal("PickForCircuit returned nil on empty sample")
	}
	if len(m.Sampled()) == 0 {
		t.Fatal("sample not expanded by PickForCircuit")
	}
}

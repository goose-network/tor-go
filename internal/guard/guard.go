// Package guard implements the guard-selection state machine from Tor
// proposal 271 ("The Next Generation Guard Design"), which Tor uses to pick
// the first hop of every circuit.
//
// The design protects clients from guard-set manipulation by keeping a
// persistent, bounded *sample* of the guard relays, filtering it against the
// current configuration, marking a small number of *primary* guards that are
// preferred, and recording *confirmed* guards that have been used
// successfully. Selection prefers primary guards, then confirmed guards, then
// the rest of the filtered sample, expanding the sample if it is too small.
//
// This mirrors src/feature/client/entrynodes.c (entry_guards_expand_sample,
// entry_guards_update_primary, select_entry_guard_for_circuit,
// entry_guard_consider_retry, entry_guard_relayed_succeeded) and the
// entry_guard_t / guard_selection_t structures in entrynodes.h.
package guard

import (
	"crypto/rand"
	"encoding/binary"
	"sort"
	"sync"
	"time"
)

// Reachability mirrors GUARD_REACHABLE_* (entrynodes.h:78).
const (
	ReachableNo    = 0 // a recent attempt failed
	ReachableYes   = 1 // a recent attempt succeeded
	ReachableMaybe = 2 // not tried recently, or due for retry
)

// Default parameters (entrynodes.h:431-467). These are the consensus
// parameter defaults; a real client reads overrides from the consensus, but
// the defaults are what Tor ships with.
const (
	DefaultMaxSampleThresholdPercent = 20 // sample ≤ 20% of eligible guards
	DefaultMaxSampleSize             = 60 // ...and never more than this
	DefaultMinFilteredSampleSize     = 20 // keep at least this many filtered
	DefaultNPrimaryGuards            = 3  // preferred guards
	DefaultGuardLifetimeDays         = 120
	DefaultGuardConfirmedMinLifetimeDays = 60
	DefaultRemoveUnlistedAfterDays        = 20
)

// Guard is a single sampled guard relay and its prop271 state. It mirrors
// entry_guard_t (entrynodes.h:87-189).
type Guard struct {
	// ID is the relay's RSA identity digest (the consensus "r" line identity),
	// hex-encoded. This is the stable key for a guard across consensus
	// refreshes.
	ID string

	// SampledOn is when the guard was added to the sample.
	SampledOn time.Time
	// ConfirmedOn is when the guard was first used successfully (zero if never
	// confirmed).
	ConfirmedOn time.Time
	// SampledIdx is the position of this guard in sample order (the order in
	// which guards were added to the sample). Used to order the confirmed list.
	SampledIdx int
	// ConfirmedIdx is the position in the confirmed list, or -1 if not
	// confirmed.
	ConfirmedIdx int

	// LastTriedToConnect is the last time we attempted to use this guard.
	LastTriedToConnect time.Time
	// FailingSince is when the guard started failing (zero if not failing).
	FailingSince time.Time

	// State flags (entrynodes.h).
	IsReachable             int // ReachableNo/Yes/Maybe
	IsPending               bool
	IsFilteredGuard         bool // passes the current filter
	IsUsableFilteredGuard   bool // filtered AND reachable-or-maybe
	IsPrimary               bool
	CurrentlyListed        bool // present in the latest consensus
}

// Selection is the result of choosing a guard for a circuit: the chosen
// guard and the circuit-state to apply (mirrors GUARD_CIRC_STATE_*).
type Selection struct {
	Guard *Guard
	// UsableOnCompletion is true when the chosen guard is a primary guard
	// (GUARD_CIRC_STATE_USABLE_ON_COMPLETION): the circuit may be used as soon
	// as it completes. False means the guard is a fallback
	// (GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD): the circuit should only be
	// used if no better guard produces a working circuit.
	UsableOnCompletion bool
}

// Manager holds the prop271 guard state for one guard selection. It is safe
// for concurrent use. It mirrors guard_selection_t (entrynodes.h:206-260).
type Manager struct {
	mu sync.Mutex

	// sampled is the bounded sample of guards, in sample order.
	sampled []*Guard
	// confirmed is the set of guards used successfully, ordered by sampled
	// index (the order in which they were first sampled).
	confirmed []*Guard
	// primary is the preferred set (top N confirmed/filtered).
	primary []*Guard

	// byID indexes sampled guards by ID for fast lookup.
	byID map[string]*Guard

	// nextSampledIdx is the next sample-order index to assign.
	nextSampledIdx int

	// primaryUpToDate is false when the primary list needs recomputing.
	primaryUpToDate bool

	// params holds the tunable parameters.
	params Params
}

// Params are the consensus-derived parameters. Zero values fall back to the
// defaults.
type Params struct {
	MaxSampleThresholdPercent int
	MaxSampleSize             int
	MinFilteredSampleSize     int
	NPrimaryGuards            int
	GuardLifetimeDays         int
	RemoveUnlistedAfterDays   int
}

func (p Params) withDefaults() Params {
	if p.MaxSampleThresholdPercent <= 0 {
		p.MaxSampleThresholdPercent = DefaultMaxSampleThresholdPercent
	}
	if p.MaxSampleSize <= 0 {
		p.MaxSampleSize = DefaultMaxSampleSize
	}
	if p.MinFilteredSampleSize <= 0 {
		p.MinFilteredSampleSize = DefaultMinFilteredSampleSize
	}
	if p.NPrimaryGuards <= 0 {
		p.NPrimaryGuards = DefaultNPrimaryGuards
	}
	if p.GuardLifetimeDays <= 0 {
		p.GuardLifetimeDays = DefaultGuardLifetimeDays
	}
	if p.RemoveUnlistedAfterDays <= 0 {
		p.RemoveUnlistedAfterDays = DefaultRemoveUnlistedAfterDays
	}
	return p
}

// NewManager creates a new, empty guard manager.
func NewManager(p Params) *Manager {
	return &Manager{
		byID:            make(map[string]*Guard),
		params:          p.withDefaults(),
		primaryUpToDate: false,
	}
}

// EligibleGuard describes a relay eligible to be sampled (a Guard-flagged
// relay with an ntor key, as determined by the caller from the consensus).
type EligibleGuard struct {
	ID       string // hex RSA identity digest
	Bandwidth uint64
}

// ExpandSample grows the sampled set until it contains at least
// MinFilteredSampleSize usable filtered guards, or the sample reaches its
// maximum size, or eligible is exhausted. This mirrors
// entry_guards_expand_sample (entrynodes.c:1182).
//
// eligible is the full set of guards eligible to be sampled, in preference
// order (e.g. bandwidth-sorted). Already-sampled guards are skipped. The
// caller should pass the same eligible set on each call; sampling is
// idempotent for guards already in the sample.
func (m *Manager) ExpandSample(eligible []EligibleGuard, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expandSampleLocked(eligible, now)
}

func (m *Manager) expandSampleLocked(eligible []EligibleGuard, now time.Time) {
	p := m.params
	maxSample := m.maxSampleSize(len(eligible))

	nUsableFiltered := m.numUsableFilteredLocked()
	for nUsableFiltered < p.MinFilteredSampleSize {
		if len(m.sampled) >= maxSample {
			return
		}
		added := m.selectAndAddLocked(eligible, now)
		if added == nil {
			return // ran out of eligible guards
		}
		if added.IsUsableFilteredGuard {
			nUsableFiltered++
		}
	}
}

// maxSampleSize returns the maximum sample size: the smaller of the absolute
// cap and threshold-percent of the eligible set (entrynodes.c:1047).
func (m *Manager) maxSampleSize(nEligible int) int {
	p := m.params
	byPercent := nEligible * p.MaxSampleThresholdPercent / 100
	if byPercent < 1 {
		byPercent = 1
	}
	if byPercent > p.MaxSampleSize {
		byPercent = p.MaxSampleSize
	}
	// Always allow at least the minimum filtered sample so we can reach it.
	if byPercent < p.MinFilteredSampleSize {
		byPercent = p.MinFilteredSampleSize
	}
	return byPercent
}

// selectAndAddLocked picks the next eligible guard not yet sampled and adds
// it. Sampling is bandwidth-weighted among the not-yet-sampled eligible
// guards (mirrors select_and_add_guard_item_for_sample, which uses
// smartlist_choose by weighted bandwidth). Returns the added guard, or nil if
// none remain.
func (m *Manager) selectAndAddLocked(eligible []EligibleGuard, now time.Time) *Guard {
	// Collect eligible guards not yet in the sample.
	type cand struct {
		idx      int
		bandwidth uint64
	}
	var cands []cand
	for i, e := range eligible {
		if _, ok := m.byID[e.ID]; ok {
			continue
		}
		cands = append(cands, cand{i, e.Bandwidth})
	}
	if len(cands) == 0 {
		return nil
	}
	// Weighted choice by bandwidth; uniform if all weights zero.
	var total uint64
	for _, c := range cands {
		total += c.bandwidth
	}
	var pick int
	if total == 0 {
		pick = cryptoRandInt(len(cands))
	} else {
		r := cryptoRandUint64(total)
		var cum uint64
		for i, c := range cands {
			cum += c.bandwidth
			if r < cum {
				pick = i
				break
			}
		}
	}
	chosen := eligible[cands[pick].idx]

	g := &Guard{
		ID:             chosen.ID,
		SampledOn:      now,
		SampledIdx:     m.nextSampledIdx,
		ConfirmedIdx:   -1,
		IsReachable:    ReachableMaybe,
		IsFilteredGuard: true, // a freshly sampled guard passes the filter
		IsUsableFilteredGuard: true,
		CurrentlyListed: true,
	}
	m.nextSampledIdx++
	m.sampled = append(m.sampled, g)
	m.byID[chosen.ID] = g
	m.primaryUpToDate = false
	return g
}

// numUsableFilteredLocked counts sampled guards that are usable+filtered.
func (m *Manager) numUsableFilteredLocked() int {
	n := 0
	for _, g := range m.sampled {
		if g.IsUsableFilteredGuard {
			n++
		}
	}
	return n
}

// UpdateListing refreshes the "currently listed" and filter state of sampled
// guards against the latest set of known guard IDs. Guards absent from the
// new consensus are marked unlisted and removed from the filter; guards
// unlisted for too long are dropped from the sample. This mirrors
// entry_guards_update_all_lists / entry_guard_set_filtered.
//
// listedIDs is the set of guard IDs present in the new consensus (with the
// Guard flag). Returns the number of guards dropped as unlisted-too-long.
func (m *Manager) UpdateListing(listedIDs map[string]bool, now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	dropped := 0
	cutoff := time.Duration(m.params.RemoveUnlistedAfterDays) * 24 * time.Hour
	keep := m.sampled[:0]
	for _, g := range m.sampled {
		listed := listedIDs[g.ID]
		g.CurrentlyListed = listed
		if listed {
			// A listed guard passes the filter and is usable if reachable.
			g.IsFilteredGuard = true
			if g.IsReachable != ReachableNo {
				g.IsUsableFilteredGuard = true
			}
			keep = append(keep, g)
			continue
		}
		// Unlisted: drop from filter.
		g.IsFilteredGuard = false
		g.IsUsableFilteredGuard = false
		if !g.SampledOn.IsZero() && now.Sub(g.SampledOn) > cutoff {
			// Unlisted too long: remove from the sample entirely.
			delete(m.byID, g.ID)
			m.removeFromConfirmedLocked(g)
			dropped++
			continue
		}
		keep = append(keep, g)
	}
	if dropped > 0 {
		m.sampled = keep
		m.primaryUpToDate = false
	}
	return dropped
}

// PickForCircuit chooses a guard for a new circuit, following the prop271
// selection order: primary guards first, then confirmed guards, then the
// filtered sample (expanding the sample if needed). It updates the guard's
// last-tried and pending state. Returns nil if no guard is available.
//
// This mirrors select_entry_guard_for_circuit (entrynodes.c:2314).
func (m *Manager) PickForCircuit(eligible []EligibleGuard, now time.Time) *Selection {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.primaryUpToDate {
		m.updatePrimaryLocked()
	}

	// 1. Primary guards: the first N that are reachable (maybe/yes).
	if sel := m.selectPrimaryLocked(now); sel != nil {
		return sel
	}

	// 2. Confirmed guards (non-primary, usable+filtered, not pending).
	if sel := m.selectConfirmedLocked(now); sel != nil {
		return sel
	}

	// 3. Filtered sample (excluding confirmed/primary/pending).
	if sel := m.selectFilteredLocked(now); sel != nil {
		return sel
	}

	// 4. Nothing available: mark all maybe-reachable and retry from the top.
	//    If the sample is too small, expand it first.
	m.markAllMaybeReachableLocked()
	m.expandSampleLocked(eligible, now)
	if !m.primaryUpToDate {
		m.updatePrimaryLocked()
	}
	if sel := m.selectPrimaryLocked(now); sel != nil {
		return sel
	}
	if sel := m.selectConfirmedLocked(now); sel != nil {
		return sel
	}
	if sel := m.selectFilteredLocked(now); sel != nil {
		return sel
	}
	return nil
}

// selectPrimaryLocked picks a primary guard that is reachable (maybe/yes),
// applying the retry schedule. Mirrors select_primary_guard_for_circuit.
func (m *Manager) selectPrimaryLocked(now time.Time) *Selection {
	var usable []*Guard
	for _, g := range m.primary {
		m.considerRetryLocked(g, now)
		if g.IsReachable == ReachableNo {
			continue
		}
		g.LastTriedToConnect = now
		g.IsPending = true
		usable = append(usable, g)
	}
	if len(usable) == 0 {
		return nil
	}
	// Pick uniformly among the usable primary guards (smartlist_choose).
	chosen := usable[cryptoRandInt(len(usable))]
	return &Selection{Guard: chosen, UsableOnCompletion: true}
}

// selectConfirmedLocked picks the first non-primary, usable+filtered,
// non-pending confirmed guard. Mirrors select_confirmed_guard_for_circuit.
func (m *Manager) selectConfirmedLocked(now time.Time) *Selection {
	for _, g := range m.confirmed {
		if g.IsPrimary {
			continue
		}
		m.considerRetryLocked(g, now)
		if g.IsUsableFilteredGuard && !g.IsPending {
			g.IsPending = true
			g.LastTriedToConnect = now
			return &Selection{Guard: g, UsableOnCompletion: false}
		}
	}
	return nil
}

// selectFilteredLocked picks the first usable+filtered sampled guard that is
// not confirmed, not primary, and not pending. Mirrors
// select_filtered_guard_for_circuit (first_reachable_filtered_entry_guard).
func (m *Manager) selectFilteredLocked(now time.Time) *Selection {
	for _, g := range m.sampled {
		if g.IsPrimary || g.ConfirmedIdx >= 0 || g.IsPending {
			continue
		}
		m.considerRetryLocked(g, now)
		if g.IsUsableFilteredGuard {
			g.IsPending = true
			g.LastTriedToConnect = now
			return &Selection{Guard: g, UsableOnCompletion: false}
		}
	}
	return nil
}

// updatePrimaryLocked recomputes the primary guard list from the confirmed
// list and filtered sample. Mirrors entry_guards_update_primary
// (entrynodes.c:1955).
func (m *Manager) updatePrimaryLocked() {
	n := m.params.NPrimaryGuards
	newPrimary := make([]*Guard, 0, n)
	seen := make(map[string]bool)

	// First, fill from confirmed guards that pass the filter, in confirmed
	// (sampled-index) order.
	for _, g := range m.confirmed {
		if len(newPrimary) >= n {
			break
		}
		if !g.IsFilteredGuard {
			continue
		}
		g.IsPrimary = true
		newPrimary = append(newPrimary, g)
		seen[g.ID] = true
	}

	// Then keep old primary guards that are still filtered.
	for _, g := range m.primary {
		if len(newPrimary) >= n {
			break
		}
		if seen[g.ID] {
			continue
		}
		if g.IsFilteredGuard {
			g.IsPrimary = true
			newPrimary = append(newPrimary, g)
			seen[g.ID] = true
		}
	}

	// Clear primary flag on guards that dropped out.
	for _, g := range m.primary {
		if !seen[g.ID] {
			g.IsPrimary = false
		}
	}

	// Finally, fill from the filtered sample (sample order), excluding
	// confirmed and already-primary.
	for _, g := range m.sampled {
		if len(newPrimary) >= n {
			break
		}
		if seen[g.ID] || g.ConfirmedIdx >= 0 {
			continue
		}
		if g.IsUsableFilteredGuard {
			g.IsPrimary = true
			newPrimary = append(newPrimary, g)
			seen[g.ID] = true
		}
	}

	m.primary = newPrimary
	m.primaryUpToDate = true
}

// considerRetryLocked flips a failing guard back to maybe-reachable once its
// retry delay has elapsed. Mirrors entry_guard_consider_retry
// (entrynodes.c:2093).
func (m *Manager) considerRetryLocked(g *Guard, now time.Time) {
	if g.IsReachable != ReachableNo {
		return
	}
	delay := retrySchedule(g.FailingSince, now, g.IsPrimary)
	if g.LastTriedToConnect.IsZero() || now.Sub(g.LastTriedToConnect) >= delay {
		g.IsReachable = ReachableMaybe
		if g.IsFilteredGuard {
			g.IsUsableFilteredGuard = true
		}
	}
}

// retrySchedule returns the retry delay for a guard that has been failing
// since failingSince. Mirrors get_retry_schedule (entrynodes.c:2051).
func retrySchedule(failingSince, now time.Time, isPrimary bool) time.Duration {
	const (
		sixHours  = 6 * time.Hour
		fourDays  = 4 * 24 * time.Hour
		sevenDays = 7 * 24 * time.Hour
	)
	tdiff := now.Sub(failingSince)
	if tdiff < 0 {
		tdiff = 0
	}
	type tier struct {
		maximum        time.Duration
		primaryDelay   time.Duration
		nonprimaryDelay time.Duration
	}
	tiers := []tier{
		{sixHours, 10 * time.Minute, time.Hour},
		{fourDays, 90 * time.Minute, 4 * time.Hour},
		{sevenDays, 4 * time.Hour, 18 * time.Hour},
		{time.Duration(1<<63 - 1), 9 * time.Hour, 36 * time.Hour},
	}
	for _, t := range tiers {
		if tdiff <= t.maximum {
			if isPrimary {
				return t.primaryDelay
			}
			return t.nonprimaryDelay
		}
	}
	return 36 * time.Hour
}

// markAllMaybeReachableLocked resets every guard to maybe-reachable so the
// next pick can retry them. Mirrors mark_all_guards_maybe_reachable.
func (m *Manager) markAllMaybeReachableLocked() {
	for _, g := range m.sampled {
		g.IsReachable = ReachableMaybe
		if g.IsFilteredGuard {
			g.IsUsableFilteredGuard = true
		}
	}
}

// NoteConnectionSuccess records that a circuit through the guard succeeded.
// A first success confirms the guard (moves it to the confirmed list); a
// repeat success after a failure clears the failing state. Mirrors
// entry_guard_relayed_succeeded / entry_guard_succeeded.
func (m *Manager) NoteConnectionSuccess(id string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.byID[id]
	if !ok {
		return
	}
	g.IsReachable = ReachableYes
	g.IsPending = false
	g.FailingSince = time.Time{}
	if g.IsFilteredGuard {
		g.IsUsableFilteredGuard = true
	}
	if g.ConfirmedIdx < 0 {
		m.confirmLocked(g, now)
	}
}

// confirmLocked adds a guard to the confirmed list (in sampled-index order).
// Mirrors entry_guard_confirmed (entrynodes.c:1900).
func (m *Manager) confirmLocked(g *Guard, now time.Time) {
	g.ConfirmedOn = now
	g.ConfirmedIdx = len(m.confirmed)
	m.confirmed = append(m.confirmed, g)
	// Keep the confirmed list ordered by sampled index.
	sort.SliceStable(m.confirmed, func(i, j int) bool {
		return m.confirmed[i].SampledIdx < m.confirmed[j].SampledIdx
	})
	for i, c := range m.confirmed {
		c.ConfirmedIdx = i
	}
	m.primaryUpToDate = false
}

// NoteConnectionFailure records that an attempt to use the guard failed. A
// failure flips the guard to ReachableNo and starts (or continues) the
// failing-since clock. Mirrors entry_guard_failed.
func (m *Manager) NoteConnectionFailure(id string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.byID[id]
	if !ok {
		return
	}
	g.IsPending = false
	if g.IsReachable != ReachableNo {
		g.FailingSince = now
	}
	g.IsReachable = ReachableNo
	g.IsUsableFilteredGuard = false
}

// removeFromConfirmedLocked drops a guard from the confirmed list and
// re-indexes.
func (m *Manager) removeFromConfirmedLocked(g *Guard) {
	idx := -1
	for i, c := range m.confirmed {
		if c == g {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	m.confirmed = append(m.confirmed[:idx], m.confirmed[idx+1:]...)
	for i, c := range m.confirmed {
		c.ConfirmedIdx = i
	}
	g.ConfirmedIdx = -1
}

// Primary returns the current primary guards (in primary order). Safe for
// concurrent use.
func (m *Manager) Primary() []*Guard {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.primaryUpToDate {
		m.updatePrimaryLocked()
	}
	out := make([]*Guard, len(m.primary))
	copy(out, m.primary)
	return out
}

// Sampled returns a snapshot of the sampled guards in sample order.
func (m *Manager) Sampled() []*Guard {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Guard, len(m.sampled))
	copy(out, m.sampled)
	return out
}

// Confirmed returns a snapshot of the confirmed guards in confirmed order.
func (m *Manager) Confirmed() []*Guard {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Guard, len(m.confirmed))
	copy(out, m.confirmed)
	return out
}

// Lookup returns the sampled guard with the given ID, or nil.
func (m *Manager) Lookup(id string) *Guard {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byID[id]
}

// cryptoRandInt returns a uniform random int in [0, n) using rejection
// sampling to avoid modulo bias (mirrors crypto_rand_int).
func cryptoRandInt(n int) int {
	if n <= 0 {
		return 0
	}
	limit := ^uint64(0)
	buckets := limit / uint64(n)
	if buckets == 0 {
		buckets = 1
	}
	threshold := buckets * uint64(n)
	for {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return int(b[0]) % n
		}
		v := binary.BigEndian.Uint64(b[:])
		if v < threshold {
			return int(v % uint64(n))
		}
	}
}

// cryptoRandUint64 returns a uniform random uint64 in [0, max) using
// rejection sampling (mirrors crypto_rand_uint64).
func cryptoRandUint64(max uint64) uint64 {
	if max == 0 {
		return 0
	}
	buckets := ^uint64(0) / max
	if buckets == 0 {
		buckets = 1
	}
	threshold := buckets * max
	for {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return binary.BigEndian.Uint64(b[:]) % max
		}
		v := binary.BigEndian.Uint64(b[:])
		if v < threshold {
			return v % max
		}
	}
}

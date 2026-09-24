package link

import (
	"encoding/binary"
	"testing"
	"time"
)

// TestHandleNetinfoTimestamp verifies that handleNetinfo parses the peer's
// NETINFO timestamp (first 4 bytes, big-endian seconds since epoch) and
// records the clock skew, mirroring channel_tls_process_netinfo_cell
// (channeltls.c:1856). A skew under one hour is recorded silently; a skew
// over one hour is logged as a warning.
func TestHandleNetinfoTimestamp(t *testing.T) {
	// A NETINFO payload with a timestamp ~10s in the past (small skew).
	now := time.Now()
	ts := uint32(now.Add(-10 * time.Second).Unix())
	payload := make([]byte, 8) // timestamp + a minimal other-addr is enough
	binary.BigEndian.PutUint32(payload[0:4], ts)

	l := &Link{}
	l.handleNetinfo(payload)

	if l.peerTimestamp.Unix() != int64(ts) {
		t.Errorf("peerTimestamp = %v, want %d", l.peerTimestamp, ts)
	}
	// Skew should be ~10s (allow slack for test timing).
	if absDuration(l.clockSkew) > 30*time.Second {
		t.Errorf("clockSkew = %v, want ~10s", l.clockSkew)
	}
}

// TestHandleNetinfoLargeSkew verifies a skew over one hour is recorded (and
// would be logged). We only assert the recorded skew magnitude here; the
// warning is a log side-effect.
func TestHandleNetinfoLargeSkew(t *testing.T) {
	now := time.Now()
	// Peer claims to be 2 hours behind.
	ts := uint32(now.Add(-2 * time.Hour).Unix())
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], ts)

	l := &Link{}
	l.handleNetinfo(payload)

	if absDuration(l.clockSkew) <= netinfoNoticeSkew*time.Second {
		t.Errorf("clockSkew = %v, want magnitude > %ds", l.clockSkew, netinfoNoticeSkew)
	}
}

// TestHandleNetinfoShortPayload verifies a too-short payload is ignored
// gracefully (no skew recorded, no panic).
func TestHandleNetinfoShortPayload(t *testing.T) {
	l := &Link{}
	l.handleNetinfo([]byte{0x01, 0x02}) // < 4 bytes
	if !l.peerTimestamp.IsZero() {
		t.Errorf("peerTimestamp = %v, want zero on short payload", l.peerTimestamp)
	}
}

// TestHandleNetinfoFutureTimestamp verifies a peer clock ahead of ours
// produces a negative skew (our clock is "behind").
func TestHandleNetinfoFutureTimestamp(t *testing.T) {
	now := time.Now()
	ts := uint32(now.Add(2 * time.Hour).Unix())
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], ts)

	l := &Link{}
	l.handleNetinfo(payload)

	if l.clockSkew >= 0 {
		t.Errorf("clockSkew = %v, want negative (peer ahead)", l.clockSkew)
	}
	if absDuration(l.clockSkew) <= netinfoNoticeSkew*time.Second {
		t.Errorf("|clockSkew| = %v, want > %ds", absDuration(l.clockSkew), netinfoNoticeSkew)
	}
}

// TestAbsDuration is a trivial sanity check for the helper.
func TestAbsDuration(t *testing.T) {
	cases := []time.Duration{5 * time.Second, -5 * time.Second, 0}
	for _, d := range cases {
		got := absDuration(d)
		want := d
		if want < 0 {
			want = -want
		}
		if got != want {
			t.Errorf("absDuration(%v) = %v, want %v", d, got, want)
		}
	}
}

package torcell

import (
	"bytes"
	"testing"
)

// TestCodecPushBackReassemblesCell verifies the pushback seam Link.readLoop relies
// on to confine the rolling idle deadline to a cell boundary. readLoop reads the
// first byte of a cell under the idle deadline, pushes it back, and ReadAny must
// re-read it as the start of the cell and reassemble the WHOLE cell intact. If
// pushback lost or duplicated that byte, the next read would start mid-cell and
// permanently desync framing — an alive-but-garbage link keepAlive never redials.
// Both circuit-ID widths are exercised (the header parse differs).
func TestCodecPushBackReassemblesCell(t *testing.T) {
	for _, width := range []int{2, 4} {
		want := &Cell{CircID: 0x12345678, Command: CellRelay}
		for i := range want.Payload {
			want.Payload[i] = byte(i)
		}
		var wire bytes.Buffer
		if err := NewCodec(&wire, width).WriteCell(want); err != nil {
			t.Fatalf("width %d WriteCell: %v", width, err)
		}
		// Read the first byte off the wire, as readLoop does under the idle deadline.
		first, err := wire.ReadByte()
		if err != nil {
			t.Fatalf("width %d ReadByte: %v", width, err)
		}
		dec := NewCodec(&wire, width)
		dec.PushBack([]byte{first})
		got, err := dec.ReadAny()
		if err != nil {
			t.Fatalf("width %d ReadAny after pushback: %v", width, err)
		}
		cell, ok := got.(*Cell)
		if !ok {
			t.Fatalf("width %d ReadAny returned %T, want *Cell", width, got)
		}
		if cell.Command != want.Command {
			t.Fatalf("width %d command = %d, want %d (framing desync)", width, cell.Command, want.Command)
		}
		if cell.Payload != want.Payload {
			t.Fatalf("width %d payload mismatch after pushback (framing desync)", width)
		}
		wantID := want.CircID
		if width == 2 {
			wantID = uint32(uint16(want.CircID))
		}
		if cell.CircID != wantID {
			t.Fatalf("width %d circID = %#x, want %#x", width, cell.CircID, wantID)
		}
		if wire.Len() != 0 {
			t.Fatalf("width %d: %d wire bytes left after a full cell (over/under-read)", width, wire.Len())
		}
	}
}

// TestCodecPushBackMultipleCells verifies pushback does not corrupt the stream when
// several cells are read back-to-back, each via a first-byte read + pushback (the
// steady-state readLoop path). Every cell must reassemble intact and in order.
func TestCodecPushBackMultipleCells(t *testing.T) {
	var wire bytes.Buffer
	enc := NewCodec(&wire, 4)
	const n = 8
	for i := 0; i < n; i++ {
		c := &Cell{CircID: uint32(0x80000000 + i), Command: CellRelay}
		c.Payload[0] = byte(i)
		if err := enc.WriteCell(c); err != nil {
			t.Fatalf("WriteCell %d: %v", i, err)
		}
	}
	dec := NewCodec(&wire, 4)
	for i := 0; i < n; i++ {
		first, err := wire.ReadByte()
		if err != nil {
			t.Fatalf("cell %d ReadByte: %v", i, err)
		}
		dec.PushBack([]byte{first})
		got, err := dec.ReadAny()
		if err != nil {
			t.Fatalf("cell %d ReadAny: %v", i, err)
		}
		cell := got.(*Cell)
		if cell.CircID != uint32(0x80000000+i) || cell.Payload[0] != byte(i) {
			t.Fatalf("cell %d desync: circID=%#x payload0=%d", i, cell.CircID, cell.Payload[0])
		}
	}
	if wire.Len() != 0 {
		t.Fatalf("%d bytes left after %d cells", wire.Len(), n)
	}
}

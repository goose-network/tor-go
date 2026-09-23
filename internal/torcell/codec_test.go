package torcell

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// rwBuf is a simple in-memory io.ReadWriter for testing the codec.
type rwBuf struct {
	buf bytes.Buffer
}

func (b *rwBuf) Read(p []byte) (int, error)  { return b.buf.Read(p) }
func (b *rwBuf) Write(p []byte) (int, error) { return b.buf.Write(p) }

func TestCellRoundTrip4ByteCircID(t *testing.T) {
	rw := &rwBuf{}
	c := NewCodec(rw, 4)

	in := &Cell{CircID: 0x12345678, Command: CellCreate2}
	in.Payload[0] = 0xAA
	in.Payload[508] = 0xBB
	if err := c.WriteCell(in); err != nil {
		t.Fatalf("WriteCell: %v", err)
	}
	// On the wire: 4-byte circID + 1-byte cmd + 509-byte payload = 514.
	if rw.buf.Len() != TotalSize4 {
		t.Fatalf("wire size = %d, want %d", rw.buf.Len(), TotalSize4)
	}
	out, err := c.ReadCell()
	if err != nil {
		t.Fatalf("ReadCell: %v", err)
	}
	if out.CircID != in.CircID {
		t.Fatalf("circID = %x, want %x", out.CircID, in.CircID)
	}
	if out.Command != in.Command {
		t.Fatalf("command = %d, want %d", out.Command, in.Command)
	}
	if out.Payload[0] != 0xAA || out.Payload[508] != 0xBB {
		t.Fatalf("payload mismatch: %x...%x", out.Payload[0], out.Payload[508])
	}
}

func TestCellRoundTrip2ByteCircID(t *testing.T) {
	rw := &rwBuf{}
	c := NewCodec(rw, 2)

	in := &Cell{CircID: 0x1234, Command: CellRelay}
	if err := c.WriteCell(in); err != nil {
		t.Fatalf("WriteCell: %v", err)
	}
	if rw.buf.Len() != TotalSize3 {
		t.Fatalf("wire size = %d, want %d", rw.buf.Len(), TotalSize3)
	}
	out, err := c.ReadCell()
	if err != nil {
		t.Fatalf("ReadCell: %v", err)
	}
	if out.CircID != in.CircID || out.Command != in.Command {
		t.Fatalf("got circID=%x cmd=%d, want %x %d", out.CircID, out.Command, in.CircID, in.Command)
	}
}

func TestVarCellRoundTrip(t *testing.T) {
	rw := &rwBuf{}
	c := NewCodec(rw, 4)

	in := &VarCell{Command: CellVersions, CircID: 0, Payload: make([]byte, 6)}
	binary.BigEndian.PutUint16(in.Payload[0:2], 4)
	binary.BigEndian.PutUint16(in.Payload[2:4], 5)
	binary.BigEndian.PutUint16(in.Payload[4:6], 6)
	if err := c.WriteVarCell(in); err != nil {
		t.Fatalf("WriteVarCell: %v", err)
	}
	out, err := c.ReadVarCell()
	if err != nil {
		t.Fatalf("ReadVarCell: %v", err)
	}
	if out.Command != in.Command || !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("varcell mismatch: cmd=%d payload=%x", out.Command, out.Payload)
	}
}

func TestReadAnyDispatches(t *testing.T) {
	rw := &rwBuf{}
	c := NewCodec(rw, 4)

	// Write a fixed cell then a var cell.
	fixed := &Cell{CircID: 1, Command: CellPadding}
	c.WriteCell(fixed)
	vc := &VarCell{Command: CellVersions, Payload: []byte{0x00, 0x05}}
	c.WriteVarCell(vc)

	m1, err := c.ReadAny()
	if err != nil {
		t.Fatalf("ReadAny 1: %v", err)
	}
	if fc, ok := m1.(*Cell); !ok || fc.Command != CellPadding {
		t.Fatalf("expected fixed CellPadding, got %T %+v", m1, m1)
	}
	m2, err := c.ReadAny()
	if err != nil {
		t.Fatalf("ReadAny 2: %v", err)
	}
	if v, ok := m2.(*VarCell); !ok || v.Command != CellVersions {
		t.Fatalf("expected VarCell Versions, got %T %+v", m2, m2)
	}
}

func TestRelayHeaderPackUnpack(t *testing.T) {
	h := RelayHeader{Command: RelayData, Recognized: 0, StreamID: 42, Length: 100}
	h.Integrity = [4]byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf := make([]byte, RelayHeaderSize)
	PackRelayHeader(buf, &h)

	var h2 RelayHeader
	UnpackRelayHeader(&h2, buf)
	if h2 != h {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", h2, h)
	}
}

func TestBuildParseRelayCell(t *testing.T) {
	payload := []byte("hello world")
	cellPayload := BuildRelayCell(RelayData, 99, payload)
	rc := ParseRelayCell(cellPayload[:])
	if rc.Header.Command != RelayData {
		t.Fatalf("command = %d, want %d", rc.Header.Command, RelayData)
	}
	if rc.Header.StreamID != 99 {
		t.Fatalf("streamID = %d, want 99", rc.Header.StreamID)
	}
	if rc.Header.Length != uint16(len(payload)) {
		t.Fatalf("length = %d, want %d", rc.Header.Length, len(payload))
	}
	if string(rc.Payload) != "hello world" {
		t.Fatalf("payload = %q", string(rc.Payload))
	}
}

func TestIsVariable(t *testing.T) {
	variable := []uint8{CellVersions, CellVPadding, CellCerts, CellAuthChallenge, CellAuthenticate, CellAuthorize}
	for _, cmd := range variable {
		if !IsVariable(cmd) {
			t.Fatalf("cmd %d should be variable", cmd)
		}
	}
	fixed := []uint8{CellPadding, CellCreate, CellRelay, CellCreate2, CellNetinfo}
	for _, cmd := range fixed {
		if IsVariable(cmd) {
			t.Fatalf("cmd %d should not be variable", cmd)
		}
	}
}

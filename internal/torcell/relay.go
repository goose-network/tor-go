package torcell

import (
	"encoding/binary"
)

// RelayHeader is the parsed header of a relay cell payload (the v0 format).
// Wire layout (11 bytes):
//
//	[0]    command    (1 byte)
//	[1:3]  recognized (2 bytes, big-endian; 0 means "for me")
//	[3:5]  streamID   (2 bytes, big-endian)
//	[5:9]  integrity  (4 bytes; v0 relay digest)
//	[9:11] length     (2 bytes, big-endian; payload length after header)
type RelayHeader struct {
	Command    uint8
	Recognized uint16
	StreamID   uint16
	Integrity  [4]byte
	Length     uint16
}

// PackRelayHeader writes h into the first RelayHeaderSize bytes of dst.
func PackRelayHeader(dst []byte, h *RelayHeader) {
	dst[0] = h.Command
	binary.BigEndian.PutUint16(dst[1:3], h.Recognized)
	binary.BigEndian.PutUint16(dst[3:5], h.StreamID)
	copy(dst[5:9], h.Integrity[:])
	binary.BigEndian.PutUint16(dst[9:11], h.Length)
}

// UnpackRelayHeader parses the first RelayHeaderSize bytes of src into h.
func UnpackRelayHeader(h *RelayHeader, src []byte) {
	h.Command = src[0]
	h.Recognized = binary.BigEndian.Uint16(src[1:3])
	h.StreamID = binary.BigEndian.Uint16(src[3:5])
	copy(h.Integrity[:], src[5:9])
	h.Length = binary.BigEndian.Uint16(src[9:11])
}

// RelayCell is a parsed relay cell: the relay header plus the relay payload
// (the bytes after the 11-byte header, up to h.Length).
type RelayCell struct {
	Header  RelayHeader
	Payload []byte
}

// ParseRelayCell parses the payload of a CellRelay/CellRelayEarly cell into a
// RelayCell. The returned RelayCell.Payload is a slice into the cell payload
// buffer, truncated to Header.Length.
func ParseRelayCell(cellPayload []byte) *RelayCell {
	rc := &RelayCell{}
	UnpackRelayHeader(&rc.Header, cellPayload)
	if int(rc.Header.Length) > len(cellPayload)-RelayHeaderSize {
		// Clamp to what's available; callers should treat this as malformed.
		rc.Payload = cellPayload[RelayHeaderSize:]
	} else {
		rc.Payload = cellPayload[RelayHeaderSize : RelayHeaderSize+int(rc.Header.Length)]
	}
	return rc
}

// BuildRelayCell serializes a relay command, stream ID and payload into a
// 509-byte cell payload, returning the full payload ready to be placed in a
// Cell.Payload. The integrity/recognized fields are left zero; the caller
// (the relay crypto layer) fills the digest and encrypts.
func BuildRelayCell(command uint8, streamID uint16, payload []byte) [PayloadSize]byte {
	var out [PayloadSize]byte
	h := RelayHeader{
		Command:    command,
		Recognized: 0,
		StreamID:   streamID,
		Length:     uint16(len(payload)),
	}
	PackRelayHeader(out[:], &h)
	n := len(payload)
	if n > RelayPayloadSizeMax {
		n = RelayPayloadSizeMax
	}
	copy(out[RelayHeaderSize:RelayHeaderSize+n], payload[:n])
	return out
}

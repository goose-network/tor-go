// Package torcell defines the on-the-wire cell format used by the Tor
// protocol. All inter-relay communication on a channel is carried in
// fixed-size cells (514 bytes on the wire: 3-byte header + 509-byte payload
// for the variable-length circuit-ID flavour, or 4-byte header + 509-byte
// payload for the fixed 4-byte circuit-ID flavour used on modern links).
//
// The layout and constants here mirror src/core/or/or.h and
// src/core/or/cell_st.h in the C reference implementation.
package torcell

// Cell command types. See src/core/or/or.h.
const (
	CellPadding       = 0
	CellCreate        = 1
	CellCreated       = 2
	CellRelay         = 3
	CellDestroy       = 4
	CellCreateFast    = 5
	CellCreatedFast   = 6
	CellVersions      = 7
	CellNetinfo       = 8
	CellRelayEarly    = 9
	CellCreate2       = 10
	CellCreated2      = 11
	CellPaddingNegotiate = 12

	// Link-protocol handshake cells (>=128).
	CellVPadding       = 128
	CellCerts          = 129
	CellAuthChallenge  = 130
	CellAuthenticate   = 131
	CellAuthorize      = 132
)

// Relay commands carried inside the payload of a CellRelay / CellRelayEarly
// cell. See src/core/or/or.h (RELAY_COMMAND_*).
const (
	RelayBegin            = 1
	RelayData             = 2
	RelayEnd              = 3
	RelayConnected        = 4
	RelaySendme           = 5
	RelayExtend           = 6
	RelayExtended         = 7
	RelayTruncate         = 8
	RelayTruncated        = 9
	RelayDrop             = 10
	RelayResolve          = 11
	RelayResolved         = 12
	RelayBeginDir         = 13
	RelayExtend2          = 14
	RelayExtended2        = 15
	RelayConfluxLink      = 19
	RelayConfluxLinked    = 20
	RelayConfluxLinkedAck = 21
	RelayConfluxSwitch    = 22
	RelayEstablishIntro   = 32
	RelayEstablishRendezvous = 33
	RelayIntroduce1       = 34
	RelayIntroduce2       = 35
	RelayRendezvous1      = 36
	RelayRendezvous2      = 37
	RelayIntroEstablished = 38
	RelayRendezvousEstablished = 39
	RelayIntroduceAck     = 40
	RelayPaddingNegotiate = 41
	RelayPaddingNegotiated = 42
	RelayXoff             = 43
	RelayXon              = 44
)

// Cell sizes. See src/core/or/or.h.
const (
	// PayloadSize is the number of bytes in a fixed cell payload.
	PayloadSize = 509

	// CircIDWidth4 is the circuit-ID width in bytes for link protocol >= 4.
	CircIDWidth4 = 4
	// CircIDWidth3 is the circuit-ID width in bytes for link protocol < 4.
	CircIDWidth3 = 2

	// TotalSize4 is the full on-wire size of a fixed cell with a 4-byte
	// circuit ID: 4 (circID) + 1 (command) + 509 (payload) = 514.
	TotalSize4 = CircIDWidth4 + 1 + PayloadSize

	// TotalSize3 is the full on-wire size of a fixed cell with a 2-byte
	// circuit ID: 2 (circID) + 1 (command) + 509 (payload) = 512.
	TotalSize3 = CircIDWidth3 + 1 + PayloadSize
)

// Relay header layout (the v0 format used inside a relay cell payload).
// See relay_header_pack/unpack in src/core/or/relay.c.
const (
	// RelayHeaderSize is the size of the relay-cell header that precedes
	// the relay payload.
	RelayHeaderSize = 11

	// RelayPayloadSizeMax is the largest relay payload that fits in one
	// cell.
	RelayPayloadSizeMax = PayloadSize - RelayHeaderSize

	// RelayDigestOffset is the offset of the 4-byte integrity field within
	// the relay header.
	RelayDigestOffset = 5

	// RelayDigestLenV0 is the length of the v0 relay digest stored in the
	// integrity field.
	RelayDigestLenV0 = 4
)

// Destroy reason codes (a small, commonly-used subset). See
// src/core/or/destroy_reasons.h in the C tree.
const (
	DestroyReasonNone        = 0
	DestroyReasonProtocol    = 1
	DestroyReasonInternal    = 2
	DestroyReasonRequested   = 3
	DestroyReasonHibernating = 4
	DestroyReasonDone        = 5
	DestroyReasonTimeout     = 10
	DestroyReasonBadProtocol = 12
)

// Cell is a parsed fixed-size Tor cell.
type Cell struct {
	// CircID is the circuit identifier carried by the cell.
	CircID uint32
	// Command is the cell command type (one of the Cell* constants).
	Command uint8
	// Payload is the 509-byte cell body.
	Payload [PayloadSize]byte
}

// IsVariable reports whether a command is carried in a variable-length cell.
// Variable-length cells use a 5-byte header (command, 2-byte length) and are
// only used during the link handshake (VERSIONS, CERTS, AUTH_CHALLENGE,
// AUTHENTICATE, VPADDING, AUTHORIZE).
func IsVariable(cmd uint8) bool {
	switch cmd {
	case CellVersions, CellVPadding, CellCerts, CellAuthChallenge,
		CellAuthenticate, CellAuthorize:
		return true
	}
	return false
}

// VarCell is a parsed variable-length cell.
type VarCell struct {
	Command  uint8
	CircID   uint32
	Payload  []byte
}

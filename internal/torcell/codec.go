package torcell

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrShortCell is returned when fewer than a full cell could be read.
var ErrShortCell = errors.New("torcell: short cell")

// Codec reads and writes Tor cells on an underlying io.ReadWriter. It
// implements the framing layer of the Tor link protocol.
//
// A Codec is configured with a circuit-ID width (2 or 4 bytes) which is
// negotiated during the VERSIONS handshake: link protocol versions < 4 use
// 2-byte circuit IDs, versions >= 4 use 4-byte circuit IDs.
type Codec struct {
	rw     io.ReadWriter
	circID int // 2 or 4
}

// NewCodec returns a Codec over rw using the given circuit-ID width (which
// must be 2 or 4).
func NewCodec(rw io.ReadWriter, circIDWidth int) *Codec {
	if circIDWidth != 2 && circIDWidth != 4 {
		circIDWidth = 4
	}
	return &Codec{rw: rw, circID: circIDWidth}
}

// CircIDWidth returns the circuit-ID width in bytes (2 or 4).
func (c *Codec) CircIDWidth() int { return c.circID }

// SetCircIDWidth changes the circuit-ID width. Called after the VERSIONS
// handshake completes and the link protocol version is known.
func (c *Codec) SetCircIDWidth(w int) {
	if w == 2 || w == 4 {
		c.circID = w
	}
}

// ReadCell reads a single fixed-size cell. It blocks until a full cell is
// available or an error occurs. The returned cell.Command is never a
// variable-length command; variable-length cells are read with ReadVarCell.
func (c *Codec) ReadCell() (*Cell, error) {
	total := c.circID + 1 + PayloadSize
	buf := make([]byte, total)
	if _, err := io.ReadFull(c.rw, buf); err != nil {
		return nil, fmt.Errorf("torcell: read cell: %w", err)
	}
	cell := &Cell{}
	if c.circID == 4 {
		cell.CircID = binary.BigEndian.Uint32(buf[0:4])
	} else {
		cell.CircID = uint32(binary.BigEndian.Uint16(buf[0:2]))
	}
	cell.Command = buf[c.circID]
	copy(cell.Payload[:], buf[c.circID+1:])
	return cell, nil
}

// ReadVarCell reads a single variable-length cell. Variable-length cells are
// only sent during the link handshake and use a 5-byte header regardless of
// the circuit-ID width: [circID (2 or 4)][cmd (1)][length (2)][payload].
func (c *Codec) ReadVarCell() (*VarCell, error) {
	hdr := make([]byte, c.circID+3)
	if _, err := io.ReadFull(c.rw, hdr); err != nil {
		return nil, fmt.Errorf("torcell: read varcell header: %w", err)
	}
	var circID uint32
	if c.circID == 4 {
		circID = binary.BigEndian.Uint32(hdr[0:4])
	} else {
		circID = uint32(binary.BigEndian.Uint16(hdr[0:2]))
	}
	cmd := hdr[c.circID]
	length := int(binary.BigEndian.Uint16(hdr[c.circID+1:]))
	if length > 0xFFFF {
		return nil, fmt.Errorf("torcell: varcell length %d too large", length)
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(c.rw, payload); err != nil {
			return nil, fmt.Errorf("torcell: read varcell payload: %w", err)
		}
	}
	return &VarCell{Command: cmd, CircID: circID, Payload: payload}, nil
}

// ReadAny reads either a fixed or variable-length cell, dispatching on the
// command byte. This is the main receive loop entry point.
func (c *Codec) ReadAny() (interface{}, error) {
	// Peek the command byte to decide. We read the header bytes we know we
	// need in all cases, then branch.
	hdr := make([]byte, c.circID+1)
	if _, err := io.ReadFull(c.rw, hdr); err != nil {
		return nil, fmt.Errorf("torcell: read header: %w", err)
	}
	var circID uint32
	if c.circID == 4 {
		circID = binary.BigEndian.Uint32(hdr[0:4])
	} else {
		circID = uint32(binary.BigEndian.Uint16(hdr[0:2]))
	}
	cmd := hdr[c.circID]

	if IsVariable(cmd) {
		// Read 2-byte length then payload.
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(c.rw, lenBuf); err != nil {
			return nil, fmt.Errorf("torcell: read varcell length: %w", err)
		}
		length := int(binary.BigEndian.Uint16(lenBuf))
		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(c.rw, payload); err != nil {
				return nil, fmt.Errorf("torcell: read varcell payload: %w", err)
			}
		}
		return &VarCell{Command: cmd, CircID: circID, Payload: payload}, nil
	}

	// Fixed cell: read the remaining payload.
	cell := &Cell{CircID: circID, Command: cmd}
	if _, err := io.ReadFull(c.rw, cell.Payload[:]); err != nil {
		return nil, fmt.Errorf("torcell: read cell payload: %w", err)
	}
	return cell, nil
}

// WriteCell writes a single fixed-size cell.
func (c *Codec) WriteCell(cell *Cell) error {
	buf := make([]byte, c.circID+1+PayloadSize)
	if c.circID == 4 {
		binary.BigEndian.PutUint32(buf[0:4], cell.CircID)
	} else {
		binary.BigEndian.PutUint16(buf[0:2], uint16(cell.CircID))
	}
	buf[c.circID] = cell.Command
	copy(buf[c.circID+1:], cell.Payload[:])
	if _, err := c.rw.Write(buf); err != nil {
		return fmt.Errorf("torcell: write cell: %w", err)
	}
	return nil
}

// WriteVarCell writes a single variable-length cell.
func (c *Codec) WriteVarCell(vc *VarCell) error {
	if len(vc.Payload) > 0xFFFF {
		return fmt.Errorf("torcell: varcell payload too large (%d)", len(vc.Payload))
	}
	buf := make([]byte, c.circID+3+len(vc.Payload))
	if c.circID == 4 {
		binary.BigEndian.PutUint32(buf[0:4], vc.CircID)
	} else {
		binary.BigEndian.PutUint16(buf[0:2], uint16(vc.CircID))
	}
	buf[c.circID] = vc.Command
	binary.BigEndian.PutUint16(buf[c.circID+1:], uint16(len(vc.Payload)))
	copy(buf[c.circID+3:], vc.Payload)
	if _, err := c.rw.Write(buf); err != nil {
		return fmt.Errorf("torcell: write varcell: %w", err)
	}
	return nil
}

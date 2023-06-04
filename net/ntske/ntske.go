/*
Copyright 2018--2019 Michael Cardell Widerkrantz, Martin Samuelsson,
Daniel Lublin

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted, provided that the
above copyright notice and this permission notice appear in all
copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
*/

//lint:file-ignore * maintain this file with minimal changes

package ntske

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

// Data is negotiated data from the Key Exchange
type Data struct {
	C2sKey []byte
	S2cKey []byte
	Server string
	Port   uint16
	Cookie [][]byte
	Algo   uint16
}

// NTS-KE record types
const (
	RecEom       uint16 = 0
	RecNextproto uint16 = 1
	RecError     uint16 = 2
	RecWarning   uint16 = 3
	RecAead      uint16 = 4
	RecCookie    uint16 = 5
	RecServer    uint16 = 6
	RecPort      uint16 = 7
)

const (
	AES_SIV_CMAC_256   = 0x0f
	DEFAULT_NTSKE_PORT = 4460
	DEFAULT_NTP_PORT   = 123
)

const (
	UnrecognizedCriticalErrorCode = 0
	BadRequestErrorCode           = 1
	InternalServerErrorCode       = 2
)

const alpn = "ntske/1"

var (
	errServerNoNTSKE            = errors.New("server not speaking ntske/1")
	errReadInternalServer       = errors.New("ntske received internal server error message")
	errReadBadRequest           = errors.New("ntske received bad request error message")
	errReadUnrecognisedCritical = errors.New("ntske received unrecognised critical error message")
	errReadUnknown              = errors.New("ntske received unknown error message")
)

// RecordHdr is the header on all records send in NTS-KE. The first
// bit of the Type is the critical bit.
type RecordHdr struct {
	Type    uint16 // First bit is Critical bit
	BodyLen uint16
}

func (h RecordHdr) pack(buf *bytes.Buffer) error {
	err := binary.Write(buf, binary.BigEndian, h)
	return err
}

func (h RecordHdr) Header() RecordHdr { return h }

func packsimple(t uint16, c bool, v interface{}, buf *bytes.Buffer) error {
	value := new(bytes.Buffer)
	err := binary.Write(value, binary.BigEndian, v)
	if err != nil {
		return err
	}

	err = packheader(t, c, buf, value.Len())
	if err != nil {
		return err
	}

	_, err = buf.ReadFrom(value)
	if err != nil {
		return err
	}

	return nil
}

func packheader(t uint16, c bool, buf *bytes.Buffer, bodylen int) error {
	var hdr RecordHdr

	hdr.Type = t
	if c {
		hdr.Type = setBit(hdr.Type, 15)
	}

	hdr.BodyLen = uint16(bodylen)

	err := hdr.pack(buf)
	if err != nil {
		return err
	}

	return nil

}

// Record is the interface all record types must implement.
// pack() packs the record into wire format.
type Record interface {
	pack(*bytes.Buffer) error
}

// ExchangeMsg is a representation of a series of records to be sent
// to the peer.
type ExchangeMsg struct {
	Record []Record
}

// Pack allocates a buffer and packs all records into wire format in
// that buffer.
func (m ExchangeMsg) Pack() (buf *bytes.Buffer, err error) {
	buf = new(bytes.Buffer)

	for _, r := range m.Record {
		err = r.pack(buf)
		if err != nil {
			return nil, err

		}
	}

	return buf, nil
}

// AddRecord adda new record type to a Key Exchange message.
func (m *ExchangeMsg) AddRecord(rec Record) {
	m.Record = append(m.Record, rec)
}

const NTPv4 uint16 = 0

// NextProto record. Tells the other side we want to speak NTP,
// probably. Set to 0.
type NextProto struct {
	RecordHdr
	NextProto uint16
}

func (n NextProto) pack(buf *bytes.Buffer) error {
	value := new(bytes.Buffer)
	err := binary.Write(value, binary.BigEndian, n.NextProto)
	if err != nil {
		return err
	}

	n.RecordHdr.Type = RecNextproto
	n.RecordHdr.Type = setBit(n.RecordHdr.Type, 15)
	n.RecordHdr.BodyLen = uint16(value.Len())

	err = n.RecordHdr.pack(buf)
	if err != nil {
		return err
	}

	_, err = buf.ReadFrom(value)
	if err != nil {
		return err
	}

	return nil
}

// End is the End of Message record.
type End struct {
	RecordHdr
}

func (e End) pack(buf *bytes.Buffer) error {
	return packheader(RecEom, true, buf, 0)
}

// Server is the NTP Server record, telling the client to use a
// certain server for the next protocol query. Critical bit is
// optional. Set Critical to true if you want it set.
type Server struct {
	RecordHdr
	Addr     []byte
	Critical bool
}

func (s Server) pack(buf *bytes.Buffer) error {
	return packsimple(RecServer, s.Critical, s.Addr, buf)
}

// Port is the NTP Port record, telling the client to use this port
// for the next protocol query. Critical bit is optional. Set Critical
// to true if you want it set.
type Port struct {
	RecordHdr
	Port     uint16
	Critical bool
}

func (p Port) pack(buf *bytes.Buffer) error {
	return packsimple(RecPort, p.Critical, p.Port, buf)
}

// Cookie is an NTS cookie to be used when querying time over NTS.
type Cookie struct {
	RecordHdr
	Cookie []byte
}

func (c Cookie) pack(buf *bytes.Buffer) error {
	return packsimple(RecCookie, false, c.Cookie, buf)
}

// Warning is the record type to send warnings to the other end. Put
// warning code in Code.
type Warning struct {
	RecordHdr
	Code uint16
}

func (w Warning) pack(buf *bytes.Buffer) error {
	return packsimple(RecWarning, true, w.Code, buf)
}

// Error is the record type to send errors to the other end. Put
// error code in Code.
type Error struct {
	RecordHdr
	Code uint16
}

func (e Error) pack(buf *bytes.Buffer) error {
	return packsimple(RecError, true, e.Code, buf)

}

// Algorithm is the record type for a list of AEAD algorithm we can use.
type Algorithm struct {
	RecordHdr
	Algo []uint16
}

func (a Algorithm) pack(buf *bytes.Buffer) error {
	return packsimple(RecAead, true, a.Algo, buf)
}

// ExportKeys exports two extra sessions keys from the already
// established NTS-KE connection for use with NTS.
func ExportKeys(cs tls.ConnectionState, data *Data) error {
	label := "EXPORTER-network-time-security"
	s2cContext := []byte{0x00, 0x00, 0x00, 0x0f, 0x01}
	c2sContext := []byte{0x00, 0x00, 0x00, 0x0f, 0x00}
	len := 32

	var err error
	data.S2cKey, err = cs.ExportKeyingMaterial(label, s2cContext, len)
	if err != nil {
		return err
	}

	data.C2sKey, err = cs.ExportKeyingMaterial(label, c2sContext, len)
	if err != nil {
		return err
	}

	return nil
}

func Read(log *zap.Logger, reader *bufio.Reader, data *Data) error {
	var msg RecordHdr
	var critical bool

	for {
		err := binary.Read(reader, binary.BigEndian, &msg)
		if err != nil {
			return err
		}

		// C (Critical Bit): Determines the disposition of
		// unrecognized Record Types. Implementations which
		// receive a record with an unrecognized Record Type
		// MUST ignore the record if the Critical Bit is 0 and
		// MUST treat it as an error if the Critical Bit is 1.
		if hasBit(msg.Type, 15) {
			critical = true
		} else {
			critical = false
		}

		// Get rid of Critical bit.
		msg.Type &^= (1 << 15)

		switch msg.Type {
		case RecEom:
			return nil

		case RecNextproto:
			var nextProto uint16
			err := binary.Read(reader, binary.BigEndian, &nextProto)
			if err != nil {
				return err
			}

		case RecAead:
			var aead uint16
			err := binary.Read(reader, binary.BigEndian, &aead)
			if err != nil {
				return err
			}
			data.Algo = aead

		case RecCookie:
			cookie := make([]byte, msg.BodyLen)
			_, err := reader.Read(cookie)
			if err != nil {
				return err
			}
			data.Cookie = append(data.Cookie, cookie)

		case RecServer:
			address := make([]byte, msg.BodyLen)

			err := binary.Read(reader, binary.BigEndian, &address)
			if err != nil {
				return err
			}
			data.Server = string(address)

		case RecPort:
			err := binary.Read(reader, binary.BigEndian, &data.Port)
			if err != nil {
				return err
			}

		case RecError:
			var code uint16
			err := binary.Read(reader, binary.BigEndian, &code)
			if err != nil {
				return err
			}
			if code == 0 {
				return errReadUnrecognisedCritical
			} else if code == 1 {
				return errReadBadRequest
			} else if code == 2 {
				return errReadInternalServer
			}
			return errReadUnknown

		default:
			if critical {
				return fmt.Errorf("unknown record type %v with critical bit set", msg.Type)
			}

			// Swallow unknown record.
			unknownMsg := make([]byte, msg.BodyLen)
			err := binary.Read(reader, binary.BigEndian, &unknownMsg)
			if err != nil {
				return err
			}
		}
	}
}

func setBit(n uint16, pos uint) uint16 {
	n |= (1 << pos)
	return n
}

func hasBit(n uint16, pos uint) bool {
	val := n & (1 << pos)
	return (val > 0)
}

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
	"net"
	"strconv"
	"strings"
	"time"
)

// KeyExchange is Network Time Security Key Exchange connection
type KeyExchange struct {
	hostport string
	Conn     *tls.Conn
	reader   *bufio.Reader
	Meta     Data
	Debug    bool
}

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

const alpn = "ntske/1"

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

// Record is the interface all record types must implement. Header()
// returns the record header. string() returns a printable
// representation of the record type. pack() packs the record into
// wire format.
type Record interface {
	Header() RecordHdr

	string() string
	pack(*bytes.Buffer) error
}

// ExchangeMsg is a representation of a series of records to be sent
// to the peer.
type ExchangeMsg struct {
	Record []Record
}

// String prints a description of all recortds in the Key Exchange
// message.
func (m ExchangeMsg) String() {
	for _, r := range m.Record {
		fmt.Printf(r.string())
	}
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

func (n NextProto) string() string {
	return fmt.Sprintf("--NextProto: %v\n", n.NextProto)
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

func (e End) string() string {
	return fmt.Sprintf("--EOM\n")
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

func (s Server) string() string {
	return fmt.Sprintf("--Server: %v\n", string(s.Addr))
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

func (p Port) string() string {
	return fmt.Sprintf("--Port: %v\n", p.Port)
}

// Cookie is an NTS cookie to be used when querying time over NTS.
type Cookie struct {
	RecordHdr
	Cookie []byte
}

func (c Cookie) pack(buf *bytes.Buffer) error {
	return packsimple(RecCookie, false, c.Cookie, buf)
}

func (c Cookie) string() string {
	return fmt.Sprintf("--Cookie: %x\n", c.Cookie)
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

func (w Warning) string() string {
	return fmt.Sprintf("--Warning: %x\n", w.Code)
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

func (e Error) string() string {
	return fmt.Sprintf("--Error: %x\n", e.Code)
}

// Algorithm is the record type for a list of AEAD algorithm we can use.
type Algorithm struct {
	RecordHdr
	Algo []uint16
}

func (a Algorithm) pack(buf *bytes.Buffer) error {
	return packsimple(RecAead, true, a.Algo, buf)
}

func (a Algorithm) string() string {
	var str string = "--AEAD: \n"

	for i, alg := range a.Algo {
		algstr := fmt.Sprintf("  #%v: %v\n", i, alg)
		str = str + algstr
	}

	return str
}

func NewListener(listener net.Listener) (*KeyExchange, error) {
	ke := new(KeyExchange)
	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("Couldn't answer`")
	}

	var ok bool
	ke.Conn, ok = conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("could not convert to tls connection")
	}

	ke.reader = bufio.NewReader(ke.Conn)

	// state := ke.Conn.ConnectionState()
	// fmt.Printf("negotiated proto: %v\n", state.NegotiatedProtocol)
	// if state.NegotiatedProtocol != alpn {
	// 	return nil, fmt.Errorf("client not speaking ntske/1")
	// }

	return ke, nil
}

// Connect connects to host:port and establishes an NTS-KE connection.
// If :port is left out, protocol default port is used.
// No further action is done.
func Connect(hostport string, config *tls.Config, debug bool) (*KeyExchange, error) {
	config.NextProtos = []string{alpn}

	ke := new(KeyExchange)
	ke.Debug = debug
	ke.hostport = hostport

	_, _, err := net.SplitHostPort(ke.hostport)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return nil, err
		}
		ke.hostport = net.JoinHostPort(ke.hostport, strconv.Itoa(DEFAULT_NTSKE_PORT))
	}

	if ke.Debug {
		fmt.Printf("Connecting to KE server %v\n", ke.hostport)
	}
	ke.Conn, err = tls.DialWithDialer(&net.Dialer{
		Timeout: time.Second * 5,
	}, "tcp", ke.hostport, config)
	if err != nil {
		return nil, err
	}

	// Set default NTP server to the IP resolved and connected to for NTS-KE.
	// Handles multiple A records & possible lack of NTPv4 Server Negotiation.
	ke.Meta.Server, _, err = net.SplitHostPort(ke.Conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("unexpected remoteaddr issue: %s", err)
	}
	ke.Meta.Port = DEFAULT_NTP_PORT

	if ke.Debug {
		fmt.Printf("Using resolved KE server as NTP default: %v\n",
			net.JoinHostPort(ke.Meta.Server, strconv.Itoa(int(ke.Meta.Port))))
	}
	ke.reader = bufio.NewReader(ke.Conn)

	state := ke.Conn.ConnectionState()
	if state.NegotiatedProtocol != alpn {
		return nil, fmt.Errorf("server not speaking ntske/1")
	}

	return ke, nil
}

// Exchange initiates a client exchange using sane defaults on a
// connection already established with Connect(). After a succesful
// run negotiated data is in ke.Meta.
func (ke *KeyExchange) Exchange() error {
	var msg ExchangeMsg
	var nextproto NextProto

	nextproto.NextProto = NTPv4
	msg.AddRecord(nextproto)

	var algo Algorithm
	algo.Algo = []uint16{AES_SIV_CMAC_256}
	msg.AddRecord(algo)

	var end End
	msg.AddRecord(end)

	buf, err := msg.Pack()
	if err != nil {
		return err
	}

	_, err = ke.Conn.Write(buf.Bytes())
	if err != nil {
		return err
	}

	// Wait for response
	err = ke.Read()
	if err != nil {
		return err
	}

	return nil
}

// ExportKeys exports two extra sessions keys from the already
// established NTS-KE connection for use with NTS.
func (ke *KeyExchange) ExportKeys() error {
	// 4.3. in the the rfc https://tools.ietf.org/html/rfc8915#section-4.3
	label := "EXPORTER-network-time-security"
	// The per-association context value SHALL consist of the following
	// five octets:
	//
	// The first two octets SHALL be zero (the Protocol ID for NTPv4).
	//
	// The next two octets SHALL be the Numeric Identifier of the
	// negotiated AEAD Algorithm in network byte order. Typically
	// 0x0f for AES-SIV-CMAC-256.
	//
	// The final octet SHALL be 0x00 for the C2S key and 0x01 for the
	// S2C key.
	s2c_context := make([]byte, 4)
	binary.BigEndian.PutUint16(s2c_context[2:], ke.Meta.Algo)
	s2c_context = append(s2c_context, 0x01)

	c2s_context := make([]byte, 4)
	binary.BigEndian.PutUint16(c2s_context[2:], ke.Meta.Algo)
	c2s_context = append(c2s_context, 0x00)

	var keylength = 32
	var err error

	state := ke.Conn.ConnectionState()
	if ke.Meta.C2sKey, err = state.ExportKeyingMaterial(label, c2s_context, keylength); err != nil {
		return err
	}
	if ke.Meta.S2cKey, err = state.ExportKeyingMaterial(label, s2c_context, keylength); err != nil {
		return err
	}

	return nil
}

// Read reads incoming NTS-KE messages until an End of Message record
// is received or an error occur. It fills out the ke.Meta structure
// with negotiated data.
func (ke *KeyExchange) Read() error {
	var msg RecordHdr
	var critical bool

	for {
		err := binary.Read(ke.reader, binary.BigEndian, &msg)
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

		if ke.Debug {
			fmt.Printf("Record type %v\n", msg.Type)
			if critical {
				fmt.Printf("Critical set\n")
			}
		}

		switch msg.Type {
		case RecEom:
			// Check that we have complete data.
			// if len(ke.Meta.Cookie) == 0 || ke.Meta.Algo == 0 {
			// 	return errors.New("incomplete data")
			// }

			return nil

		case RecNextproto:
			var nextProto uint16
			err := binary.Read(ke.reader, binary.BigEndian, &nextProto)
			if err != nil {
				return errors.New("buffer overrun")
			}

		case RecAead:
			var aead uint16
			err := binary.Read(ke.reader, binary.BigEndian, &aead)
			if err != nil {
				return errors.New("buffer overrun")
			}

			ke.Meta.Algo = aead

		case RecCookie:
			cookie := make([]byte, msg.BodyLen)
			_, err := ke.reader.Read(cookie)
			if err != nil {
				return errors.New("buffer overrun")
			}

			ke.Meta.Cookie = append(ke.Meta.Cookie, cookie)

		case RecServer:
			address := make([]byte, msg.BodyLen)

			err := binary.Read(ke.reader, binary.BigEndian, &address)
			if err != nil {
				return errors.New("buffer overrun")
			}
			ke.Meta.Server = string(address)
			if ke.Debug {
				fmt.Printf("(got negotiated NTP server: %v)\n", ke.Meta.Server)
			}

		case RecPort:
			err := binary.Read(ke.reader, binary.BigEndian, &ke.Meta.Port)
			if err != nil {
				return errors.New("buffer overrun")
			}
			if ke.Debug {
				fmt.Printf("(got negotiated NTP port: %v)\n", ke.Meta.Port)
			}

		default:
			if critical {
				return fmt.Errorf("unknown record type %v with critical bit set", msg.Type)
			}

			// Swallow unknown record.
			unknownMsg := make([]byte, msg.BodyLen)
			err := binary.Read(ke.reader, binary.BigEndian, &unknownMsg)
			if err != nil {
				return errors.New("buffer overrun")
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

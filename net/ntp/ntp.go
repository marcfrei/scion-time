package ntp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/secure-io/siv-go"
)

const (
	nanosecondsPerSecond int64 = 1e9

	ServerPort = 123

	PacketLen = 48
	NTSPacketLen = 228

	LeapIndicatorNoWarning    = 0
	LeapIndicatorInsertSecond = 1
	LeapIndicatorDeleteSecond = 2
	LeapIndicatorUnknown      = 3

	VersionMin = 1
	VersionMax = 4

	ModeReserved0        = 0
	ModeSymmetricActive  = 1
	ModeSymmetricPassive = 2
	ModeClient           = 3
	ModeServer           = 4
	ModeBroadcast        = 5
	ModeControl          = 6
	ModeReserved7        = 7
)

const (
	ExtUniqueIdentifier  uint16 = 0x104
	ExtCookie            uint16 = 0x204
	ExtCookiePlaceholder uint16 = 0x304
	ExtAuthenticator     uint16 = 0x404
)

type Time32 struct {
	Seconds  uint16
	Fraction uint16
}

type Time64 struct {
	Seconds  uint32
	Fraction uint32
}

type Packet struct {
	LVM            uint8
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      Time32
	RootDispersion Time32
	ReferenceID    uint32
	ReferenceTime  Time64
	OriginTime     Time64
	ReceiveTime    Time64
	TransmitTime   Time64
	Extension      []ExtensionField
}

var (
	epoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

	errUnexpectedPacketSize = errors.New("unexpected packet size")
)

func Time64FromTime(t time.Time) Time64 {
	d := t.Sub(epoch).Nanoseconds()
	return Time64{
		Seconds: uint32(
			d / nanosecondsPerSecond),
		Fraction: uint32(
			(d%nanosecondsPerSecond<<32 + nanosecondsPerSecond/2) / nanosecondsPerSecond),
	}
}

func TimeFromTime64(t Time64) time.Time {
	return epoch.Add(time.Duration(
		int64(t.Seconds)*nanosecondsPerSecond +
			(int64(t.Fraction)*nanosecondsPerSecond+1<<31)>>32))
}

func (t Time64) Before(u Time64) bool {
	return t.Seconds < u.Seconds ||
		t.Seconds == u.Seconds && t.Fraction < u.Fraction
}

func (t Time64) After(u Time64) bool {
	return t.Seconds > u.Seconds ||
		t.Seconds == u.Seconds && t.Fraction > u.Fraction
}

func ClockOffset(t0, t1, t2, t3 time.Time) time.Duration {
	return (t1.Sub(t0) + t2.Sub(t3)) / 2
}

func RoundTripDelay(t0, t1, t2, t3 time.Time) time.Duration {
	return t3.Sub(t0) - t2.Sub(t1)
}

func EncodePacket(b *[]byte, pkt *Packet) {
	var pktlen int
	if pkt.Extension != nil {
		pktlen = NTSPacketLen
	} else {
		pktlen = PacketLen
	}

	if cap(*b) < pktlen {
		*b = make([]byte, pktlen)
	} else {
		*b = (*b)[:pktlen]
	}

	(*b)[0] = byte(pkt.LVM)
	(*b)[1] = byte(pkt.Stratum)
	(*b)[2] = byte(pkt.Poll)
	(*b)[3] = byte(pkt.Precision)
	binary.BigEndian.PutUint16((*b)[4:], pkt.RootDelay.Seconds)
	binary.BigEndian.PutUint16((*b)[6:], pkt.RootDelay.Fraction)
	binary.BigEndian.PutUint16((*b)[8:], pkt.RootDispersion.Seconds)
	binary.BigEndian.PutUint16((*b)[10:], pkt.RootDispersion.Fraction)
	binary.BigEndian.PutUint32((*b)[12:], pkt.ReferenceID)
	binary.BigEndian.PutUint32((*b)[16:], pkt.ReferenceTime.Seconds)
	binary.BigEndian.PutUint32((*b)[20:], pkt.ReferenceTime.Fraction)
	binary.BigEndian.PutUint32((*b)[24:], pkt.OriginTime.Seconds)
	binary.BigEndian.PutUint32((*b)[28:], pkt.OriginTime.Fraction)
	binary.BigEndian.PutUint32((*b)[32:], pkt.ReceiveTime.Seconds)
	binary.BigEndian.PutUint32((*b)[36:], pkt.ReceiveTime.Fraction)
	binary.BigEndian.PutUint32((*b)[40:], pkt.TransmitTime.Seconds)
	binary.BigEndian.PutUint32((*b)[44:], pkt.TransmitTime.Fraction)

	var buf *bytes.Buffer = new(bytes.Buffer)
	buf.Write((*b)[0:48])
	for _, ef := range pkt.Extension {
		_ = ef.pack(buf)
	}

	copy((*b)[0:pktlen], buf.Bytes())
}

func DecodePacket(pkt *Packet, b []byte, cookies *[][]byte, keys2c Key) error {
	if len(b) < PacketLen {
		return errUnexpectedPacketSize
	}

	pkt.LVM = uint8(b[0])
	pkt.Stratum = uint8(b[1])
	pkt.Poll = int8(b[2])
	pkt.Precision = int8(b[3])
	pkt.RootDelay.Seconds = binary.BigEndian.Uint16(b[4:])
	pkt.RootDelay.Fraction = binary.BigEndian.Uint16(b[6:])
	pkt.RootDispersion.Seconds = binary.BigEndian.Uint16(b[8:])
	pkt.RootDispersion.Fraction = binary.BigEndian.Uint16(b[10:])
	pkt.ReferenceID = binary.BigEndian.Uint32(b[12:])
	pkt.ReferenceTime.Seconds = binary.BigEndian.Uint32(b[16:])
	pkt.ReferenceTime.Fraction = binary.BigEndian.Uint32(b[20:])
	pkt.OriginTime.Seconds = binary.BigEndian.Uint32(b[24:])
	pkt.OriginTime.Fraction = binary.BigEndian.Uint32(b[28:])
	pkt.ReceiveTime.Seconds = binary.BigEndian.Uint32(b[32:])
	pkt.ReceiveTime.Fraction = binary.BigEndian.Uint32(b[36:])
	pkt.TransmitTime.Seconds = binary.BigEndian.Uint32(b[40:])
	pkt.TransmitTime.Fraction = binary.BigEndian.Uint32(b[44:])

	var pos int = 48 // Keep track of where in the original buf we are
	msgbuf := bytes.NewReader(b[48:])
	for msgbuf.Len() >= 28 {
		var eh ExtHdr
		err := eh.unpack(msgbuf)
		if err != nil {
			return fmt.Errorf("unpack extension field: %s", err)
		}

		switch eh.Type {
		case ExtUniqueIdentifier:
			u := UniqueIdentifier{ExtHdr: eh}
			err = u.unpack(msgbuf)
			if err != nil {
				return fmt.Errorf("unpack UniqueIdentifier: %s", err)
			}

			pkt.AddExt(u)

		case ExtAuthenticator:
			a := Authenticator{ExtHdr: eh}
			err = a.unpack(msgbuf)
			if err != nil {
				return fmt.Errorf("unpack Authenticator: %s", err)
			}

			aessiv, err := siv.NewCMAC(keys2c)
			if err != nil {
				return err
			}

			decrytedBuf, err := aessiv.Open(nil, a.Nonce, a.CipherText, b[:pos])
			if err != nil {
				return err
			}
			pkt.AddExt(a)
			b = append(b, decrytedBuf...)
			msgbuf = bytes.NewReader(b[(pos + int(eh.Length)):])

		case ExtCookie:
			cookie := Cookie{ExtHdr: eh}
			err = cookie.unpack(msgbuf)
			if err != nil {
				return fmt.Errorf("unpack Cookie: %s", err)
			}
			pkt.AddExt(cookie)
			*cookies = append(*cookies, cookie.Cookie)

		default:
			// Unknown extension field. Skip it.
			_, err := msgbuf.Seek(int64(eh.Length), io.SeekCurrent)
			if err != nil {
				return err
			}
		}

		pos += int(eh.Length)
	}

	return nil
}

func (p *Packet) LeapIndicator() uint8 {
	return (p.LVM >> 6) & 0b0000_0011
}

func (p *Packet) SetLeapIndicator(l uint8) {
	if l&0b0000_0011 != l {
		panic("unexpected NTP leap indicator value")
	}
	p.LVM = (p.LVM & 0b0011_1111) | (l << 6)
}

func (p *Packet) Version() uint8 {
	return (p.LVM >> 3) & 0b0000_0111
}

func (p *Packet) SetVersion(v uint8) {
	if v&0b0000_0111 != v {
		panic("unexpected NTP version value")
	}
	p.LVM = (p.LVM & 0b_1100_0111) | (v << 3)
}

func (p *Packet) Mode() uint8 {
	return p.LVM & 0b0000_0111
}

func (p *Packet) SetMode(m uint8) {
	if m&0b0000_0111 != m {
		panic("unexpected NTP mode value")
	}
	p.LVM = (p.LVM & 0b1111_1000) | m
}

// ExtensionField code taken from github.com/hacklunch/ntp
type ExtHdr struct {
	Type   uint16
	Length uint16
}

func (h ExtHdr) pack(buf *bytes.Buffer) error {
	err := binary.Write(buf, binary.BigEndian, h)
	return err
}

func (h *ExtHdr) unpack(buf *bytes.Reader) error {
	err := binary.Read(buf, binary.BigEndian, h)
	return err
}

func (h ExtHdr) Header() ExtHdr { return h }

func (h ExtHdr) string() string {
	return fmt.Sprintf("Extension field type: %v, len: %v\n", h.Type, h.Length)
}

func (packet *Packet) AddExt(ext ExtensionField) {
	packet.Extension = append(packet.Extension, ext)
}

type ExtensionField interface {
	Header() ExtHdr
	string() string
	pack(*bytes.Buffer) error
}

type UniqueIdentifier struct {
	ExtHdr
	ID []byte
}

func (u UniqueIdentifier) string() string {
	return fmt.Sprintf("-- UniqueIdentifier EF\n"+
		"  ID: %x\n", u.ID)
}

func (u UniqueIdentifier) pack(buf *bytes.Buffer) error {
	value := new(bytes.Buffer)
	err := binary.Write(value, binary.BigEndian, u.ID)
	if err != nil {
		return err
	}
	if value.Len() < 32 {
		return fmt.Errorf("UniqueIdentifier.ID < 32 bytes")
	}

	newlen := (value.Len() + 3) & ^3
	padding := make([]byte, newlen-value.Len())

	u.ExtHdr.Type = ExtUniqueIdentifier
	u.ExtHdr.Length = 4 + uint16(newlen)
	err = u.ExtHdr.pack(buf)
	if err != nil {
		return err
	}

	_, err = buf.ReadFrom(value)
	if err != nil {
		return err
	}

	_, err = buf.Write(padding)
	if err != nil {
		return err
	}

	return nil
}

func (u *UniqueIdentifier) unpack(buf *bytes.Reader) error {
	if u.ExtHdr.Type != ExtUniqueIdentifier {
		return fmt.Errorf("expected unpacked EF header")
	}
	valueLen := u.ExtHdr.Length - uint16(binary.Size(u.ExtHdr))
	id := make([]byte, valueLen)
	if err := binary.Read(buf, binary.BigEndian, id); err != nil {
		return err
	}
	u.ID = id
	return nil
}

func (u *UniqueIdentifier) Generate() ([]byte, error) {
	id := make([]byte, 32)

	_, err := rand.Read(id)
	if err != nil {
		return nil, err
	}

	u.ID = id

	return id, nil
}

type Cookie struct {
	ExtHdr
	Cookie []byte
}

func (c Cookie) string() string {
	return fmt.Sprintf("-- Cookie EF\n"+
		"  %x\n", c.Cookie)
}

func (c Cookie) pack(buf *bytes.Buffer) error {
	value := new(bytes.Buffer)
	origlen, err := value.Write(c.Cookie)
	if err != nil {
		return err
	}

	// Round up to nearest word boundary
	newlen := (origlen + 3) & ^3
	padding := make([]byte, newlen-origlen)

	c.ExtHdr.Type = ExtCookie
	c.ExtHdr.Length = 4 + uint16(newlen)
	err = c.ExtHdr.pack(buf)
	if err != nil {
		return err
	}

	_, err = buf.ReadFrom(value)
	if err != nil {
		return err
	}
	_, err = buf.Write(padding)
	if err != nil {
		return err
	}

	return nil
}

func (c *Cookie) unpack(buf *bytes.Reader) error {
	if c.ExtHdr.Type != ExtCookie {
		return fmt.Errorf("expected unpacked EF header")
	}
	valueLen := c.ExtHdr.Length - uint16(binary.Size(c.ExtHdr))
	cookie := make([]byte, valueLen)
	if err := binary.Read(buf, binary.BigEndian, cookie); err != nil {
		return err
	}
	c.Cookie = cookie
	return nil
}

type CookiePlaceholder struct {
	ExtHdr
	Cookie []byte
}

type Key []byte

type Authenticator struct {
	ExtHdr
	NonceLen      uint16
	CipherTextLen uint16
	Nonce         []byte
	CipherText    []byte
	Key           Key
}

func (a Authenticator) string() string {
	return fmt.Sprintf("-- Authenticator EF\n"+
		"  NonceLen: %v\n"+
		"  CipherTextLen: %v\n"+
		"  Nonce: %x\n"+
		"  Ciphertext: %x\n"+
		"  Key: %x\n",
		a.NonceLen,
		a.CipherTextLen,
		a.Nonce,
		a.CipherText,
		a.Key,
	)
}

func (a Authenticator) pack(buf *bytes.Buffer) error {
	aessiv, err := siv.NewCMAC(a.Key)
	if err != nil {
		return err
	}

	bits := make([]byte, 16)
	_, err = rand.Read(bits)
	if err != nil {
		return err
	}

	a.Nonce = bits

	a.CipherText = aessiv.Seal(nil, a.Nonce, nil, buf.Bytes())
	a.CipherTextLen = uint16(len(a.CipherText))

	noncebuf := new(bytes.Buffer)
	err = binary.Write(noncebuf, binary.BigEndian, a.Nonce)
	if err != nil {
		return err
	}
	a.NonceLen = uint16(noncebuf.Len())

	cipherbuf := new(bytes.Buffer)
	err = binary.Write(cipherbuf, binary.BigEndian, a.CipherText)
	if err != nil {
		return err
	}
	a.CipherTextLen = uint16(cipherbuf.Len())

	extbuf := new(bytes.Buffer)

	err = binary.Write(extbuf, binary.BigEndian, a.NonceLen)
	if err != nil {
		return err
	}

	err = binary.Write(extbuf, binary.BigEndian, a.CipherTextLen)
	if err != nil {
		return err
	}

	_, err = extbuf.ReadFrom(noncebuf)
	if err != nil {
		return err
	}
	noncepadding := make([]byte, (noncebuf.Len()+3) & ^3)
	_, err = extbuf.Write(noncepadding)
	if err != nil {
		return err
	}

	_, err = extbuf.ReadFrom(cipherbuf)
	if err != nil {
		return err
	}
	cipherpadding := make([]byte, (cipherbuf.Len()+3) & ^3)
	_, err = extbuf.Write(cipherpadding)
	if err != nil {
		return err

	}
	// FIXME Add additionalpadding as described in section 5.6 of nts draft?

	a.ExtHdr.Type = ExtAuthenticator
	a.ExtHdr.Length = 4 + uint16(extbuf.Len())
	err = a.ExtHdr.pack(buf)
	if err != nil {
		return err
	}

	_, err = buf.ReadFrom(extbuf)
	if err != nil {

		return err
	}
	//_, err = buf.Write(additionalpadding)
	//if err != nil {
	//	return err
	//}

	return nil
}

func (a *Authenticator) unpack(buf *bytes.Reader) error {
	if a.ExtHdr.Type != ExtAuthenticator {
		return fmt.Errorf("expected unpacked EF header")
	}

	// NonceLen, 2
	if err := binary.Read(buf, binary.BigEndian, &a.NonceLen); err != nil {
		return err
	}

	// CipherTextlen, 2
	if err := binary.Read(buf, binary.BigEndian, &a.CipherTextLen); err != nil {
		return err
	}

	// Nonce
	nonce := make([]byte, a.NonceLen)
	if err := binary.Read(buf, binary.BigEndian, &nonce); err != nil {
		return err
	}
	a.Nonce = nonce

	// Ciphertext
	ciphertext := make([]byte, a.CipherTextLen)
	if err := binary.Read(buf, binary.BigEndian, ciphertext); err != nil {
		return err
	}
	a.CipherText = ciphertext

	return nil
}

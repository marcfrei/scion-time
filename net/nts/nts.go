/*
Copyright 2015-2017 Brett Vickers. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY COPYRIGHT HOLDER ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package nts

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"example.com/scion-time/net/ntske"
	"github.com/secure-io/siv-go"
)

const (
	NumStoredCookies int = 8
	ntpHeaderLen     int = 48
)

const (
	extUniqueIdentifier  uint16 = 0x104
	extCookie            uint16 = 0x204
	extCookiePlaceholder uint16 = 0x304
	extAuthenticator     uint16 = 0x404
)

const (
	cookieTypeAlgorithm uint16 = 0x101
	cookieTypeKeyS2C    uint16 = 0x201
	cookieTypeKeyC2S    uint16 = 0x301

	cookieTypeKeyID      uint16 = 0x401
	cookieTypeNonce      uint16 = 0x501
	cookieTypeCiphertext uint16 = 0x601
)

type NTSPacket struct {
	NTPHeader  []byte
	Extensions []ExtensionField
}

func NewPacket(ntpHeader []byte, ntskeData ntske.Data) (pkt NTSPacket, uniqueid []byte) {
	pkt.NTPHeader = ntpHeader
	var uid UniqueIdentifier
	uid.Generate()
	pkt.AddExt(uid)

	var cookie Cookie
	cookie.Cookie = ntskeData.Cookie[0]
	pkt.AddExt(cookie)

	// Add cookie extension fields here s.t. 8 cookies are available after response.
	cookiePlaceholderData := make([]byte, len(cookie.Cookie))
	for i := len(ntskeData.Cookie); i < NumStoredCookies; i++ {
		var cookiePlacholder CookiePlaceholder
		cookiePlacholder.Cookie = cookiePlaceholderData
		pkt.AddExt(cookiePlacholder)
	}

	var auth Authenticator
	auth.Key = ntskeData.C2sKey
	pkt.AddExt(auth)

	return pkt, uid.ID
}

func EncodePacket(b *[]byte, pkt *NTSPacket) {
	buf := new(bytes.Buffer)
	if len(pkt.NTPHeader) != ntpHeaderLen {
		panic("unexpected NTP header")
	}
	_, _ = buf.Write((pkt.NTPHeader))

	for _, e := range pkt.Extensions {
		err := e.pack(buf)
		if err != nil {
			panic(err)
		}
	}

	pktlen := buf.Len()
	if cap(*b) < pktlen {
		*b = make([]byte, pktlen)
	} else {
		*b = (*b)[:pktlen]
	}

	copy((*b)[:pktlen], buf.Bytes())
}

func DecodePacket(pkt *NTSPacket, b []byte, key []byte) (cookies [][]byte, uniqueID []byte, err error) {
	pos := ntpHeaderLen
	msgbuf := bytes.NewReader(b[48:])
	authenticated := false
	unique := false
	for msgbuf.Len() >= 28 {
		var eh ExtHdr
		err := eh.unpack(msgbuf)
		if err != nil {
			return cookies, uniqueID, fmt.Errorf("unpack extension field: %s", err)
		}

		switch eh.Type {
		case extUniqueIdentifier:
			u := UniqueIdentifier{ExtHdr: eh}
			err = u.unpack(msgbuf)
			if err != nil {
				return cookies, uniqueID, fmt.Errorf("unpack UniqueIdentifier: %s", err)
			}
			uniqueID = u.ID
			pkt.AddExt(u)
			unique = true

		case extAuthenticator:
			a := Authenticator{ExtHdr: eh}
			err = a.unpack(msgbuf)
			if err != nil {
				return cookies, uniqueID, fmt.Errorf("unpack Authenticator: %s", err)
			}

			aessiv, err := siv.NewCMAC(key)
			if err != nil {
				return cookies, uniqueID, err
			}

			decrytedBuf, err := aessiv.Open(nil, a.Nonce, a.CipherText, b[:pos])
			if err != nil {
				return cookies, uniqueID, err
			}
			pkt.AddExt(a)

			//ignore unauthenticated fields and only continue with decrypted
			msgbuf = bytes.NewReader(decrytedBuf)
			authenticated = true

		case extCookie:
			cookie := Cookie{ExtHdr: eh}
			err = cookie.unpack(msgbuf)
			if err != nil {
				return cookies, uniqueID, fmt.Errorf("unpack Cookie: %s", err)
			}
			pkt.AddExt(cookie)
			cookies = append(cookies, cookie.Cookie)

		default:
			// Unknown extension field. Skip it.
			_, err := msgbuf.Seek(int64(eh.Length), io.SeekCurrent)
			if err != nil {
				return cookies, uniqueID, err
			}
		}
		pos += int(eh.Length)
	}

	if !authenticated {
		return cookies, uniqueID, errors.New("packet does not contain a valid authenticator")
	}
	if !unique {
		return cookies, uniqueID, errors.New("packet not does not contain a unique identifier")
	}

	return cookies, uniqueID, nil
}

func ExtractCookie(b []byte) (cookie []byte, err error) {
	msgbuf := bytes.NewReader(b[48:])
	for msgbuf.Len() >= 28 {
		var eh ExtHdr
		err := eh.unpack(msgbuf)
		if err != nil {
			return cookie, fmt.Errorf("unpack extension field: %s", err)
		}

		switch eh.Type {
		case extUniqueIdentifier:
			u := UniqueIdentifier{ExtHdr: eh}
			err = u.unpack(msgbuf)
			if err != nil {
				return cookie, fmt.Errorf("unpack UniqueIdentifier: %s", err)
			}

		case extAuthenticator:
			a := Authenticator{ExtHdr: eh}
			err = a.unpack(msgbuf)
			if err != nil {
				return cookie, fmt.Errorf("unpack Authenticator: %s", err)
			}

		case extCookie:
			cookieExt := Cookie{ExtHdr: eh}
			err = cookieExt.unpack(msgbuf)
			if err != nil {
				return cookie, fmt.Errorf("unpack Cookie: %s", err)
			}
			return cookieExt.Cookie, nil

		default:
			// Unknown extension field. Skip it.
			_, err := msgbuf.Seek(int64(eh.Length), io.SeekCurrent)
			if err != nil {
				return cookie, err
			}
		}
	}

	return cookie, errors.New("packet not does not contain a cookie")
}

func ProcessResponse(ntskeFetcher *ntske.Fetcher, cookies [][]byte, reqID []byte, respID []byte) error {
	for _, cookie := range cookies {
		ntskeFetcher.StoreCookie(cookie)
	}
	if !bytes.Equal(reqID, respID) {
		return errors.New("unexpected response ID")
	}
	return nil
}

func PrepareNewResponsePacket(ntpheader []byte, cookies [][]byte, key []byte, uniqueid []byte) (pkt NTSPacket) {
	pkt.NTPHeader = ntpheader
	var uid UniqueIdentifier
	uid.ID = uniqueid
	pkt.AddExt(uid)

	var buf *bytes.Buffer = new(bytes.Buffer)
	for _, c := range cookies {
		var cookie Cookie
		cookie.Cookie = c
		cookie.pack(buf)
	}

	var auth Authenticator
	auth.Key = key
	auth.AssociatedData = buf.Bytes()
	pkt.AddExt(auth)

	return pkt
}

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

func (packet *NTSPacket) AddExt(ext ExtensionField) {
	packet.Extensions = append(packet.Extensions, ext)
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

	u.ExtHdr.Type = extUniqueIdentifier
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
	if u.ExtHdr.Type != extUniqueIdentifier {
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

	c.ExtHdr.Type = extCookie
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
	if c.ExtHdr.Type != extCookie {
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

func (c CookiePlaceholder) string() string {
	return "-- CookiePlacholder EF\n"
}

func (c CookiePlaceholder) pack(buf *bytes.Buffer) error {
	value := new(bytes.Buffer)
	origlen, err := value.Write(c.Cookie)
	if err != nil {
		return err
	}

	// Round up to nearest word boundary
	newlen := (origlen + 3) & ^3
	padding := make([]byte, newlen-origlen)

	c.ExtHdr.Type = extCookiePlaceholder
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

type Key []byte

type Authenticator struct {
	ExtHdr
	NonceLen       uint16
	CipherTextLen  uint16
	Nonce          []byte
	AssociatedData []byte
	CipherText     []byte
	Key            Key
}

func (a Authenticator) string() string {
	return fmt.Sprintf("-- Authenticator EF\n"+
		"  NonceLen: %v\n"+
		"  CipherTextLen: %v\n"+
		"  Nonce: %x\n"+
		"  AssociatedData %x\n"+
		"  Ciphertext: %x\n"+
		"  Key: %x\n",
		a.NonceLen,
		a.CipherTextLen,
		a.AssociatedData,
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

	a.CipherText = aessiv.Seal(nil, a.Nonce, a.AssociatedData, buf.Bytes())
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

	a.ExtHdr.Type = extAuthenticator
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
	if a.ExtHdr.Type != extAuthenticator {
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

type PlainCookie struct {
	Algo uint16
	S2C  []byte
	C2S  []byte
}

// Encodes cookie to byte slice with following format for each field
// uint16 | uint16 | []byte
// type   | length | value
func (c *PlainCookie) Encode() (b []byte, err error) {
	var cookiesize int = 3*4 + 2 + len(c.C2S) + len(c.S2C)
	b = make([]byte, cookiesize)
	binary.BigEndian.PutUint16((b)[0:], cookieTypeAlgorithm)
	binary.BigEndian.PutUint16((b)[2:], 0x2)
	binary.BigEndian.PutUint16((b)[4:], c.Algo)
	binary.BigEndian.PutUint16((b)[6:], cookieTypeKeyS2C)
	binary.BigEndian.PutUint16((b)[8:], uint16(len(c.S2C)))
	copy((b)[10:], c.S2C)
	pos := len(c.S2C) + 10
	binary.BigEndian.PutUint16((b)[pos:], cookieTypeKeyC2S)
	binary.BigEndian.PutUint16((b)[pos+2:], uint16(len(c.C2S)))
	copy((b)[pos+4:], c.C2S)
	return b, nil
}

func (c *PlainCookie) Decode(b []byte) {
	var pos int = 0
	for pos < len(b) {
		var t uint16 = binary.BigEndian.Uint16(b[pos:])
		var len uint16 = binary.BigEndian.Uint16(b[pos+2:])
		if t == cookieTypeAlgorithm {
			c.Algo = binary.BigEndian.Uint16(b[pos+4:])
		} else if t == cookieTypeKeyS2C {
			c.S2C = b[pos+4 : pos+4+int(len)]
		} else if t == cookieTypeKeyC2S {
			c.C2S = b[pos+4 : pos+4+int(len)]
		}
		pos += 4 + int(len)
	}
}

type EncryptedCookie struct {
	ID         uint16
	Nonce      []byte
	Ciphertext []byte
}

func (c *EncryptedCookie) Encode() (b []byte, err error) {
	var encryptedcookiesize int = 3*4 + 2 + len(c.Nonce) + len(c.Ciphertext)
	b = make([]byte, encryptedcookiesize)
	binary.BigEndian.PutUint16((b)[0:], cookieTypeKeyID)
	binary.BigEndian.PutUint16((b)[2:], 0x2)
	binary.BigEndian.PutUint16((b)[4:], c.ID)
	binary.BigEndian.PutUint16((b)[6:], cookieTypeNonce)
	binary.BigEndian.PutUint16((b)[8:], uint16(len(c.Nonce)))
	copy((b)[10:], c.Nonce)
	pos := len(c.Nonce) + 10
	binary.BigEndian.PutUint16((b)[pos:], cookieTypeCiphertext)
	binary.BigEndian.PutUint16((b)[pos+2:], uint16(len(c.Ciphertext)))
	copy((b)[pos+4:], c.Ciphertext)
	return b, nil
}

func (c *EncryptedCookie) Decode(b []byte) {
	var pos int = 0
	for pos < len(b) {
		var t uint16 = binary.BigEndian.Uint16(b[pos:])
		var len uint16 = binary.BigEndian.Uint16(b[pos+2:])
		if t == cookieTypeKeyID {
			c.ID = binary.BigEndian.Uint16(b[pos+4:])
		} else if t == cookieTypeNonce {
			c.Nonce = b[pos+4 : pos+4+int(len)]
		} else if t == cookieTypeCiphertext {
			c.Ciphertext = b[pos+4 : pos+4+int(len)]
		}
		pos += 4 + int(len)
	}
}

func (c *PlainCookie) Encrypt(key []byte, keyid int) (EncryptedCookie, error) {
	var ecookie EncryptedCookie
	ecookie.ID = uint16(keyid)
	bits := make([]byte, 16)
	_, err := rand.Read(bits)
	if err != nil {
		return ecookie, err
	}
	ecookie.Nonce = bits

	aessiv, err := siv.NewCMAC(key)
	if err != nil {
		return ecookie, err
	}

	b, err := c.Encode()
	if err != nil {
		return ecookie, err
	}

	ecookie.Ciphertext = aessiv.Seal(nil, ecookie.Nonce, b, nil)

	return ecookie, nil
}

func (c *EncryptedCookie) Decrypt(key []byte, keyid int) (PlainCookie, error) {
	var cookie PlainCookie

	if c.ID != uint16(keyid) {
		return cookie, errors.New("Wrong Key ID")
	}

	aessiv, err := siv.NewCMAC(key)
	if err != nil {
		return cookie, err
	}

	b, err := aessiv.Open(nil, c.Nonce, c.Ciphertext, nil)
	if err != nil {
		return cookie, err
	}
	cookie.Decode(b)
	if err != nil {
		return cookie, err
	}
	return cookie, nil
}

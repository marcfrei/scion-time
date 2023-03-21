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
	ntpHeaderLen int = 48
)

const (
	extUniqueIdentifier  uint16 = 0x104
	extCookie            uint16 = 0x204
	extCookiePlaceholder uint16 = 0x304
	extAuthenticator     uint16 = 0x404
)

type NTSPacket struct {
	NTPHeader  []byte
	Extensions []ExtensionField
}

func EncodePacket(b *[]byte, pkt *NTSPacket) {
	var buf *bytes.Buffer = new(bytes.Buffer)
	if len(pkt.NTPHeader) != ntpHeaderLen {
		panic("unexpected NTP header")
	}
	_, _ = buf.Write((pkt.NTPHeader))

	for _, e := range pkt.Extensions {
		err := e.pack(buf)
		if err != nil {
			// TODO better error handling
			panic(err)
		}
	}

	var pktlen int = buf.Len()
	if cap(*b) < pktlen {
		*b = make([]byte, pktlen)
	} else {
		*b = (*b)[:pktlen]
	}

	copy((*b)[:pktlen], buf.Bytes())
}

func DecodePacket(pkt *NTSPacket, b []byte, uniqueID []byte, f *ntske.Fetcher) error {
	var pos int = ntpHeaderLen // Keep track of where in the original buf we are
	msgbuf := bytes.NewReader(b[48:])
	var authenticated bool = false
	var unique bool = false
	var cookies [][]byte
	for msgbuf.Len() >= 28 {
		var eh ExtHdr
		err := eh.unpack(msgbuf)
		if err != nil {
			return fmt.Errorf("unpack extension field: %s", err)
		}

		switch eh.Type {
		case extUniqueIdentifier:
			u := UniqueIdentifier{ExtHdr: eh}
			err = u.unpack(msgbuf)
			if err != nil {
				return fmt.Errorf("unpack UniqueIdentifier: %s", err)
			}
			if !bytes.Equal(u.ID, uniqueID) {
				return fmt.Errorf("Unique identifiers do not match")
			}
			pkt.AddExt(u)
			unique = true

		case extAuthenticator:
			a := Authenticator{ExtHdr: eh}
			err = a.unpack(msgbuf)
			if err != nil {
				return fmt.Errorf("unpack Authenticator: %s", err)
			}

			aessiv, err := siv.NewCMAC(f.GetS2cKey())
			if err != nil {
				return err
			}

			decrytedBuf, err := aessiv.Open(nil, a.Nonce, a.CipherText, b[:pos])
			if err != nil {
				return err
			}
			pkt.AddExt(a)

			//ignore unauthenticated fields and only continue with decrypted
			msgbuf = bytes.NewReader(decrytedBuf)
			authenticated = true

		case extCookie:
			cookie := Cookie{ExtHdr: eh}
			err = cookie.unpack(msgbuf)
			if err != nil {
				return fmt.Errorf("unpack Cookie: %s", err)
			}
			pkt.AddExt(cookie)
			cookies = append(cookies, cookie.Cookie)

		default:
			// Unknown extension field. Skip it.
			_, err := msgbuf.Seek(int64(eh.Length), io.SeekCurrent)
			if err != nil {
				return err
			}
		}

		pos += int(eh.Length)
	}

	if !authenticated {
		return errors.New("packet does not contain a valid authenticator")
	}
	if !unique {
		return errors.New("packet not does not contain a unique identifier")
	}

	for _, cookie := range cookies {
		f.StoreCookie(cookie)
	}

	return nil
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
	return fmt.Sprintf("-- CookiePlacholder EF\n")
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

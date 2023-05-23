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
	"github.com/miscreant/miscreant.go"
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

type NTSPacket struct {
	NTPHeader          []byte
	UniqueID           UniqueIdentifier
	Cookies            []Cookie
	CookiePlaceholders []CookiePlaceholder
	Auth               Authenticator
}

func NewPacket(ntpHeader []byte, ntskeData ntske.Data) (pkt NTSPacket, uniqueid []byte) {
	pkt.NTPHeader = ntpHeader
	var uid UniqueIdentifier
	uid.Generate()
	pkt.UniqueID = uid

	var cookie Cookie
	cookie.Cookie = ntskeData.Cookie[0]
	pkt.Cookies = append(pkt.Cookies, cookie)

	// Add cookie extension fields here s.t. 8 cookies are available after response.
	cookiePlaceholderData := make([]byte, len(cookie.Cookie))
	for i := len(ntskeData.Cookie); i < NumStoredCookies; i++ {
		var cookiePlacholder CookiePlaceholder
		cookiePlacholder.Cookie = cookiePlaceholderData
		pkt.CookiePlaceholders = append(pkt.CookiePlaceholders, cookiePlacholder)
	}

	var auth Authenticator
	auth.Key = ntskeData.C2sKey
	pkt.Auth = auth

	return pkt, uid.ID
}

func EncodePacket(b *[]byte, pkt *NTSPacket) {
	buf := new(bytes.Buffer)
	if len(pkt.NTPHeader) != ntpHeaderLen {
		panic("unexpected NTP header")
	}
	_, _ = buf.Write((pkt.NTPHeader))

	err := pkt.UniqueID.pack(buf)
	if err != nil {
		panic(err)
	}
	for _, c := range pkt.Cookies {
		err = c.pack(buf)
		if err != nil {
			panic(err)
		}
	}
	for _, c := range pkt.CookiePlaceholders {
		err = c.pack(buf)
		if err != nil {
			panic(err)
		}
	}
	err = pkt.Auth.pack(buf)
	if err != nil {
		panic(err)
	}

	pktlen := buf.Len()
	if cap(*b) < pktlen {
		*b = make([]byte, pktlen)
	} else {
		*b = (*b)[:pktlen]
	}

	copy((*b)[:pktlen], buf.Bytes())
}

func DecodePacket(pkt *NTSPacket, b []byte, key []byte) (err error) {
	pos := ntpHeaderLen
	msgbuf := bytes.NewReader(b[48:])
	authenticated := false
	unique := false
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
			pkt.UniqueID = u
			unique = true

		case extAuthenticator:
			a := Authenticator{ExtHdr: eh}
			err = a.unpack(msgbuf)
			if err != nil {
				return fmt.Errorf("unpack Authenticator: %s", err)
			}

			aessiv, err := miscreant.NewAEAD("AES-CMAC-SIV", key, 16)
			if err != nil {
				return err
			}

			decrytedBuf, err := aessiv.Open(nil, a.Nonce, a.CipherText, b[:pos])
			if err != nil {
				return err
			}
			pkt.Auth = a

			//ignore unauthenticated fields and only continue with decrypted
			msgbuf = bytes.NewReader(decrytedBuf)
			authenticated = true

		case extCookie:
			cookie := Cookie{ExtHdr: eh}
			err = cookie.unpack(msgbuf)
			if err != nil {
				return fmt.Errorf("unpack Cookie: %s", err)
			}
			pkt.Cookies = append(pkt.Cookies, cookie)

		case extCookiePlaceholder:
			cookie := CookiePlaceholder{ExtHdr: eh}
			err = cookie.unpack(msgbuf)
			if err != nil {
				return fmt.Errorf("unpack Cookie: %s", err)
			}
			pkt.CookiePlaceholders = append(pkt.CookiePlaceholders, cookie)

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
		return errors.New("packet does not contain a unique identifier")
	}

	return nil
}

func ExtractCookie(b []byte) ([]byte, error) {
	msgbuf := bytes.NewReader(b[48:])
	for msgbuf.Len() >= 28 {
		var eh ExtHdr
		err := eh.unpack(msgbuf)
		if err != nil {
			return nil, fmt.Errorf("unpack extension field: %s", err)
		}

		switch eh.Type {
		case extCookie:
			cookie := Cookie{ExtHdr: eh}
			err = cookie.unpack(msgbuf)
			if err != nil {
				return nil, fmt.Errorf("unpack Cookie: %s", err)
			}
			return cookie.Cookie, nil

		default:
			_, err := msgbuf.Seek(int64(eh.Length-uint16(binary.Size(eh))), io.SeekCurrent)
			if err != nil {
				return nil, err
			}
		}
	}

	return nil, errors.New("packet does not contain a cookie")
}

func ProcessResponse(ntskeFetcher *ntske.Fetcher, pkt *NTSPacket, reqID []byte) error {
	if !bytes.Equal(reqID, pkt.UniqueID.ID) {
		return errors.New("unexpected response ID")
	}
	for _, cookie := range pkt.Cookies {
		ntskeFetcher.StoreCookie(cookie.Cookie)
	}
	return nil
}

func NewResponsePacket(ntpheader []byte, cookies [][]byte, key []byte, uniqueid []byte) (pkt NTSPacket) {
	pkt.NTPHeader = ntpheader
	var uid UniqueIdentifier
	uid.ID = uniqueid
	pkt.UniqueID = uid

	buf := new(bytes.Buffer)
	for _, c := range cookies {
		var cookie Cookie
		cookie.Cookie = c
		cookie.pack(buf)
	}

	var auth Authenticator
	auth.Key = key
	auth.PlainText = buf.Bytes()
	pkt.Auth = auth

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

type UniqueIdentifier struct {
	ExtHdr
	ID []byte
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
	PlainText     []byte
	CipherText    []byte
	Key           Key
}

func (a Authenticator) pack(buf *bytes.Buffer) error {
	aessiv, err := miscreant.NewAEAD("AES-CMAC-SIV", a.Key, 16)
	if err != nil {
		return err
	}

	bits := make([]byte, 16)
	_, err = rand.Read(bits)
	if err != nil {
		return err
	}

	a.Nonce = bits

	a.CipherText = aessiv.Seal(nil, a.Nonce, a.PlainText, buf.Bytes())
	a.CipherTextLen = uint16(len(a.CipherText))

	a.NonceLen = uint16(len(a.Nonce))
	noncepadlen := (4 - a.NonceLen) % 4

	a.CipherTextLen = uint16(len(a.CipherText))
	cipherpadlen := (4 - a.CipherTextLen) % 4

	a.ExtHdr.Type = extAuthenticator
	a.ExtHdr.Length = 4 + 2 + 2 + a.NonceLen + noncepadlen + a.CipherTextLen + cipherpadlen
	err = a.ExtHdr.pack(buf)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.BigEndian, a.NonceLen)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.BigEndian, a.CipherTextLen)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.BigEndian, a.Nonce)
	if err != nil {
		return err
	}

	noncepadding := make([]byte, noncepadlen)
	err = binary.Write(buf, binary.BigEndian, noncepadding)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.BigEndian, a.CipherText)
	if err != nil {
		return err
	}

	cipherpadding := make([]byte, cipherpadlen)
	_, err = buf.Write(cipherpadding)
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

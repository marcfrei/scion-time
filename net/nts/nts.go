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

var (
	unexpectedEFHeader = errors.New("expected unpacked EF header")
)

type NTSPacket struct {
	UniqueID           UniqueIdentifier
	Cookies            []Cookie
	CookiePlaceholders []CookiePlaceholder
	Auth               Authenticator
}

func NewPacket(ntskeData ntske.Data) (pkt NTSPacket, uniqueid []byte) {
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
	if len(*b) != ntpHeaderLen {
		panic("unexpected NTP header")
	}
	pktlen := 1024
	if cap(*b) < pktlen {
		t := make([]byte, ntpHeaderLen)
		copy(t, *b)
		*b = make([]byte, pktlen)
		copy(*b, t)
	} else {
		*b = (*b)[:pktlen]
	}

	pos := ntpHeaderLen
	pos, err := pkt.UniqueID.pack(b, pos)
	if err != nil {
		panic(err)
	}
	for _, c := range pkt.Cookies {
		pos, err = c.pack(b, pos)
		if err != nil {
			panic(err)
		}
	}
	for _, c := range pkt.CookiePlaceholders {
		pos, err = c.pack(b, pos)
		if err != nil {
			panic(err)
		}
	}
	pos, err = pkt.Auth.pack(b, pos)
	if err != nil {
		panic(err)
	}
	*b = (*b)[:pos]
}

func DecodePacket(pkt *NTSPacket, b *[]byte) (err error) {
	pos := ntpHeaderLen
	authenticated := false
	unique := false

	for len(*b)-pos >= 28 {
		var eh ExtHdr
		_ = eh.unpack(b, pos)
		pos += 4

		switch eh.Type {
		case extUniqueIdentifier:
			u := UniqueIdentifier{ExtHdr: eh}
			err = u.unpack(b, pos)
			if err != nil {
				return err
			}
			pkt.UniqueID = u
			unique = true

		case extAuthenticator:
			a := Authenticator{ExtHdr: eh}
			err = a.unpack(b, pos)
			if err != nil {
				return err
			}
			a.pos = pos - 4
			pkt.Auth = a
			authenticated = true
			break

		case extCookie:
			cookie := Cookie{ExtHdr: eh}
			err = cookie.unpack(b, pos)
			if err != nil {
				return err
			}
			pkt.Cookies = append(pkt.Cookies, cookie)

		case extCookiePlaceholder:
			cookie := CookiePlaceholder{ExtHdr: eh}
			err = cookie.unpack(b, pos)
			if err != nil {
				return err
			}
			pkt.CookiePlaceholders = append(pkt.CookiePlaceholders, cookie)

		default:
			// unknown extension field
			// do nothing
		}

		pos += int(eh.Length) - 4
	}

	if !authenticated {
		return errors.New("packet does not contain an authenticator")
	}
	if !unique {
		return errors.New("packet does not contain a unique identifier")
	}

	return nil
}

func (pkt *NTSPacket) Authenticate(b *[]byte, key []byte) error {
	aessiv, err := miscreant.NewAEAD("AES-CMAC-SIV", key, 16)
	if err != nil {
		return err
	}

	decrytedBuf, err := aessiv.Open(nil, pkt.Auth.Nonce, pkt.Auth.CipherText, (*b)[:pkt.Auth.pos])
	if err != nil {
		return err
	}

	pos := 0
	for len(decrytedBuf)-pos >= 28 {
		var eh ExtHdr
		_ = eh.unpack(&decrytedBuf, pos)
		pos += 4

		switch eh.Type {
		case extCookie:
			cookie := Cookie{ExtHdr: eh}
			err = cookie.unpack(&decrytedBuf, pos)
			if err != nil {
				return err
			}
			pkt.Cookies = append(pkt.Cookies, cookie)
		}
		pos += int(eh.Length) - 4
	}

	return nil
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

func NewResponsePacket(cookies [][]byte, key []byte, uniqueid []byte) (pkt NTSPacket) {
	var uid UniqueIdentifier
	uid.ID = uniqueid
	pkt.UniqueID = uid

	lencookies := len(cookies) * (4 + len(cookies[0]))
	buf := make([]byte, lencookies)
	for _, c := range cookies {
		var cookie Cookie
		cookie.Cookie = c
		cookie.pack(&buf, 0)
	}

	var auth Authenticator
	auth.Key = key
	auth.PlainText = buf
	pkt.Auth = auth

	return pkt
}

type ExtHdr struct {
	Type   uint16
	Length uint16
}

func (h ExtHdr) pack(buf *[]byte, pos int) (int, error) {
	binary.BigEndian.PutUint16((*buf)[pos:], h.Type)
	binary.BigEndian.PutUint16((*buf)[pos+2:], h.Length)
	return pos + 4, nil
}

func (h *ExtHdr) unpack(buf *[]byte, pos int) error {
	h.Type = binary.BigEndian.Uint16((*buf)[pos:])
	h.Length = binary.BigEndian.Uint16((*buf)[pos+2:])
	return nil
}

func (h ExtHdr) Header() ExtHdr { return h }

type UniqueIdentifier struct {
	ExtHdr
	ID []byte
}

func (u UniqueIdentifier) pack(buf *[]byte, pos int) (int, error) {
	if len(u.ID) < 32 {
		return 0, errors.New("UniqueIdentifier.ID < 32 bytes")
	}

	newlen := (len(u.ID) + 3) & ^3
	padding := make([]byte, newlen-len(u.ID))

	u.ExtHdr.Type = extUniqueIdentifier
	u.ExtHdr.Length = 4 + uint16(newlen)
	pos, _ = u.ExtHdr.pack(buf, pos)

	n := copy((*buf)[pos:], u.ID)
	pos += n
	n = copy((*buf)[pos:], padding)
	pos += n

	return pos, nil
}

func (u *UniqueIdentifier) unpack(buf *[]byte, pos int) error {
	if u.ExtHdr.Type != extUniqueIdentifier {
		return unexpectedEFHeader
	}
	valueLen := u.ExtHdr.Length - uint16(binary.Size(u.ExtHdr))
	id := make([]byte, valueLen)
	copy(id, (*buf)[pos:])
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

func (c Cookie) pack(buf *[]byte, pos int) (int, error) {
	// Round up to nearest word boundary
	origlen := len(c.Cookie)
	newlen := (origlen + 3) & ^3
	padding := make([]byte, newlen-origlen)

	c.ExtHdr.Type = extCookie
	c.ExtHdr.Length = 4 + uint16(newlen)
	pos, _ = c.ExtHdr.pack(buf, pos)

	n := copy((*buf)[pos:], c.Cookie)
	pos += n
	n = copy((*buf)[pos:], padding)
	pos += n

	return pos, nil
}

func (c *Cookie) unpack(buf *[]byte, pos int) error {
	if c.ExtHdr.Type != extCookie {
		return unexpectedEFHeader
	}
	valueLen := c.ExtHdr.Length - uint16(binary.Size(c.ExtHdr))
	cookie := make([]byte, valueLen)
	copy(cookie, (*buf)[pos:])
	c.Cookie = cookie
	return nil
}

type CookiePlaceholder struct {
	ExtHdr
	Cookie []byte
}

func (c CookiePlaceholder) pack(buf *[]byte, pos int) (int, error) {
	// Round up to nearest word boundary
	origlen := len(c.Cookie)
	newlen := (origlen + 3) & ^3
	padding := make([]byte, newlen-origlen)

	c.ExtHdr.Type = extCookie
	c.ExtHdr.Length = 4 + uint16(newlen)
	pos, _ = c.ExtHdr.pack(buf, pos)

	n := copy((*buf)[pos:], c.Cookie)
	pos += n
	n = copy((*buf)[pos:], padding)
	pos += n

	return pos, nil
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
	pos           int
}

func (a Authenticator) pack(buf *[]byte, pos int) (int, error) {
	aessiv, err := miscreant.NewAEAD("AES-CMAC-SIV", a.Key, 16)
	if err != nil {
		return 0, err
	}

	bits := make([]byte, 16)
	_, err = rand.Read(bits)
	if err != nil {
		return 0, err
	}

	a.Nonce = bits

	a.CipherText = aessiv.Seal(nil, a.Nonce, a.PlainText, (*buf)[:pos])
	a.CipherTextLen = uint16(len(a.CipherText))

	a.NonceLen = uint16(len(a.Nonce))
	noncepadlen := (4 - a.NonceLen) % 4

	a.CipherTextLen = uint16(len(a.CipherText))
	cipherpadlen := (4 - a.CipherTextLen) % 4

	a.ExtHdr.Type = extAuthenticator
	a.ExtHdr.Length = 4 + 2 + 2 + a.NonceLen + noncepadlen + a.CipherTextLen + cipherpadlen
	pos, _ = a.ExtHdr.pack(buf, pos)

	binary.BigEndian.PutUint16((*buf)[pos:], a.NonceLen)
	binary.BigEndian.PutUint16((*buf)[pos+2:], a.CipherTextLen)
	pos += 4

	n := copy((*buf)[pos:], a.Nonce)
	pos += n
	noncepadding := make([]byte, noncepadlen)
	n = copy((*buf)[pos:], noncepadding)
	pos += n

	n = copy((*buf)[pos:], a.CipherText)
	pos += n
	cipherpadding := make([]byte, cipherpadlen)
	n = copy((*buf)[pos:], cipherpadding)
	pos += n

	return pos, nil
}

func (a *Authenticator) unpack(buf *[]byte, pos int) error {
	if a.ExtHdr.Type != extAuthenticator {
		return unexpectedEFHeader
	}

	a.NonceLen = binary.BigEndian.Uint16((*buf)[pos:])
	a.CipherTextLen = binary.BigEndian.Uint16((*buf)[pos+2:])
	pos += 4

	// Nonce
	nonce := make([]byte, a.NonceLen)
	n := copy(nonce, (*buf)[pos:])
	a.Nonce = nonce
	pos += n

	// Ciphertext
	ciphertext := make([]byte, a.CipherTextLen)
	copy(ciphertext, (*buf)[pos:])
	a.CipherText = ciphertext

	return nil
}

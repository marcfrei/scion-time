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
	MaxPacketLen     = 1024
	numStoredCookies = 8
	ntpPacketLen     = 48
)

const (
	extUniqueIdentifier  uint16 = 0x104
	extCookie            uint16 = 0x204
	extCookiePlaceholder uint16 = 0x304
	extAuthenticator     uint16 = 0x404
)

var (
	errNoAuthenticator      = errors.New("packet does not contain an authenticator")
	errNoCookies            = errors.New("packet does not contain cookies")
	errNoUniqueID           = errors.New("packet does not contain a unique identifier")
	errShortUniqueID        = errors.New("UniqueIdentifier.ID < 32 bytes")
	errUnexpectedExtHdrType = errors.New("unexpected extension header type")
	errUnexpectedResponseID = errors.New("unexpected response ID")
)

// A Packet contains the NTP extension fiels for a NTS secured NTP request.
type Packet struct {
	UniqueID           UniqueIdentifier
	Cookies            []Cookie
	CookiePlaceholders []CookiePlaceholder
	Auth               Authenticator
}

// NewRequestPacket returns a new Packet initialized with a new UniqueID and a Cookie from ntskeData.
func NewRequestPacket(ntskeData ntske.Data) (pkt Packet, uniqueid []byte) {
	id, err := newID()
	if err != nil {
		panic(err)
	}

	var uid UniqueIdentifier
	uid.ID = id
	pkt.UniqueID = uid

	var cookie Cookie
	cookie.Cookie = ntskeData.Cookie[0]
	pkt.Cookies = append(pkt.Cookies, cookie)

	// Add cookie extension fields here s.t. 8 cookies are available after response.
	cookiePlaceholderData := make([]byte, len(cookie.Cookie))
	for i := len(ntskeData.Cookie); i < numStoredCookies; i++ {
		var cookiePlacholder CookiePlaceholder
		cookiePlacholder.Cookie = cookiePlaceholderData
		pkt.CookiePlaceholders = append(pkt.CookiePlaceholders, cookiePlacholder)
	}

	var auth Authenticator
	auth.Key = ntskeData.C2sKey
	pkt.Auth = auth

	return pkt, id
}

// EncodePacket encodes Packet to a byte slice. It is expected that
// the first 48 bytes of the slice already contain a NTP packet.
// NTS authentication is added here.
func EncodePacket(b *[]byte, pkt *Packet) {
	if len(*b) != ntpPacketLen {
		panic("unexpected NTP header")
	}
	if cap(*b) < MaxPacketLen {
		t := make([]byte, ntpPacketLen)
		copy(t, *b)
		*b = make([]byte, MaxPacketLen)
		copy(*b, t)
	} else {
		*b = (*b)[:MaxPacketLen]
	}

	pos := ntpPacketLen
	pos, err := pkt.UniqueID.pack(*b, pos)
	if err != nil {
		panic(err)
	}
	for _, c := range pkt.Cookies {
		pos, err = c.pack(*b, pos)
		if err != nil {
			panic(err)
		}
	}
	for _, c := range pkt.CookiePlaceholders {
		pos, err = c.pack(*b, pos)
		if err != nil {
			panic(err)
		}
	}
	pos, err = pkt.Auth.pack(*b, pos)
	if err != nil {
		panic(err)
	}
	*b = (*b)[:pos]
}

// DecodePacket decodes a byte slice to Packet. Authentication is not
// checkt here, but an error is thrown if it does not contain an
// Autheticator or UniqueID extension field.
func DecodePacket(pkt *Packet, b []byte) (err error) {
	pos := ntpPacketLen
	foundUniqueID := false
	foundAuthenticator := false

	for len(b)-pos >= 28 && !foundAuthenticator {
		var eh extHdr
		eh.unpack(b, pos)
		pos += 4

		switch eh.Type {
		case extUniqueIdentifier:
			u := UniqueIdentifier{extHdr: eh}
			err = u.unpack(b, pos)
			if err != nil {
				return err
			}
			pkt.UniqueID = u
			foundUniqueID = true

		case extAuthenticator:
			a := Authenticator{extHdr: eh}
			err = a.unpack(b, pos)
			if err != nil {
				return err
			}
			a.pos = pos - 4
			pkt.Auth = a
			foundAuthenticator = true

		case extCookie:
			cookie := Cookie{extHdr: eh}
			err = cookie.unpack(b, pos)
			if err != nil {
				return err
			}
			pkt.Cookies = append(pkt.Cookies, cookie)

		case extCookiePlaceholder:
			cookie := CookiePlaceholder{extHdr: eh}
			err = cookie.unpack(b, pos)
			if err != nil {
				return err
			}
			pkt.CookiePlaceholders = append(pkt.CookiePlaceholders, cookie)

		default:
			// skip extension field
		}

		pos += int(eh.Length) - 4
	}

	if !foundUniqueID {
		return errNoUniqueID
	}
	if !foundAuthenticator {
		return errNoAuthenticator
	}

	return nil
}

// GetFirstCookie returns the first cookie byte slice a packet contains.
func (pkt *Packet) GetFirstCookie() ([]byte, error) {
	var cookie []byte
	if pkt.Cookies == nil || len(pkt.Cookies) < 1 {
		return cookie, errNoCookies
	}
	cookie = pkt.Cookies[0].Cookie
	return cookie, nil
}

// authenticate checks the authentication of a Packet using the provided key.
func (pkt *Packet) authenticate(b []byte, key []byte) error {
	aessiv, err := miscreant.NewAEAD("AES-CMAC-SIV", key, 16)
	if err != nil {
		return err
	}

	decrytedBuf, err := aessiv.Open(nil, pkt.Auth.Nonce, pkt.Auth.CipherText, b[:pkt.Auth.pos])
	if err != nil {
		return err
	}

	pos := 0
	for len(decrytedBuf)-pos >= 28 {
		var eh extHdr
		eh.unpack(decrytedBuf, pos)
		pos += 4

		switch eh.Type {
		case extCookie:
			cookie := Cookie{extHdr: eh}
			err = cookie.unpack(decrytedBuf, pos)
			if err != nil {
				return err
			}
			pkt.Cookies = append(pkt.Cookies, cookie)
		}
		pos += int(eh.Length) - 4
	}

	return nil
}

// ProcessResponse handles the response from a server. It checks that the UniqueID matches
// the one from the request and checks the authentication. Additionally it stores the cookies.
func ProcessResponse(b []byte, key []byte, ntskeFetcher *ntske.Fetcher, pkt *Packet, reqID []byte) error {
	if !bytes.Equal(reqID, pkt.UniqueID.ID) {
		return errUnexpectedResponseID
	}

	err := pkt.authenticate(b, key)
	if err != nil {
		return err
	}

	for _, cookie := range pkt.Cookies {
		ntskeFetcher.StoreCookie(cookie.Cookie)
	}
	return nil
}

// NewResponsePacket creates and returns a new Packet that should be used by
// a server for a response to a request.
func NewResponsePacket(cookies [][]byte, key []byte, uniqueid []byte) (pkt Packet) {
	var uid UniqueIdentifier
	uid.ID = uniqueid
	pkt.UniqueID = uid

	lencookies := len(cookies) * (4 + len(cookies[0]))
	buf := make([]byte, lencookies)
	var err error
	pos := 0
	for _, c := range cookies {
		var cookie Cookie
		cookie.Cookie = c
		pos, err = cookie.pack(buf, pos)
		if err != nil {
			panic(err)
		}
	}

	var auth Authenticator
	auth.Key = key
	auth.PlainText = buf
	pkt.Auth = auth

	return pkt
}

// ProcessResponse handles the request from a client.
// It checks the authentication.
func ProcessRequest(b []byte, key []byte, pkt *Packet) error {
	err := pkt.authenticate(b, key)
	if err != nil {
		return err
	}
	return nil
}

type extHdr struct {
	Type   uint16
	Length uint16
}

func (h extHdr) pack(buf []byte, pos int) int {
	binary.BigEndian.PutUint16(buf[pos:], h.Type)
	binary.BigEndian.PutUint16(buf[pos+2:], h.Length)
	return pos + 4
}

func (h *extHdr) unpack(buf []byte, pos int) {
	h.Type = binary.BigEndian.Uint16(buf[pos:])
	h.Length = binary.BigEndian.Uint16(buf[pos+2:])
}

// A UniqueIdentifier is the NTS extension that contains a
// nonce to uniquely identify a request.
type UniqueIdentifier struct {
	extHdr
	ID []byte
}

func (u UniqueIdentifier) pack(buf []byte, pos int) (int, error) {
	if len(u.ID) < 32 {
		return 0, errShortUniqueID
	}

	newlen := (len(u.ID) + 3) & ^3
	padding := make([]byte, newlen-len(u.ID))

	u.extHdr.Type = extUniqueIdentifier
	u.extHdr.Length = 4 + uint16(newlen)
	pos = u.extHdr.pack(buf, pos)

	n := copy(buf[pos:], u.ID)
	pos += n
	n = copy(buf[pos:], padding)
	pos += n

	return pos, nil
}

func (u *UniqueIdentifier) unpack(buf []byte, pos int) error {
	if u.extHdr.Type != extUniqueIdentifier {
		return errUnexpectedExtHdrType
	}
	valueLen := u.extHdr.Length - 4
	id := make([]byte, valueLen)
	copy(id, buf[pos:])
	u.ID = id
	return nil
}

func newID() ([]byte, error) {
	id := make([]byte, 32)
	_, err := rand.Read(id)
	if err != nil {
		return nil, err
	}

	return id, nil
}

// A Cookie is the NTS extension field for a NTS cookie.
// It contains a byte slice that only the server can decode
// to access the shared keys.
type Cookie struct {
	extHdr
	Cookie []byte
}

func (c Cookie) pack(buf []byte, pos int) (int, error) {
	origlen := len(c.Cookie)
	newlen := (origlen + 3) & ^3
	padding := make([]byte, newlen-origlen)

	c.extHdr.Type = extCookie
	c.extHdr.Length = 4 + uint16(newlen)
	pos = c.extHdr.pack(buf, pos)

	n := copy(buf[pos:], c.Cookie)
	pos += n
	n = copy(buf[pos:], padding)
	pos += n

	return pos, nil
}

func (c *Cookie) unpack(buf []byte, pos int) error {
	if c.extHdr.Type != extCookie {
		return errUnexpectedExtHdrType
	}
	valueLen := c.extHdr.Length - 4
	cookie := make([]byte, valueLen)
	copy(cookie, buf[pos:])
	c.Cookie = cookie
	return nil
}

// A CookiePlaceholder is the NTS extension field for a NTS cookie placeholder.
// It contains a byte slice the same length as for a Cookie. The content however
// is will be ignored and should be 0.
type CookiePlaceholder struct {
	extHdr
	Cookie []byte
}

func (c CookiePlaceholder) pack(buf []byte, pos int) (int, error) {
	origlen := len(c.Cookie)
	newlen := (origlen + 3) & ^3
	padding := make([]byte, newlen-origlen)

	c.extHdr.Type = extCookie
	c.extHdr.Length = 4 + uint16(newlen)
	pos = c.extHdr.pack(buf, pos)

	n := copy(buf[pos:], c.Cookie)
	pos += n
	n = copy(buf[pos:], padding)
	pos += n

	return pos, nil
}

func (c *CookiePlaceholder) unpack(buf []byte, pos int) error {
	if c.extHdr.Type != extCookiePlaceholder {
		return errUnexpectedExtHdrType
	}
	return nil
}

// An Authenticator is the NTS extension field for a NTS authenticator.
// It contains a nonce and authenticates the Packet using the Key.
// Additionally it can encrypt the contents of PlainText.
// pos is the position of the Authenticator in the NTP packet byte slice.
type Authenticator struct {
	extHdr
	Nonce      []byte
	CipherText []byte
	Key        []byte
	PlainText  []byte
	pos        int
}

func (a Authenticator) pack(buf []byte, pos int) (int, error) {
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
	nonceLen := uint16(len(a.Nonce))
	noncepadlen := (-nonceLen) % 4

	a.CipherText = aessiv.Seal(nil, a.Nonce, a.PlainText, buf[:pos])
	cipherTextLen := uint16(len(a.CipherText))
	cipherpadlen := (-cipherTextLen) % 4

	a.extHdr.Type = extAuthenticator
	a.extHdr.Length = 4 + 2 + 2 + nonceLen + noncepadlen + cipherTextLen + cipherpadlen
	pos = a.extHdr.pack(buf, pos)

	binary.BigEndian.PutUint16(buf[pos:], nonceLen)
	binary.BigEndian.PutUint16(buf[pos+2:], cipherTextLen)
	pos += 4

	n := copy(buf[pos:], a.Nonce)
	pos += n
	noncepadding := make([]byte, noncepadlen)
	n = copy(buf[pos:], noncepadding)
	pos += n

	n = copy(buf[pos:], a.CipherText)
	pos += n
	cipherpadding := make([]byte, cipherpadlen)
	n = copy(buf[pos:], cipherpadding)
	pos += n

	return pos, nil
}

func (a *Authenticator) unpack(buf []byte, pos int) error {
	if a.extHdr.Type != extAuthenticator {
		return errUnexpectedExtHdrType
	}

	nonceLen := binary.BigEndian.Uint16(buf[pos:])
	cipherTextLen := binary.BigEndian.Uint16(buf[pos+2:])
	pos += 4

	nonce := make([]byte, nonceLen)
	n := copy(nonce, buf[pos:])
	a.Nonce = nonce
	pos += n

	ciphertext := make([]byte, cipherTextLen)
	copy(ciphertext, buf[pos:])
	a.CipherText = ciphertext

	return nil
}

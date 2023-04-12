package ntske

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/secure-io/siv-go"
)

const (
	cookieTypeAlgorithm uint16 = 0x101
	cookieTypeKeyS2C    uint16 = 0x201
	cookieTypeKeyC2S    uint16 = 0x301

	cookieTypeKeyID      uint16 = 0x401
	cookieTypeNonce      uint16 = 0x501
	cookieTypeCiphertext uint16 = 0x601
)

var errUnexpectedCookieData = errors.New("unexpected cookie data")

type PlainCookie struct {
	Algo uint16
	S2C  []byte
	C2S  []byte
}

// Encodes cookie to byte slice with following format for each field
// uint16 | uint16 | []byte
// type   | length | value
func (c *PlainCookie) Encode() []byte {
	var cookiesize int = 3*4 + 2 + len(c.C2S) + len(c.S2C)
	b := make([]byte, cookiesize)
	binary.BigEndian.PutUint16(b[0:], cookieTypeAlgorithm)
	binary.BigEndian.PutUint16(b[2:], 0x2)
	binary.BigEndian.PutUint16(b[4:], c.Algo)
	binary.BigEndian.PutUint16(b[6:], cookieTypeKeyS2C)
	binary.BigEndian.PutUint16(b[8:], uint16(len(c.S2C)))
	copy(b[10:], c.S2C)
	pos := len(c.S2C) + 10
	binary.BigEndian.PutUint16(b[pos:], cookieTypeKeyC2S)
	binary.BigEndian.PutUint16(b[pos+2:], uint16(len(c.C2S)))
	copy(b[pos+4:], c.C2S)
	return b
}

func (c *PlainCookie) Decode(b []byte) error {
	var pos int = 0
	field_algo, field_s2c, field_c2s := false, false, false
	for pos < len(b) {
		var t uint16 = binary.BigEndian.Uint16(b[pos:])
		var len uint16 = binary.BigEndian.Uint16(b[pos+2:])
		if t == cookieTypeAlgorithm {
			c.Algo = binary.BigEndian.Uint16(b[pos+4:])
			field_algo = true
		} else if t == cookieTypeKeyS2C {
			c.S2C = b[pos+4 : pos+4+int(len)]
			field_s2c = true
		} else if t == cookieTypeKeyC2S {
			c.C2S = b[pos+4 : pos+4+int(len)]
			field_c2s = true
		}
		pos += 4 + int(len)
	}
	if pos != len(b) {
		return errUnexpectedCookieData
	}
	if !(field_algo && field_s2c && field_c2s) {
		return errUnexpectedCookieData
	}
	return nil
}

type EncryptedCookie struct {
	ID         uint16
	Nonce      []byte
	Ciphertext []byte
}

func (c *EncryptedCookie) Encode() []byte {
	var encryptedcookiesize int = 3*4 + 2 + len(c.Nonce) + len(c.Ciphertext)
	b := make([]byte, encryptedcookiesize)
	binary.BigEndian.PutUint16(b[0:], cookieTypeKeyID)
	binary.BigEndian.PutUint16(b[2:], 0x2)
	binary.BigEndian.PutUint16(b[4:], c.ID)
	binary.BigEndian.PutUint16(b[6:], cookieTypeNonce)
	binary.BigEndian.PutUint16(b[8:], uint16(len(c.Nonce)))
	copy(b[10:], c.Nonce)
	pos := len(c.Nonce) + 10
	binary.BigEndian.PutUint16(b[pos:], cookieTypeCiphertext)
	binary.BigEndian.PutUint16(b[pos+2:], uint16(len(c.Ciphertext)))
	copy(b[pos+4:], c.Ciphertext)
	return b
}

func (c *EncryptedCookie) Decode(b []byte) error {
	var pos int = 0
	field_id, field_nonce, field_ciphertext := false, false, false
	for pos < len(b) {
		var t uint16 = binary.BigEndian.Uint16(b[pos:])
		var len uint16 = binary.BigEndian.Uint16(b[pos+2:])
		if t == cookieTypeKeyID {
			c.ID = binary.BigEndian.Uint16(b[pos+4:])
			field_id = true
		} else if t == cookieTypeNonce {
			c.Nonce = b[pos+4 : pos+4+int(len)]
			field_nonce = true
		} else if t == cookieTypeCiphertext {
			c.Ciphertext = b[pos+4 : pos+4+int(len)]
			field_ciphertext = true
		}
		pos += 4 + int(len)
	}
	if pos != len(b) {
		return errUnexpectedCookieData
	}
	if !(field_id && field_nonce && field_ciphertext) {
		return errUnexpectedCookieData
	}
	return nil
}

func (c *PlainCookie) Encrypt(key []byte, keyid int) (EncryptedCookie, error) {
	bits := make([]byte, 16)
	_, err := rand.Read(bits)
	if err != nil {
		return EncryptedCookie{}, err
	}

	aessiv, err := siv.NewCMAC(key)
	if err != nil {
		return EncryptedCookie{}, err
	}

	b := c.Encode()

	var ecookie EncryptedCookie
	ecookie.ID = uint16(keyid)
	ecookie.Nonce = bits
	ecookie.Ciphertext = aessiv.Seal(nil /* dst */, ecookie.Nonce, b, nil /* additionalData */)

	return ecookie, nil
}

func (c *EncryptedCookie) Decrypt(key []byte, keyid int) (PlainCookie, error) {
	if c.ID != uint16(keyid) {
		return PlainCookie{}, errors.New("Wrong Key ID")
	}

	aessiv, err := siv.NewCMAC(key)
	if err != nil {
		return PlainCookie{}, err
	}

	b, err := aessiv.Open(nil /* dst */, c.Nonce, c.Ciphertext, nil /* additionalData */)
	if err != nil {
		return PlainCookie{}, err
	}

	var cookie PlainCookie
	err = cookie.Decode(b)
	if err != nil {
		return PlainCookie{}, err
	}
	return cookie, nil
}

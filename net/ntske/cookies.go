package ntske

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/miscreant/miscreant.go"
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

// ServerCookie is the representation of a plaintext NTS cookie.
type ServerCookie struct {
	Algo uint16
	S2C  []byte
	C2S  []byte
}

// Encode encodes the ServerCookie to a byte slice with following format for each field.
// uint16 | uint16 | []byte
// type   | length | value
func (c *ServerCookie) Encode() []byte {
	cookieLen := 3*4 + 2 + len(c.C2S) + len(c.S2C)
	b := make([]byte, cookieLen)
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

// Decode decodes a ServerCookie from a byte slice or returns an error if it can not decode.
func (c *ServerCookie) Decode(b []byte) error {
	pos := 0
	algo, s2c, c2s := false, false, false
	for pos < len(b) {
		t := binary.BigEndian.Uint16(b[pos:])
		len := binary.BigEndian.Uint16(b[pos+2:])
		if t == cookieTypeAlgorithm {
			c.Algo = binary.BigEndian.Uint16(b[pos+4:])
			algo = true
		} else if t == cookieTypeKeyS2C {
			c.S2C = b[pos+4 : pos+4+int(len)]
			s2c = true
		} else if t == cookieTypeKeyC2S {
			c.C2S = b[pos+4 : pos+4+int(len)]
			c2s = true
		}
		pos += 4 + int(len)
	}
	if pos != len(b) {
		return errUnexpectedCookieData
	}
	if !(algo && s2c && c2s) {
		return errUnexpectedCookieData
	}
	return nil
}

// EncryptedServerCookie is the representation of an encrypted NTS cookie.
type EncryptedServerCookie struct {
	ID         uint16
	Nonce      []byte
	Ciphertext []byte
}

// Encode encodes the EncryptedServerCookie to a byte slice.
func (c *EncryptedServerCookie) Encode() []byte {
	encryptedCookieLen := 3*4 + 2 + len(c.Nonce) + len(c.Ciphertext)
	b := make([]byte, encryptedCookieLen)
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

// Decode decodes an EncryptedServerCookie from a byte slice or returns an error if it can not decode.
func (c *EncryptedServerCookie) Decode(b []byte) error {
	pos := 0
	id, nonce, ciphertext := false, false, false
	for pos < len(b) {
		t := binary.BigEndian.Uint16(b[pos:])
		len := binary.BigEndian.Uint16(b[pos+2:])
		if t == cookieTypeKeyID {
			c.ID = binary.BigEndian.Uint16(b[pos+4:])
			id = true
		} else if t == cookieTypeNonce {
			c.Nonce = b[pos+4 : pos+4+int(len)]
			nonce = true
		} else if t == cookieTypeCiphertext {
			c.Ciphertext = b[pos+4 : pos+4+int(len)]
			ciphertext = true
		}
		pos += 4 + int(len)
	}
	if pos != len(b) {
		return errUnexpectedCookieData
	}
	if !(id && nonce && ciphertext) {
		return errUnexpectedCookieData
	}
	return nil
}

// EncryptWithNonce encrypts the ServerCookie using the provided key with a fresh nonce and returns an EncryptedServerCookie.
func (c *ServerCookie) EncryptWithNonce(key []byte, keyid int) (EncryptedServerCookie, error) {
	// Note: NTS cookies are right now encrypted using AES_SIV_CMAC. This however is not mandatory for NTS.
	// In case that the encryption seems to be a major bottleneck the encryption mode could be changed.

	bits := make([]byte, 16)
	_, err := rand.Read(bits)
	if err != nil {
		return EncryptedServerCookie{}, err
	}

	aessiv, err := miscreant.NewAEAD("AES-CMAC-SIV", key, 16)
	if err != nil {
		return EncryptedServerCookie{}, err
	}

	b := c.Encode()

	var ecookie EncryptedServerCookie
	ecookie.ID = uint16(keyid)
	ecookie.Nonce = bits
	ecookie.Ciphertext = aessiv.Seal(nil /* dst */, ecookie.Nonce, b, nil /* additionalData */)

	return ecookie, nil
}

// Decrypt decrypts the EncryptedServerCookie using the provided key and returns a ServerCookie.
func (c *EncryptedServerCookie) Decrypt(key []byte) (ServerCookie, error) {
	aessiv, err := miscreant.NewAEAD("AES-CMAC-SIV", key, 16)
	if err != nil {
		return ServerCookie{}, err
	}

	b, err := aessiv.Open(nil /* dst */, c.Nonce, c.Ciphertext, nil /* additionalData */)
	if err != nil {
		return ServerCookie{}, err
	}

	var cookie ServerCookie
	err = cookie.Decode(b)
	if err != nil {
		return ServerCookie{}, err
	}
	return cookie, nil
}

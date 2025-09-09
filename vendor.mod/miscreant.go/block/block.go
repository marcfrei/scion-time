// Common block cipher functionality shared across this library

package block

import (
	"crypto/cipher"
	"crypto/subtle"
)

const (
	// Size is the block size of AES.
	Size = 16
)

// Block is a 128-bit array used by certain block ciphers (i.e. AES).
type Block [Size]byte

// MultiplyByX multiplies an element in GF(2^128) by its generator.
//
// This function is incorrectly named "doubling" in section 2.3 of RFC 5297.
// Based on equivalent code in Tink Go (https://github.com/tink-crypto/tink-go)
func (b *Block) MultiplyByX() {
	z := int(b[0] >> 7)
	for i := 0; i < Size-1; i++ {
		b[i] = (b[i] << 1) | (b[i+1] >> 7)
	}
	b[Size-1] = (b[Size-1] << 1) ^ byte(subtle.ConstantTimeSelect(z, 0x87, 0x00))
}

// Encrypt encrypts a block with the given block cipher.
func (b *Block) Encrypt(c cipher.Block) {
	c.Encrypt(b[:], b[:])
}

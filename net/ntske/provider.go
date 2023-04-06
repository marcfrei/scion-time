package ntske

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"time"

	"example.com/scion-time/core/timebase"
	"golang.org/x/crypto/hkdf"
)

const (
	keyValidity        time.Duration = time.Hour * 24 * 3
	keyRenewalInterval time.Duration = time.Hour * 24
)

type Key struct {
	Id    int
	Value []byte
	Start time.Time
	End   time.Time
}

type Provider struct {
	keys        map[int]Key
	currentID   int
	hkdf        io.Reader
	lastCreated time.Time
}

func (k *Key) IsValid() bool {
	now := timebase.Now()
	if !k.Start.Before(now) || !k.End.After(now) {
		return false
	}
	return true
}

func (p *Provider) generateNext() (Key, error) {
	if p.currentID == math.MaxInt {
		panic("ID overflow")
	}
	p.currentID = p.currentID + 1
	p.lastCreated = p.lastCreated.Add(keyRenewalInterval)

	value := make([]byte, 32)
	_, err := io.ReadFull(p.hkdf, value)
	if err != nil {
		return Key{}, err
	}

	key := Key{
		Value: value,
		Id:    p.currentID,
		Start: p.lastCreated,
		End:   p.lastCreated.Add(keyValidity),
	}
	p.keys[p.currentID] = key

	return key, nil
}

func NewProvider() Provider {
	p := Provider{}
	p.currentID = 1

	key := Key{}
	value := make([]byte, 32)
	_, err := rand.Read(value)
	if err != nil {
		panic("failed to read from rand")
	}

	p.hkdf = hkdf.New(sha256.New, value, nil, nil)

	now := timebase.Now()
	year, month, day := now.Date()

	key.Value = value
	key.Id = p.currentID
	key.Start = time.Date(year, month, day, 0, 0, 0, 0, now.Location())
	key.End = key.Start.Add(keyValidity)

	p.keys = make(map[int]Key)
	p.keys[p.currentID] = key
	p.lastCreated = key.Start

	return p
}

func (p *Provider) Get(id int) (Key, error) {
	for p.lastCreated.Add(keyRenewalInterval).Before(timebase.Now()) {
		_, err := p.generateNext()
		return Key{}, err
	}
	key, ok := p.keys[id]
	if !ok {
		return Key{}, errors.New("key does not exist for given id")
	}
	if !key.IsValid() {
		return key, errors.New("key is no longer valid")
	}
	return key, nil
}

func (p *Provider) Current() (Key, error) {
	for p.lastCreated.Add(keyRenewalInterval).Before(timebase.Now()) {
		_, err := p.generateNext()
		return Key{}, err
	}
	return p.Get(p.currentID)
}

package server

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	keyValidDuration time.Duration = time.Hour * 24 * 3
	keyRenewInterval time.Duration = time.Hour * 24
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

func (k *Key) isValid() bool {
	now := time.Now()
	if !k.Start.Before(now) || !k.End.After(now) {
		return false
	}
	return true
}

func (p *Provider) generateNext() (Key, error) {
	p.currentID = p.currentID + 1
	p.lastCreated = p.lastCreated.Add(keyRenewInterval)

	key := Key{}
	value := make([]byte, 32)
	_, err := io.ReadFull(p.hkdf, value)
	if err != nil {
		return key, err
	}

	key.Value = value
	key.Id = p.currentID
	key.Start = p.lastCreated
	key.End = key.Start.Add(keyValidDuration)

	p.keys[p.currentID] = key

	return key, nil
}

func (p *Provider) Init(id int) error {
	p.currentID = id

	key := Key{}
	value := make([]byte, 32)
	_, err := rand.Read(value)
	if err != nil {
		return err
	}

	p.hkdf = hkdf.New(sha256.New, value, nil, nil)

	now := time.Now()
	year, month, day := now.Date()

	key.Value = value
	key.Id = p.currentID
	key.Start = time.Date(year, month, day, 0, 0, 0, 0, now.Location())
	key.End = key.Start.Add(keyValidDuration)

	p.keys = make(map[int]Key)
	p.keys[id] = key
	p.lastCreated = key.Start

	return nil
}

func (p *Provider) Get(id int) (key Key, err error) {
	for p.lastCreated.Add(keyRenewInterval).Before(time.Now()) {
		p.generateNext()
	}
	key, ok := p.keys[id]
	if !ok {
		return key, errors.New("key does not exist for given id")
	}
	if !key.isValid() {
		return key, errors.New("key is no longer valid")
	}
	return key, nil
}

func (p *Provider) GetNewest() (key Key, err error) {
	for p.lastCreated.Add(keyRenewInterval).Before(time.Now()) {
		p.generateNext()
	}
	return p.Get(p.currentID)
}

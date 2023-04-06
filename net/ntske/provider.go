package ntske

import (
	"crypto/rand"
	"math"
	"sync"
	"time"

	"example.com/scion-time/core/timebase"
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
	generatedAt time.Time
	lock        sync.Mutex
}

func (k *Key) IsValid() bool {
	now := timebase.Now()
	if !k.Start.Before(now) || !k.End.After(now) {
		return false
	}
	return true
}

func (p *Provider) generateNext() {
	for id, key := range p.keys {
		if !key.IsValid() {
			delete(p.keys, id)
		}
	}

	if p.currentID == math.MaxInt {
		panic("ID overflow")
	}
	p.currentID = p.currentID + 1
	p.generatedAt = timebase.Now()

	value := make([]byte, 32)
	_, err := rand.Read(value)
	if err != nil {
		panic("failed to read from rand")
	}

	key := Key{
		Value: value,
		Id:    p.currentID,
		Start: p.generatedAt,
		End:   p.generatedAt.Add(keyValidity),
	}
	p.keys[p.currentID] = key
}

func NewProvider() *Provider {
	p := &Provider{}
	p.currentID = 0
	p.keys = make(map[int]Key)
	p.generateNext()
	return p
}

func (p *Provider) Get(id int) (Key, bool) {
	p.lock.Lock()
	defer p.lock.Unlock()

	key, ok := p.keys[id]
	if !ok {
		return Key{}, false
	}
	if !key.IsValid() {
		return key, false
	}
	return key, true
}

func (p *Provider) Current() Key {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.generatedAt.Add(keyRenewalInterval).Before(timebase.Now()) {
		p.generateNext()
	}

	return p.keys[p.currentID]
}

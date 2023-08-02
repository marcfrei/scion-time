package ntske

import (
	"crypto/rand"
	"math"
	"sync"
	"time"
)

/*
This provider is set up to be used concurrently by the NTSKE and time servers.
In case they should not run on the same machine one option would be to synchronize
an initial key once at startup of the servers and then each of them will separately
create the next key each day using some key derivation function like hkdf.
*/

const (
	keyValidity        time.Duration = time.Hour * 24 * 3
	keyRenewalInterval time.Duration = time.Hour * 24
)

// Key is the key shared between NTP and NTSKE server with a validity time period.
type Key struct {
	ID       int
	Value    []byte
	Validity struct {
		NotBefore time.Time
		NotAfter  time.Time
	}
}

// Provider is a thread safe provider for keys shared between NTP and NTSKE servers.
type Provider struct {
	mu          sync.Mutex
	keys        map[int]Key
	currentID   int
	generatedAt time.Time
}

func (k *Key) IsValidAt(t time.Time) bool {
	if t.Before(k.Validity.NotBefore) || t.After(k.Validity.NotAfter) {
		return false
	}
	return true
}

func (p *Provider) generateNext() {
	tNow := time.Now()
	for id, key := range p.keys {
		if !key.IsValidAt(tNow) {
			delete(p.keys, id)
		}
	}

	if p.currentID == math.MaxInt {
		panic("ID overflow")
	}
	p.currentID = p.currentID + 1
	p.generatedAt = tNow

	value := make([]byte, 32)
	_, err := rand.Read(value)
	if err != nil {
		panic("failed to read from rand")
	}

	key := Key{
		Value: value,
		ID:    p.currentID,
	}
	key.Validity.NotBefore = p.generatedAt
	key.Validity.NotAfter = p.generatedAt.Add(keyValidity)

	p.keys[p.currentID] = key
}

// Creates and returns a new provider.
func NewProvider() *Provider {
	p := &Provider{}
	p.keys = make(map[int]Key)
	p.generateNext()
	return p
}

// Get() returns the Key with ID id and true if it exists and is still valid or false otherwise.
func (p *Provider) Get(id int) (Key, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key, ok := p.keys[id]
	if !ok {
		return Key{}, false
	}
	if !key.IsValidAt(time.Now()) {
		return Key{}, false
	}
	return key, true
}

// Current() returns the newest Key or creates a new one if no one is valid.
func (p *Provider) Current() Key {
	p.mu.Lock()
	defer p.mu.Unlock()

	tNow := time.Now()
	if key := p.keys[p.currentID]; !key.IsValidAt(tNow) || p.generatedAt.Add(keyRenewalInterval).Before(tNow) {
		p.generateNext()
	}

	return p.keys[p.currentID]
}

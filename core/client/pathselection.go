package client

import (
	crand "crypto/rand"
	mrand "math/rand/v2"
	"sync"

	"github.com/scionproto/scion/pkg/snet"
)

var rng struct {
	gen *mrand.Rand
	mu  sync.Mutex
}

func init() {
	var seed [32]byte
	n, err := crand.Read(seed[:])
	if err != nil || n != len(seed) {
		panic("secure random seed generation failed")
	}
	// ChaCha8 is a ChaCha8-based cryptographically strong random number generator.
	// See https://pkg.go.dev/math/rand/v2#ChaCha8
	src := mrand.NewChaCha8(seed)
	rng.gen = mrand.New(src) // #nosec G404
}

func randIntN(n int) int {
	rng.mu.Lock()
	defer rng.mu.Unlock()
	return rng.gen.IntN(n)
}

func SelectPaths(ps []snet.Path, k int) []snet.Path {
	if k < 0 {
		panic("invalid argument: k must be non-negative")
	}

	candidates := append([]snet.Path(nil), ps...)
	if len(candidates) <= k {
		return candidates
	}
	selected := make([]snet.Path, 0, k)

	covered := make(map[snet.PathInterface]struct{})

	for len(selected) < k && len(candidates) > 0 {
		selIdx := -1
		selPathLen := -1
		selNewCount := -1
		tieCount := 0

		for i, p := range candidates {
			ifaces := p.Metadata().Interfaces
			pathLen := len(ifaces)
			newCount := 0
			for _, iface := range ifaces {
				if _, ok := covered[iface]; !ok {
					newCount++
				}
			}

			pick := false
			if len(selected) == 0 {
				// First pick: shortest path, break ties randomly.
				if selIdx == -1 || pathLen < selPathLen {
					pick = true
					tieCount = 1
				} else if pathLen == selPathLen {
					tieCount++
					pick = randIntN(tieCount) == 0
				}
			} else {
				// Subsequent picks: max new coverage, break ties by shorter path then randomly.
				if newCount > selNewCount {
					pick = true
					tieCount = 1
				} else if newCount == selNewCount {
					if pathLen < selPathLen {
						pick = true
						tieCount = 1
					} else if pathLen == selPathLen {
						tieCount++
						pick = randIntN(tieCount) == 0
					}
				}
			}
			if pick {
				selIdx = i
				selPathLen = pathLen
				selNewCount = newCount
			}
		}

		p := candidates[selIdx]
		selected = append(selected, p)
		for _, iface := range p.Metadata().Interfaces {
			covered[iface] = struct{}{}
		}
		candidates[selIdx] = candidates[len(candidates)-1]
		candidates = candidates[:len(candidates)-1]
	}

	return selected
}

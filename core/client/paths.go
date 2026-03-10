package client

import (
	crand "crypto/rand"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"

	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

var rng struct {
	gen *rand.Rand
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
	src := rand.NewChaCha8(seed)
	rng.gen = rand.New(src) // #nosec G404
}

func randIntN(n int) int {
	rng.mu.Lock()
	defer rng.mu.Unlock()
	return rng.gen.IntN(n)
}

func pathIsEmpty(p snet.Path) bool {
	switch pp := p.(type) {
	case nil:
		return false
	case path.Path:
		switch pp.DataplanePath.(type) {
		case path.Empty, *path.Empty:
			return true
		default:
			return false
		}
	case *path.Path:
		if pp == nil {
			return false
		}
		switch pp.DataplanePath.(type) {
		case path.Empty, *path.Empty:
			return true
		default:
			return false
		}
	default:
		switch p.Dataplane().(type) {
		case path.Empty, *path.Empty:
			return true
		default:
			return false
		}
	}
}

func pathInterfaces(p snet.Path) []snet.PathInterface {
	if p == nil {
		return nil
	}
	if pp, ok := p.(path.Path); ok {
		return pp.Meta.Interfaces
	}
	if pp, ok := p.(*path.Path); ok {
		if pp == nil {
			return nil
		}
		return pp.Meta.Interfaces
	}
	md := p.Metadata()
	if md != nil {
		return md.Interfaces
	}
	return nil
}

func SelectPaths(ps []snet.Path, k int, preselected ...snet.Path) []snet.Path {
	if k < 0 {
		panic("invalid argument: k must be non-negative")
	}

	numPreselected := 0
	for _, p := range preselected {
		if p == nil {
			continue
		}
		numPreselected++
	}
	numCandidates := 0
	for i, p := range ps {
		if p == nil {
			panic(fmt.Sprintf("unexpected candidate path (ps[%d]=%v", i, p))
		}
		numCandidates++
	}
	numPaths := numPreselected + numCandidates

	candidates := append([]snet.Path(nil), ps...)
	selected := make([]snet.Path, 0, min(k, len(candidates)))

	coveredIfaces := make(map[snet.PathInterface]int)
	numSelected := 0
	for _, p := range preselected {
		if p == nil {
			continue
		}
		ifaces := pathInterfaces(p)
		pathLen := len(ifaces)
		if pathLen < 2 && (!pathIsEmpty(p) || numPaths != 1) {
			panic(fmt.Sprintf("unexpected path (type=%T, ifaces=%d)", p, pathLen))
		}
		for _, iface := range ifaces {
			coveredIfaces[iface]++
		}
		numSelected++
	}

	for len(selected) < k && len(candidates) > 0 {
		selIdx := -1
		selPathLen := 0
		selScore := 0.0
		tieCount := 0

		for i, p := range candidates {
			ifaces := pathInterfaces(p)
			pathLen := len(ifaces)
			if pathLen < 2 && (!pathIsEmpty(p) || numPaths != 1) {
				panic(fmt.Sprintf("unexpected path (type=%T, ifaces=%d)", p, pathLen))
			}

			pick := false
			if numSelected == 0 {
				// First pick: shortest path, break ties randomly.
				if selIdx == -1 || pathLen < selPathLen {
					pick = true
					tieCount = 1
				} else if pathLen == selPathLen {
					tieCount++
					pick = randIntN(tieCount) == 0
				}
				if pick {
					selIdx = i
					selPathLen = pathLen
				}
			} else {
				// Subsequent picks: maximize score and break ties randomly.
				const pathLengthPenalty = 0.5
				const pathOverlapPenalty = 0.25
				const scoreEps = 1e-9
				pathCoverage := 0
				pathOverlap := 0
				for _, iface := range ifaces {
					c := coveredIfaces[iface]
					if c == 0 {
						pathCoverage++
					}
					pathOverlap += c
				}
				score := float64(pathCoverage) -
					pathLengthPenalty*float64(pathLen) -
					pathOverlapPenalty*float64(pathOverlap)
				if selIdx == -1 || score > selScore+scoreEps {
					pick = true
					tieCount = 1
				} else if math.Abs(score-selScore) <= scoreEps {
					tieCount++
					pick = randIntN(tieCount) == 0
				}
				if pick {
					selIdx = i
					selScore = score
				}
			}
		}

		p := candidates[selIdx]
		for _, iface := range pathInterfaces(p) {
			coveredIfaces[iface]++
		}
		selected = append(selected, p)
		numSelected++
		candidates[selIdx] = candidates[len(candidates)-1]
		candidates = candidates[:len(candidates)-1]
	}

	return selected
}

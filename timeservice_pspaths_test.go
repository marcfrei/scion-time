package main

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"

	"example.com/scion-time/core/client"
)

// testScanPath builds a path 1-ff00:0:1#1 -> 1-ff00:0:m#1, #e -> 1-ff00:0:9#d
// with error e (ns) and n picks.
func testScanPath(m, eg, d int, e float64) *scanPath {
	src, dst := addr.MustParseIA("1-ff00:0:1"), addr.MustParseIA("1-ff00:0:9")
	mid := addr.MustParseIA("1-ff00:0:" + string(rune('a'+m)))
	ifaces := []snet.PathInterface{
		{IA: src, ID: 1}, {IA: mid, ID: 1},
		{IA: mid, ID: iface.ID(eg)}, {IA: dst, ID: iface.ID(d)},
	}
	p := path.Path{Src: src, Dst: dst, Meta: snet.PathMetadata{Interfaces: ifaces}}
	const n = 100
	return &scanPath{fp: client.PathFingerprint(p), p: p, ifaces: ifaces,
		n: n, sum: n * e, sum2: n * (e*e + 1e6)}
}

func testOpts() quickScanOptions {
	return quickScanOptions{tol: 250 * time.Nanosecond, tolRel: 0.25, minPool: 10, remain: 5}
}

func TestBatches(t *testing.T) {
	var ps []*scanPath
	for i := range 16 {
		ps = append(ps, &scanPath{id: i})
	}
	bs := batches(ps, 7)
	if len(bs) != 3 {
		t.Fatalf("got %d batches, want 3", len(bs))
	}
	seen := map[*scanPath]bool{}
	for _, b := range bs {
		if len(b) != 7 {
			t.Fatalf("batch of %d paths, want 7", len(b))
		}
		for i, sp := range b {
			if slices.Contains(b[:i], sp) {
				t.Fatalf("path %d twice in a batch", sp.id)
			}
			seen[sp] = true
		}
	}
	if len(seen) != 16 {
		t.Fatalf("%d paths measured, want 16", len(seen))
	}
	if bs := batches(ps[:3], 7); len(bs) != 1 || len(bs[0]) != 3 {
		t.Fatalf("batches of 3 paths = %v", bs)
	}
}

func TestReplaceScionPaths(t *testing.T) {
	pool := []*scanPath{testScanPath(0, 2, 1, 1000), testScanPath(1, 3, 2, -2000)}
	block := scionPathsBlock(pool, nil, 1500, "scan.csv")
	want := []string{pool[0].fp, pool[1].fp}

	base := "local_address = \"1-ff00:0:1,[127.0.0.1]:10123\"\n# keep me\nfilter_size = 64\n"
	old := base + "# preselectpaths: written earlier\nscion_paths = [\n  \"aa\", # e +1.00 us, x\n  \"bb\",\n]\nsync_clock = \"/dev/ptp0\"\n"
	oneLine := base + "scion_paths = [\"aa\", \"bb\"] # hand-written\nsync_clock = \"/dev/ptp0\"\n"
	for name, content := range map[string]string{"append": base, "replace": old, "one line": oneLine, "no newline": strings.TrimSuffix(base, "\n")} {
		updated := replaceScionPaths(content, block)
		var cfg svcConfig
		err := toml.NewDecoder(bytes.NewReader([]byte(updated))).DisallowUnknownFields().Decode(&cfg)
		if err != nil {
			t.Fatalf("%s: updated config does not load: %v\n%s", name, err, updated)
		}
		if !slices.Equal(cfg.SCIONPaths, want) {
			t.Fatalf("%s: scion_paths = %v, want %v", name, cfg.SCIONPaths, want)
		}
		if !strings.Contains(updated, "# keep me\n") || strings.Count(updated, "scion_paths") != 1 ||
			strings.Contains(updated, "written earlier") {
			t.Fatalf("%s: unexpected content:\n%s", name, updated)
		}
		if strings.Contains(content, "sync_clock") && cfg.SyncClock != "/dev/ptp0" {
			t.Fatalf("%s: lost sync_clock:\n%s", name, updated)
		}
	}
}

func TestCutoff(t *testing.T) {
	var similar, steep []*scanPath
	for i := range 40 {
		e := 200 * math.Sin(float64(i))
		similar = append(similar, testScanPath(i%5, 2+i/5, 1+i%3, e))
		if i >= 8 {
			e = 10000
		}
		steep = append(steep, testScanPath(i%5, 2+i/5, 1+i%3, e))
	}
	sortAbs := func(ps []*scanPath) {
		slices.SortFunc(ps, func(a, b *scanPath) int { return cmpFloat(absMean(a), absMean(b)) })
	}
	sortAbs(similar)
	sortAbs(steep)
	if n, _, _ := cutoff(similar, 7, testOpts(), absMean); n != len(similar) {
		t.Errorf("similar paths: pool of %d, want all %d", n, len(similar))
	}
	if n, _, _ := cutoff(steep, 7, testOpts(), absMean); n > 12 {
		t.Errorf("steep: pool of %d, want at most 12", n)
	}
	if n, _, _ := cutoff(similar[:8], 7, testOpts(), absMean); n != 8 {
		t.Errorf("fewer paths than the minimum pool: %d, want 8", n)
	}
}

func TestResilience(t *testing.T) {
	// All pool paths leave the middle AS through interface 2; candidates use 3.
	var pool, cands []*scanPath
	for i := range 6 {
		pool = append(pool, testScanPath(0, 2, 1+i%3, float64(i)))
		cands = append(cands, testScanPath(0, 3, 1+i%3, float64(100+i)))
	}
	added, weak := resilience(pool, cands, 5, absMean)
	if len(added) != 5 {
		t.Fatalf("added %d paths, want 5", len(added))
	}
	for _, sp := range added {
		if sp.ifaces[2].ID != 3 {
			t.Fatalf("added path %v does not avoid interface 2", sp.ifaces)
		}
	}
	if len(weak) != 0 {
		t.Fatalf("weak interfaces %v, want none", weak)
	}
	if got := shared(append(pool, cands...)); len(got) != 2 {
		t.Fatalf("shared interfaces %v, want the two of the first hop", got)
	}
}

// withBins gives sp the last-stage statistics of 18 bins of 20 picks with a
// noise of 5 µs per pick, the bin means oscillating by amp (ns) around e.
func withBins(sp *scanPath, e, amp float64) *scanPath {
	sp.bins = map[int64]*scanBin{}
	sp.n, sp.sum, sp.sum2 = 0, 0, 0
	for k := range 18 {
		m := e + amp*math.Sin(2*math.Pi*float64(k)/19)
		b := &scanBin{n: 20, sum: 20 * m, sum2: 20 * (m*m + 25e6)}
		sp.bins[int64(k)] = b
		sp.n += b.n
		sp.sum += b.sum
		sp.sum2 += b.sum2
	}
	return sp
}

// TestSelectPoolQualityFirst: 10 stable paths through one middle AS and 6
// oscillating ones through another. The resilience rule must not add the
// oscillating paths to get around the first AS; the pool's dependence on it is
// reported as a single point of failure instead.
func TestSelectPoolQualityFirst(t *testing.T) {
	var in []*scanPath
	for i := range 10 {
		in = append(in, withBins(testScanPath(0, 2+i, 1+i%3, 0), 600*math.Sin(float64(i)), 0))
	}
	for i := range 6 {
		in = append(in, withBins(testScanPath(1, 2+i, 1+i%3, 0), 300, 4500))
	}
	if v := in[10].variation(); v < 2500 || in[0].variation() != 0 {
		t.Fatalf("variation %.2f us (oscillating), %.2f us (stable)", v/1e3, in[0].variation()/1e3)
	}
	pool, added, _ := selectPool(in, 7, testOpts())
	if len(pool) != 10 || len(added) != 0 {
		t.Fatalf("pool of %d paths, %d added; want the 10 stable ones", len(pool), len(added))
	}
	for _, sp := range pool {
		if sp.ifaces[1].IA != in[0].ifaces[1].IA {
			t.Fatalf("oscillating path in the pool: %s", hops(sp.ifaces))
		}
	}
	if mid := in[0].ifaces[1]; !slices.Contains(shared(pool), mid) {
		t.Fatalf("single points of failure %v, want %v among them", shared(pool), mid)
	}
}

func TestHelpers(t *testing.T) {
	if !disturbed([]float64{25e3, 30e3, 21e3, -1e3}) || disturbed([]float64{25e3, -30e3, 21e3, -1e3}) ||
		disturbed([]float64{25e3, 30e3, 21e3}) {
		t.Error("disturbed")
	}
	t0 := time.Now()
	cts := []ctsSample{{t0, 1000}, {t0.Add(time.Second), 3000}}
	if c, ok := interpCTS(cts, t0.Add(500*time.Millisecond)); !ok || c != 2000 {
		t.Errorf("interpCTS = %v %v, want 2µs", c, ok)
	}
	if _, ok := interpCTS(cts, t0.Add(2*time.Second)); ok {
		t.Error("interpCTS beyond the last sample")
	}
	if m := median([]float64{3, 1, 2, 10}); m != 2.5 {
		t.Errorf("median = %v", m)
	}
	sp := testScanPath(2, 7, 4, 0)
	if h := hops(sp.ifaces); h != "1-ff00:0:1 1>1 1-ff00:0:c 7>4 1-ff00:0:9" {
		t.Errorf("hops = %q", h)
	}
}

// TestQuickScanPipeline feeds synthetic picks and CTS samples through the
// stages: 10 symmetric stable paths, 5 paths that are symmetric on average but
// oscillate by ±4.5 µs with a period of 570 s (as Thun's uplink 2), 15
// asymmetric and 10 strongly asymmetric paths, a CTS offset that moves with
// the clock, and one disturbed round.
func TestQuickScanPipeline(t *testing.T) {
	q := &quickScan{log: slog.Default(), k: 7, w: bufio.NewWriter(io.Discard), paths: map[string]*scanPath{}}
	rng := rand.New(rand.NewPCG(1, 2))
	truth := map[string]float64{}
	phase := map[string]float64{} // oscillating paths only
	for i := range 40 {
		e := 800 * math.Sin(float64(i)) // ns
		switch {
		case i >= 25:
			e = math.Copysign(150000, e)
		case i >= 15:
			e = math.Copysign(20000+500*float64(i), e)
		}
		sp := testScanPath(i%5, 2+i/5, 1+i%3, 0)
		sp.n, sp.sum, sp.sum2, sp.id = 0, 0, 0, i
		q.paths[sp.fp] = sp
		q.order = append(q.order, sp)
		truth[sp.fp] = e
		if i >= 10 && i < 15 {
			phase[sp.fp] = 2 * math.Pi * rng.Float64()
		}
	}
	errAt := func(fp string, tm time.Duration) float64 {
		e := truth[fp]
		if ph, ok := phase[fp]; ok {
			e += 4500 * math.Sin(2*math.Pi*tm.Seconds()/570+ph)
		}
		return e
	}
	clockOff := func(tm time.Duration) float64 { return 3000 * math.Sin(tm.Seconds()/60) } // clock error, ns
	t0 := time.Now()
	tick := 0 * time.Second
	addCTS := func(until time.Duration) {
		for ; tick <= until; tick += time.Second {
			q.cts = append(q.cts, ctsSample{t: t0.Add(tick), off: time.Duration(clockOff(tick))})
		}
	}
	now := time.Duration(0)
	disturbedRound := true
	opts := testOpts()
	for si, st := range quickScanStages {
		if si == len(quickScanStages)-1 {
			for _, sp := range q.inRace() {
				sp.resetStats()
			}
		}
		for _, b := range batches(q.inRace(), q.k) {
			q.dwell++
			for range int(st.dwell / (1410 * time.Millisecond)) {
				q.round++
				q.stageRounds++
				q.hitRounds++
				now += 1410 * time.Millisecond
				extra := 0.0
				if disturbedRound && si == 1 {
					extra, disturbedRound = 50000, false
				}
				for _, sp := range b {
					sp.rounds++
					off := errAt(sp.fp, now) + clockOff(now) + 5000*rng.NormFloat64() + extra
					q.pending = append(q.pending, scanPick{t: t0.Add(now), fp: sp.fp, round: q.round,
						dwell: q.dwell, off: time.Duration(off), ok: true})
				}
				addCTS(now + time.Second)
				q.process()
				if q.err != nil {
					t.Fatal(q.err)
				}
			}
		}
		q.eliminate(si, st.cap, opts)
	}
	if q.discarded != 1 {
		t.Errorf("%d rounds discarded, want 1", q.discarded)
	}
	in := q.inRace()
	stable, osc := 0, 0
	for _, sp := range in {
		switch _, ok := phase[sp.fp]; {
		case ok:
			osc++
			if v := sp.variation(); v < 2000 {
				t.Errorf("oscillating path: variation %.2f us, want more than 2 us", v/1e3)
			}
		case math.Abs(truth[sp.fp]) < 10000:
			stable++
			if v := sp.variation(); v > 1500 {
				t.Errorf("stable path: variation %.2f us, want less than 1.5 us", v/1e3)
			}
			if d := sp.mean() - truth[sp.fp]; math.Abs(d) > 4*sp.se() {
				t.Errorf("path estimate off by %.2f us (se %.2f us)", d/1e3, sp.se()/1e3)
			}
		}
		if math.Abs(truth[sp.fp]) > 100000 {
			t.Errorf("strongly asymmetric path with e %.1f us still in the race", truth[sp.fp]/1e3)
		}
	}
	if stable != 10 || osc == 0 || len(in) > 21 {
		t.Errorf("%d paths in the last stage, %d stable symmetric, %d oscillating; want all 10 stable ones, some oscillating ones, at most 21", len(in), stable, osc)
	}
	pool, added, _ := selectPool(in, q.k, opts)
	if len(added) != 0 {
		t.Errorf("%d paths added for resilience, want none", len(added))
	}
	for _, sp := range pool {
		if _, ok := phase[sp.fp]; ok || math.Abs(truth[sp.fp]) > 10000 {
			t.Errorf("pool contains a path with e %.1f us and variation %.1f us", sp.mean()/1e3, sp.variation()/1e3)
		}
	}
	if len(pool) != 10 {
		t.Errorf("pool of %d paths, want the 10 stable symmetric ones", len(pool))
	}
}

// TestSurveyProcess checks that the survey writes every pick at once, also
// after the CTS offsets stopped, and neither keeps statistics nor fails, while
// the quick scan waits for CTS samples and fails without them.
func TestSurveyProcess(t *testing.T) {
	for _, survey := range []bool{true, false} {
		var buf bytes.Buffer
		q := &quickScan{log: slog.Default(), k: 7, survey: survey, w: bufio.NewWriter(&buf), paths: map[string]*scanPath{}}
		sp := testScanPath(0, 2, 1, 0)
		sp.n, sp.sum, sp.sum2 = 0, 0, 0
		q.paths[sp.fp] = sp
		q.order = append(q.order, sp)
		t0 := time.Now().Add(-time.Minute)
		q.cts = []ctsSample{{t: t0, off: 0}, {t: t0.Add(time.Second), off: 0}}
		for i := range 5 {
			q.pending = append(q.pending, scanPick{t: t0.Add(time.Duration(i) * time.Second), fp: sp.fp,
				round: i + 1, dwell: 1, off: 1000, ok: true})
		}
		q.process()
		if err := q.w.Flush(); err != nil {
			t.Fatal(err)
		}
		m := strings.Count(buf.String(), "m,")
		switch {
		case survey && (m != 5 || len(q.pending) != 0 || sp.n != 0 || q.err != nil):
			t.Errorf("survey: %d picks written, %d pending, %d in the statistics, error %v; want 5, 0, 0, none",
				m, len(q.pending), sp.n, q.err)
		case !survey && (m != 1 || len(q.pending) != 4 || q.err == nil):
			t.Errorf("quick scan: %d picks written, %d pending, error %v; want 1, 4 and an error",
				m, len(q.pending), q.err)
		}
	}
}

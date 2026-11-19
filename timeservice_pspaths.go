// Quick path scan: measures all SCION paths to the server in batches, ranks
// them by their error against GNSS and selects a path pool for scion_paths.
// The survey measures all paths in rotation for days, only to record them.
// See doc/path-scan-design-2026-11-16.md.

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	gosync "sync"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/scionproto/scion/pkg/snet"

	"example.com/scion-time/base/logbase"
	"example.com/scion-time/core/client"
	"example.com/scion-time/core/server"
	"example.com/scion-time/core/sync"
	"example.com/scion-time/driver/clocks"
	"example.com/scion-time/service"
)

const (
	quickScanZ           = 3.0    // standard errors for optimistic and pessimistic |e|
	quickScanMinSigma    = 3000.0 // ns, σ floor while picks are few
	quickScanTau         = 2000.0 // ns, drift of a path's error between short windows, stages 1 and 2
	quickScanBin         = 30 * time.Second
	quickScanRefRank     = 20      // elimination reference: path max(20, provisional pool)
	quickScanDisturbance = 20000.0 // ns, common deviation that discards a round
	quickScanMaxDiscard  = 0.02    // share of discarded rounds that aborts the scan
	quickScanMaxLoss     = 0.05    // per path after stage 1, and rounds without any pick
	quickScanMaxDrift    = 5000.0  // ns of CTS change within 10 s (0.5 ppm)
	quickScanTestStep    = 100 * time.Microsecond
	quickScanTestTol     = 5000.0 // ns
	quickScanTestDwell   = 30 * time.Second
	quickScanDraws       = 100
	quickScanMarker      = "# preselectpaths:"
)

// Stages 1 and 2 select up to 21 finalists by their mean error. The last stage
// measures each batch of finalists continuously for 9 minutes, long enough to
// see errors that vary over minutes (Thun's uplink 2 oscillated with a period
// of 9.5 minutes, 2026-11-17), and decides the pool on its own data, without
// the selection bias of the earlier stages.
var quickScanStages = []struct {
	dwell time.Duration
	cap   int // paths kept after the stage, by |e|; 0 for no cap
}{
	{20 * time.Second, 0},
	{45 * time.Second, 21},
	{9 * time.Minute, 0},
}

type quickScanOptions struct {
	out      string
	update   bool
	tol      time.Duration
	tolRel   float64
	maxErr   time.Duration
	minPool  int
	remain   int
	survey   bool
	dwell    time.Duration
	duration time.Duration
}

type scanPath struct {
	id        int
	fp        string
	p         snet.Path
	ifaces    []snet.PathInterface
	n         int                // picks in the statistics
	sum, sum2 float64            // of e in ns
	windows   int                // dwells in the statistics
	bins      map[int64]*scanBin // 30 s bins of e in the last stage
	rounds    int                // rounds in which the path was scheduled
	hits      int                // accepted picks, including the discarded first pick per dwell
	rejected  int                // picks rejected by the RTD gate
	dwell     int                // last dwell with an accepted pick
	out       string             // why the path left the race, "" while in it
}

type scanBin struct {
	n         int
	sum, sum2 float64
}

func (sp *scanPath) mean() float64 { return sp.sum / float64(sp.n) }

func (sp *scanPath) sigma() float64 {
	if sp.n < 2 {
		return 0
	}
	m := sp.mean()
	return math.Sqrt(max(sp.sum2/float64(sp.n)-m*m, 0) * float64(sp.n) / float64(sp.n-1))
}

// se is the standard error of the mean error. In the last stage it comes from
// the 30 s bins and so includes any variation over time; before, it combines
// the noise of the picks with an assumed drift between short windows.
func (sp *scanPath) se() float64 {
	if means, _ := sp.binStats(); len(means) >= 3 {
		return math.Sqrt(sampleVar(means) / float64(len(means)))
	}
	s := max(sp.sigma(), quickScanMinSigma)
	return math.Sqrt(s*s/float64(sp.n) + quickScanTau*quickScanTau/float64(max(sp.windows, 1)))
}

// binStats returns the means of the 30 s bins with at least 5 picks and the
// variances of these means due to noise.
func (sp *scanPath) binStats() (means, noise []float64) {
	for _, b := range sp.bins {
		if b.n < 5 {
			continue
		}
		m := b.sum / float64(b.n)
		means = append(means, m)
		noise = append(noise, max(b.sum2/float64(b.n)-m*m, quickScanMinSigma*quickScanMinSigma)/float64(b.n))
	}
	return
}

// variation is the variation of the error over the last stage beyond noise.
func (sp *scanPath) variation() float64 {
	means, noise := sp.binStats()
	if len(means) < 3 {
		return 0
	}
	var w float64
	for _, x := range noise {
		w += x
	}
	return math.Sqrt(max(sampleVar(means)-w/float64(len(noise)), 0))
}

// score is the path's error over time, the root of its mean squared error:
// accuracy and stability.
func (sp *scanPath) score() float64 { return math.Hypot(sp.mean(), sp.variation()) }

func (sp *scanPath) resetStats() {
	sp.n, sp.sum, sp.sum2, sp.windows = 0, 0, 0, 0
	sp.bins = map[int64]*scanBin{}
}

func sampleVar(x []float64) float64 {
	var m, v float64
	for _, y := range x {
		m += y
	}
	m /= float64(len(x))
	for _, y := range x {
		v += (y - m) * (y - m)
	}
	return v / float64(len(x)-1)
}

func (sp *scanPath) loss() float64 {
	if sp.rounds == 0 {
		return 1
	}
	return 1 - float64(min(sp.hits, sp.rounds))/float64(sp.rounds)
}

type scanPick struct {
	t          time.Time
	fp         string
	round      int
	dwell      int
	off        time.Duration
	rtd, floor time.Duration
	ok         bool
}

type ctsSample struct {
	t   time.Time
	off time.Duration
}

type quickScan struct {
	log      *slog.Logger
	clk      *ntpReferenceClockSCION
	clock    *clocks.AdjustableClock
	adj      *sync.PIController
	interval time.Duration
	timeout  time.Duration
	k        int
	survey   bool

	configFile string
	scanFile   string

	mu          gosync.Mutex
	w           *bufio.Writer
	cts         []ctsSample
	steer       bool
	lastStep    time.Time
	pending     []scanPick
	round       int
	dwell       int
	testing     bool
	testPicks   []scanPick
	stageRounds int // rounds measured in the stages
	hitRounds   int // of which with at least one accepted pick
	lastHit     int

	paths     map[string]*scanPath
	order     []*scanPath
	processed int
	discarded int
	err       error
}

func runQuickScan(configFile string, opts quickScanOptions) {
	ctx := context.Background()
	log := slog.Default()

	cfg := loadConfig(configFile)
	if cfg.NTLCTSOff == "" {
		logbase.Fatal(log, "quick scan requires ntl_ctsoff")
	}
	localAddr := localAddress(cfg)
	checkClocks(log, cfg, localAddr, false /* server */)
	refClocks, _ := createClocks(cfg, localAddr, log)
	var clk *ntpReferenceClockSCION
	for _, c := range refClocks {
		if sc, ok := c.(*ntpReferenceClockSCION); ok {
			if clk != nil {
				logbase.Fatal(log, "quick scan requires exactly one SCION reference clock")
			}
			clk = sc
		}
	}
	if clk == nil || clk.pather == nil || clk.remoteAddr.IA == clk.localAddr.IA {
		logbase.Fatal(log, "quick scan requires a SCION reference clock in another AS")
	}
	if dispatcherMode(cfg) == dispatcherModeInternal {
		server.StartSCIONDispatcher(ctx, log, snet.CopyUDPAddr(localAddr.Host))
	}

	syncCfg := syncConfig(cfg)
	kp, ki := piControllerConfig(cfg)
	clock := clocks.NewAdjustableClock(log, cfg.SyncClock)
	q := &quickScan{
		log:      log,
		clk:      clk,
		clock:    clock,
		adj:      &sync.PIController{Clock: clock, KP: kp, KI: ki, StepThreshold: sync.PIControllerDefaultStepThreshold},
		interval: syncCfg.SyncInterval,
		timeout:  syncCfg.SyncTimeout,
		k:        len(clk.ntpcs),
		survey:   opts.survey,
		paths:    map[string]*scanPath{},

		configFile: configFile,
	}

	name := "quick path scan"
	if opts.survey {
		name = "path survey"
	}
	out := opts.out
	if out == "" {
		out = "path-quickscan-"
		if opts.survey {
			out = "path-survey-"
		}
		out += time.Now().UTC().Format("20060102T150405Z") + ".csv"
	}
	f, err := os.Create(out) // #nosec G304
	if err != nil {
		logbase.Fatal(log, "failed to create scan file", slog.String("file", out), slog.Any("error", err))
	}
	q.w = bufio.NewWriter(f)
	q.scanFile = out

	q.addPaths()
	if !opts.survey && len(q.order) < opts.minPool {
		logbase.Fatal(log, "too few paths to the server", slog.Int("paths", len(q.order)))
	}
	log.LogAttrs(ctx, slog.LevelInfo, "starting "+name,
		slog.Int("paths", len(q.order)), slog.String("file", out))

	for _, c := range clk.ntpcs {
		c.Filter.OnPick = func(off, rtd, floor time.Duration, ok bool) {
			pk := scanPick{t: time.Now(), fp: c.Path(), off: off, rtd: rtd, floor: floor, ok: ok}
			q.mu.Lock()
			pk.round, pk.dwell = q.round, q.dwell
			q.pending = append(q.pending, pk)
			if ok && !q.testing && q.lastHit != q.round {
				q.lastHit = q.round
				q.hitRounds++
			}
			q.mu.Unlock()
		}
	}
	service.StartNTLCTSOff(log, cfg.NTLCTSOff, q.ctsSink)

	if opts.survey {
		err = q.runSurvey(opts.dwell, opts.duration)
	} else {
		err = q.run(opts)
	}
	q.mu.Lock()
	ferr := errors.Join(q.w.Flush(), f.Close())
	q.mu.Unlock()
	if err == nil {
		err = ferr
	}
	if err != nil {
		logbase.Fatal(log, name+" failed, configuration unchanged", slog.Any("error", err))
	}
	log.LogAttrs(ctx, slog.LevelInfo, name+" done")
}

// addPaths adds the paths to the server that are not known yet.
func (q *quickScan) addPaths() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, p := range q.clk.pather.Paths(q.clk.remoteAddr.IA) {
		fp := client.PathFingerprint(p)
		if q.paths[fp] != nil {
			continue
		}
		sp := &scanPath{id: len(q.order), fp: fp, p: p, ifaces: client.PathInterfaces(p)}
		q.paths[fp] = sp
		q.order = append(q.order, sp)
		q.writef("p,%d,%s,%s\n", sp.id, fp, hops(sp.ifaces))
	}
}

// start runs the self-test, then steps the clock to GNSS and holds it there.
func (q *quickScan) start() error {
	time.Sleep(3 * time.Second)
	q.mu.Lock()
	n := len(q.cts)
	q.mu.Unlock()
	if n == 0 {
		return errors.New("no NTL CTS offset samples")
	}

	// The self-test uses the shortest paths, which most likely work.
	order := slices.Clone(q.order)
	rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	slices.SortStableFunc(order, func(a, b *scanPath) int { return len(a.ifaces) - len(b.ifaces) })
	if err := q.selfTest(order[:min(q.k, len(order))]); err != nil {
		return err
	}

	// Align the clock with GNSS, using a CTS sample taken after the self-test
	// stepped the clock back, then hold it there for the rest of the scan.
	var off time.Duration
	for i := 0; ; i++ {
		q.mu.Lock()
		s := q.cts[len(q.cts)-1]
		fresh := s.t.After(q.lastStep)
		q.mu.Unlock()
		if fresh {
			off = s.off
			break
		}
		if i == 50 {
			return errors.New("no NTL CTS offset sample after the self-test")
		}
		time.Sleep(100 * time.Millisecond)
	}
	q.stepClock(off)
	q.mu.Lock()
	q.steer = true
	q.mu.Unlock()
	return nil
}

func (q *quickScan) run(opts quickScanOptions) error {
	if err := q.start(); err != nil {
		return err
	}

	for si, st := range quickScanStages {
		cands := q.inRace()
		if si == len(quickScanStages)-1 {
			for _, sp := range cands {
				sp.resetStats()
			}
		}
		q.mu.Lock()
		q.writef("s,%d,%d,%d\n", time.Now().UnixNano(), si+1, int(st.dwell.Seconds()))
		q.mu.Unlock()
		start := time.Now()
		rand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
		for _, b := range batches(cands, q.k) {
			if err := q.measure(b, st.dwell); err != nil {
				return err
			}
		}
		time.Sleep(2 * time.Second)
		q.process()
		if q.err != nil {
			return q.err
		}
		q.eliminate(si, st.cap, opts)
		q.log.LogAttrs(context.Background(), slog.LevelInfo, "quick path scan stage done",
			slog.Int("stage", si+1), slog.Int("paths", len(cands)),
			slog.Int("remaining", len(q.inRace())), slog.Duration("duration", time.Since(start)))
	}
	return q.finish(opts)
}

// runSurvey measures all paths in cycles until the duration has passed. Each
// cycle shuffles the paths into batches and measures each batch for one dwell.
// The survey only records: it keeps no statistics and stops for nothing but a
// failed self-test or a write error, so that a server outage or a gap in the
// CTS offsets costs only the data of that time.
func (q *quickScan) runSurvey(dwell, duration time.Duration) error {
	if err := q.start(); err != nil {
		return err
	}
	end := time.Now().Add(duration)
	for cycle := 1; time.Now().Before(end); cycle++ {
		q.addPaths()
		ps := slices.Clone(q.order)
		rand.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
		q.mu.Lock()
		q.writef("s,%d,%d,%d\n", time.Now().UnixNano(), cycle, int(dwell.Seconds()))
		q.mu.Unlock()
		for _, b := range batches(ps, q.k) {
			d := min(dwell, time.Until(end))
			if d <= 0 {
				break
			}
			if err := q.measure(b, d); err != nil {
				return err
			}
		}
		q.log.LogAttrs(context.Background(), slog.LevelInfo, "path survey cycle done",
			slog.Int("cycle", cycle), slog.Int("paths", len(ps)))
	}
	time.Sleep(2 * time.Second)
	q.process()
	return nil
}

// writef writes to the scan file. The bufio.Writer keeps the first write
// error and returns it from Flush, which is checked.
func (q *quickScan) writef(format string, a ...any) {
	_, _ = fmt.Fprintf(q.w, format, a...)
}

func (q *quickScan) ctsSink(off time.Duration) {
	now := time.Now()
	q.mu.Lock()
	q.cts = append(q.cts, ctsSample{t: now, off: off})
	if len(q.cts) > 180 {
		q.cts = slices.Delete(q.cts, 0, len(q.cts)-180)
	}
	q.writef("r,%d,%d\n", now.UnixNano(), off.Nanoseconds())
	steer := q.steer
	q.mu.Unlock()
	if steer {
		q.adj.Do(off)
	}
}

func (q *quickScan) stepClock(off time.Duration) {
	q.clock.Step(off)
	q.mu.Lock()
	q.lastStep = time.Now()
	q.mu.Unlock()
}

// measure runs rounds on a batch of paths for one dwell.
func (q *quickScan) measure(b []*scanPath, d time.Duration) error {
	q.mu.Lock()
	q.dwell++
	q.writef("b,%d", time.Now().UnixNano())
	for _, sp := range b {
		q.writef(",%d", sp.id)
	}
	q.writef("\n")
	q.mu.Unlock()
	ia := q.clk.remoteAddr.IA
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		cur := map[string]snet.Path{}
		for _, p := range q.clk.pather.Paths(ia) {
			cur[client.PathFingerprint(p)] = p
		}
		q.mu.Lock()
		q.round++
		testing := q.testing
		if !testing {
			q.stageRounds++
		}
		q.writef("n,%d\n", time.Now().UnixNano())
		q.mu.Unlock()
		var ps []snet.Path
		for _, sp := range b {
			if !testing {
				sp.rounds++
			}
			if p, ok := cur[sp.fp]; ok {
				sp.p = p
				ps = append(ps, p)
			}
		}
		if len(ps) != 0 {
			ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
			_, _, _ = client.MeasureClockOffsetSCION(ctx, q.log, q.clk.ntpcs[:],
				q.clk.localAddr, q.clk.remoteAddr, q.clk.publicIP, ps)
			cancel()
		}
		q.process()
		if q.err != nil {
			return q.err
		}
		q.mu.Lock()
		err := q.w.Flush()
		unreachable := !q.survey && q.stageRounds >= 50 && 2*q.hitRounds < q.stageRounds
		q.mu.Unlock()
		if err != nil {
			return err
		}
		if unreachable {
			return errors.New("server unreachable: more than half of the rounds without any measurement")
		}
		time.Sleep(q.interval)
	}
	return nil
}

// process evaluates the picks that have CTS samples on both sides.
func (q *quickScan) process() {
	q.mu.Lock()
	if len(q.cts) < 2 {
		q.mu.Unlock()
		return
	}
	cts := slices.Clone(q.cts)
	last := cts[len(cts)-1].t
	var ready, rest []scanPick
	for _, pk := range q.pending {
		if pk.t.Before(last) || q.survey {
			ready = append(ready, pk)
		} else {
			rest = append(rest, pk)
		}
	}
	q.pending = rest
	for _, pk := range ready {
		sp := q.paths[pk.fp]
		if sp == nil {
			continue
		}
		ok := 0
		if pk.ok {
			ok = 1
		}
		q.writef("m,%d,%d,%d,%d,%d,%d\n", pk.t.UnixNano(), sp.id,
			pk.off.Nanoseconds(), pk.rtd.Nanoseconds(), pk.floor.Nanoseconds(), ok)
	}
	testing, lastStep, steer := q.testing, q.lastStep, q.steer
	if testing {
		q.testPicks = append(q.testPicks, ready...)
	}
	q.mu.Unlock()
	if q.survey && !testing {
		return
	}

	if time.Since(last) > 5*time.Second {
		q.err = errors.New("NTL CTS offset samples stopped")
		return
	}
	if steer && time.Since(lastStep) > 15*time.Second {
		for i := len(cts) - 1; i >= 0; i-- {
			if dt := last.Sub(cts[i].t); dt >= 10*time.Second {
				if math.Abs(float64(cts[len(cts)-1].off-cts[i].off)) > quickScanMaxDrift*dt.Seconds()/10 {
					q.err = errors.New("clock not held on GNSS: CTS offset drifts by more than 0.5 ppm")
					return
				}
				break
			}
		}
	}
	if testing {
		return
	}

	type entry struct {
		sp *scanPath
		pk scanPick
		e  float64
	}
	var rounds [][]entry
	idx := map[int]int{}
	for _, pk := range ready {
		sp := q.paths[pk.fp]
		if sp == nil {
			continue
		}
		if !pk.ok {
			sp.rejected++
			continue
		}
		sp.hits++
		if pk.t.Sub(lastStep).Abs() < 2*time.Second {
			continue
		}
		c, ok := interpCTS(cts, pk.t)
		if !ok {
			continue
		}
		i, ok := idx[pk.round]
		if !ok {
			i = len(rounds)
			idx[pk.round] = i
			rounds = append(rounds, nil)
		}
		rounds[i] = append(rounds[i], entry{sp: sp, pk: pk, e: float64(pk.off - c)})
	}
	for _, r := range rounds {
		q.processed++
		var dev []float64
		for _, x := range r {
			if x.sp.n >= 5 {
				dev = append(dev, x.e-x.sp.mean())
			}
		}
		if disturbed(dev) {
			q.discarded++
			continue
		}
		for _, x := range r {
			if x.sp.dwell != x.pk.dwell {
				x.sp.dwell = x.pk.dwell // first pick of the dwell
				x.sp.windows++
				continue
			}
			x.sp.n++
			x.sp.sum += x.e
			x.sp.sum2 += x.e * x.e
			if x.sp.bins != nil {
				k := x.pk.t.UnixNano() / int64(quickScanBin)
				b := x.sp.bins[k]
				if b == nil {
					b = &scanBin{}
					x.sp.bins[k] = b
				}
				b.n++
				b.sum += x.e
				b.sum2 += x.e * x.e
			}
		}
	}
	if q.processed >= 50 && float64(q.discarded) > quickScanMaxDiscard*float64(q.processed) {
		q.err = fmt.Errorf("server or local disturbance: %d of %d rounds discarded", q.discarded, q.processed)
	}
}

// disturbed reports whether most picks of a round deviate from their paths'
// means by more than quickScanDisturbance in the same direction.
func disturbed(dev []float64) bool {
	if len(dev) < 4 {
		return false
	}
	var up, down int
	for _, d := range dev {
		if d > quickScanDisturbance {
			up++
		} else if d < -quickScanDisturbance {
			down++
		}
	}
	return 3*up >= 2*len(dev) || 3*down >= 2*len(dev)
}

func interpCTS(cts []ctsSample, t time.Time) (time.Duration, bool) {
	for i := len(cts) - 1; i > 0; i-- {
		a, b := cts[i-1], cts[i]
		if !t.Before(a.t) && t.Before(b.t) {
			f := float64(t.Sub(a.t)) / float64(b.t.Sub(a.t))
			return a.off + time.Duration(f*float64(b.off-a.off)), true
		}
	}
	return 0, false
}

// selfTest steps the clock and checks that the measured offsets and the CTS
// offset move alike: the CTS must compare the clock that timestamps the
// packets, with the sign of the measured offsets.
func (q *quickScan) selfTest(b []*scanPath) error {
	q.mu.Lock()
	q.testing = true
	q.mu.Unlock()
	defer func() {
		q.mu.Lock()
		q.testing = false
		q.testPicks = nil
		q.mu.Unlock()
	}()

	window := func() (offs map[string][]float64, c float64, t0, t1 time.Time, slope float64, err error) {
		start := time.Now()
		if err = q.measure(b, quickScanTestDwell); err != nil {
			return
		}
		time.Sleep(2 * time.Second)
		q.process()
		end := time.Now()
		q.mu.Lock()
		offs = map[string][]float64{}
		for _, pk := range q.testPicks {
			if pk.ok && pk.t.After(start.Add(2*time.Second)) {
				offs[pk.fp] = append(offs[pk.fp], float64(pk.off))
			}
		}
		q.testPicks = nil
		var cs []ctsSample
		for _, s := range q.cts {
			if s.t.After(start.Add(2*time.Second)) && s.t.Before(end) {
				cs = append(cs, s)
			}
		}
		q.mu.Unlock()
		if len(cs) < 10 {
			err = errors.New("self-test: too few CTS samples")
			return
		}
		for _, s := range cs {
			c += float64(s.off)
		}
		c /= float64(len(cs))
		t0, t1 = cs[0].t, cs[len(cs)-1].t
		slope = float64(cs[len(cs)-1].off-cs[0].off) / float64(t1.Sub(t0))
		return
	}

	o1, c1, a0, a1, slope, err := window()
	if err != nil {
		return err
	}
	q.stepClock(quickScanTestStep)
	o2, c2, b0, b1, _, err := window()
	q.stepClock(-quickScanTestStep)
	if err != nil {
		return err
	}
	var dm []float64
	for fp, x := range o1 {
		if y := o2[fp]; len(x) >= 5 && len(y) >= 5 {
			dm = append(dm, median(y)-median(x))
		}
	}
	if len(dm) < 3 {
		return errors.New("self-test: too few paths measured; is the timeservice client still running?")
	}
	dOff := median(dm)
	drift := slope * float64(b0.Add(b1.Sub(b0)/2).Sub(a0.Add(a1.Sub(a0)/2)))
	dCTS := c2 - c1
	step := -float64(quickScanTestStep)
	q.log.LogAttrs(context.Background(), slog.LevelInfo, "quick path scan self-test",
		slog.Float64("offset change [us]", dOff/1e3), slog.Float64("CTS change [us]", dCTS/1e3),
		slog.Float64("drift [us]", drift/1e3))
	if math.Abs(dOff-dCTS) > quickScanTestTol || math.Abs(dCTS-drift-step) > quickScanTestTol {
		return fmt.Errorf("self-test failed: a clock step of %v changed the measured offsets by %.1f us and the CTS offset by %.1f us (drift %.1f us); check ntl_ctsoff",
			quickScanTestStep, dOff/1e3, dCTS/1e3, drift/1e3)
	}
	return nil
}

func median(x []float64) float64 {
	y := slices.Clone(x)
	slices.Sort(y)
	n := len(y)
	if n%2 == 1 {
		return y[n/2]
	}
	return (y[n/2-1] + y[n/2]) / 2
}

func (q *quickScan) inRace() []*scanPath {
	var r []*scanPath
	for _, sp := range q.order {
		if sp.out == "" {
			r = append(r, sp)
		}
	}
	return r
}

// batches splits paths into batches of k; a short last batch is topped up
// with paths from the start, so that k paths are measured at a time.
func batches(ps []*scanPath, k int) [][]*scanPath {
	var bs [][]*scanPath
	for i := 0; i < len(ps); i += k {
		b := slices.Clone(ps[i:min(i+k, len(ps))])
		for _, sp := range ps {
			if len(b) == k {
				break
			}
			if !slices.Contains(b, sp) {
				b = append(b, sp)
			}
		}
		bs = append(bs, b)
	}
	return bs
}

func absMean(sp *scanPath) float64 { return math.Abs(sp.mean()) }

func (q *quickScan) eliminate(si, limit int, opts quickScanOptions) {
	for _, sp := range q.inRace() {
		switch {
		case sp.n == 0:
			sp.out = "no data"
		case si == 0 && 2*sp.hits < sp.rounds-1:
			sp.out = "loss"
		case si > 0 && sp.loss() > quickScanMaxLoss:
			sp.out = "loss"
		}
	}
	if si == len(quickScanStages)-1 {
		return // the pool is decided by finish, on the scores
	}
	in := q.inRace()
	if len(in) == 0 {
		return
	}
	var bound float64
	if opts.maxErr > 0 {
		bound = float64(opts.maxErr)
	} else {
		slices.SortFunc(in, func(a, b *scanPath) int { return cmpFloat(absMean(a), absMean(b)) })
		n, _, _ := cutoff(in, q.k, opts, absMean)
		var u []float64
		for _, sp := range in {
			u = append(u, absMean(sp)+quickScanZ*sp.se())
		}
		slices.Sort(u)
		bound = u[min(max(quickScanRefRank, n), len(u))-1]
	}
	for _, sp := range in {
		if absMean(sp)-quickScanZ*sp.se() > bound {
			sp.out = "worse"
		}
	}
	if limit == 0 {
		return
	}
	in = q.inRace()
	slices.SortFunc(in, func(a, b *scanPath) int {
		return cmpFloat(absMean(a), absMean(b))
	})
	if len(in) <= limit {
		return
	}
	kept, capped := in[:limit], in[limit:]
	added, _ := resilience(kept, capped, opts.remain, absMean)
	for _, sp := range capped {
		if !slices.Contains(added, sp) {
			sp.out = "cap"
		}
	}
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// expectedError estimates how far from symmetric and stable the paths are
// that the runtime path selection uses with a pool: the root mean square of
// err over the k paths that SelectPaths picks, averaged over its random
// tie-breaks. Unlike the FTM of the client, or a signed mean, this neither
// masks bad paths nor lets opposite errors cancel, so the FTM's fault
// tolerance remains for faults at runtime; and unlike a plain mean, a single
// bad path among good ones counts by its square, not by a seventh.
func expectedError(pool []*scanPath, k int, err func(*scanPath) float64) float64 {
	ps := make([]snet.Path, len(pool))
	est := map[string]float64{}
	for i, sp := range pool {
		ps[i] = sp.p
		est[sp.fp] = err(sp)
	}
	var sum float64
	for range quickScanDraws {
		sel := client.SelectPaths(ps, k)
		var e float64
		for _, p := range sel {
			x := est[client.PathFingerprint(p)]
			e += x * x
		}
		sum += math.Sqrt(e / float64(len(sel)))
	}
	return sum / quickScanDraws
}

// cutoff returns the size of the largest pool, taken from paths sorted by
// err, whose expected error is within the tolerance of the best size, and that
// best expected error and the tolerance.
func cutoff(sorted []*scanPath, k int, opts quickScanOptions, err func(*scanPath) float64) (n int, best, tol float64) {
	if len(sorted) <= opts.minPool {
		return len(sorted), 0, 0
	}
	e := make([]float64, len(sorted)+1)
	best = math.Inf(1)
	for n := opts.minPool; n <= len(sorted); n++ {
		e[n] = expectedError(sorted[:n], k, err)
		best = min(best, e[n])
	}
	tol = max(float64(opts.tol), opts.tolRel*best)
	for n := len(sorted); n > opts.minPool; n-- {
		if e[n] <= best+tol {
			return n, best, tol
		}
	}
	return opts.minPool, best, tol
}

// shared returns the interfaces used by all paths.
func shared(ps []*scanPath) []snet.PathInterface {
	if len(ps) == 0 {
		return nil
	}
	var r []snet.PathInterface
	for _, x := range ps[0].ifaces {
		all := true
		for _, sp := range ps[1:] {
			if !slices.Contains(sp.ifaces, x) {
				all = false
				break
			}
		}
		if all {
			r = append(r, x)
		}
	}
	return r
}

// resilience adds paths from cands (best first) until, for every interface
// not shared by all paths, at least remain pool paths avoid it. It returns
// the added paths and the interfaces for which that is not possible.
func resilience(pool, cands []*scanPath, remain int, err func(*scanPath) float64) (added []*scanPath, weak []snet.PathInterface) {
	all := append(slices.Clone(pool), cands...)
	common := shared(all)
	cands = slices.Clone(cands)
	slices.SortFunc(cands, func(a, b *scanPath) int { return cmpFloat(err(a), err(b)) })
	for {
		var ifaces []snet.PathInterface
		for _, sp := range append(slices.Clone(pool), added...) {
			for _, x := range sp.ifaces {
				if !slices.Contains(ifaces, x) && !slices.Contains(common, x) && !slices.Contains(weak, x) {
					ifaces = append(ifaces, x)
				}
			}
		}
		changed := false
		for _, x := range ifaces {
			avoid := 0
			for _, sp := range append(slices.Clone(pool), added...) {
				if !slices.Contains(sp.ifaces, x) {
					avoid++
				}
			}
			if avoid >= remain {
				continue
			}
			i := slices.IndexFunc(cands, func(sp *scanPath) bool {
				return !slices.Contains(sp.ifaces, x) && !slices.Contains(added, sp)
			})
			if i < 0 {
				weak = append(weak, x)
			} else {
				added = append(added, cands[i])
			}
			changed = true
			break
		}
		if !changed {
			return added, weak
		}
	}
}

func hops(ifaces []snet.PathInterface) string {
	if len(ifaces) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(ifaces[0].IA.String())
	for i := 0; i+1 < len(ifaces); i += 2 {
		fmt.Fprintf(&b, " %d>%d %s", ifaces[i].ID, ifaces[i+1].ID, ifaces[i+1].IA)
	}
	return b.String()
}

// selectPool decides the pool from the paths measured in the last stage, by
// their scores: the cutoff, or the fixed bound -max-error, then a ceiling per
// path, then the resilience rule, which may only add paths below the ceiling:
// accuracy and stability come before resilience.
func selectPool(in []*scanPath, k int, opts quickScanOptions) (pool, added []*scanPath, weak []snet.PathInterface) {
	score := func(sp *scanPath) float64 { return sp.score() }
	in = slices.Clone(in)
	slices.SortFunc(in, func(a, b *scanPath) int { return cmpFloat(a.score(), b.score()) })
	var n int
	var ceiling float64
	if opts.maxErr > 0 {
		ceiling = float64(opts.maxErr)
		n = slices.IndexFunc(in, func(sp *scanPath) bool { return sp.score() > ceiling })
		if n < 0 {
			n = len(in)
		}
		n = min(max(n, opts.minPool), len(in))
	} else {
		var best, tol float64
		n, best, tol = cutoff(in, k, opts, score)
		// The expected error of the pool dilutes a single bad path among the
		// k picked ones; each path must itself be similarly good.
		ceiling = best + 2*tol
		if best == 0 {
			ceiling = math.Inf(1) // too few paths for a cutoff
		}
		for n > opts.minPool && in[n-1].score() > ceiling {
			n--
		}
	}
	pool = slices.Clone(in[:n])
	var cands []*scanPath
	for _, sp := range in[n:] {
		if sp.score() <= ceiling {
			cands = append(cands, sp)
		}
	}
	added, weak = resilience(pool, cands, opts.remain, score)
	return append(pool, added...), added, weak
}

func (q *quickScan) finish(opts quickScanOptions) error {
	if q.stageRounds > 0 && 1-float64(q.hitRounds)/float64(q.stageRounds) > quickScanMaxLoss {
		return fmt.Errorf("%d of %d rounds without any measurement", q.stageRounds-q.hitRounds, q.stageRounds)
	}
	in := q.inRace()
	if len(in) < opts.minPool {
		return fmt.Errorf("only %d paths qualify, fewer than %d", len(in), opts.minPool)
	}
	pool, added, weak := selectPool(in, q.k, opts)
	slices.SortFunc(in, func(a, b *scanPath) int { return cmpFloat(a.score(), b.score()) })
	ee := expectedError(pool, q.k, func(sp *scanPath) float64 { return sp.score() })
	spof := shared(pool)

	q.report(in, pool, added, weak, spof, ee)
	block := scionPathsBlock(pool, spof, ee, q.scanFile)
	fmt.Println()
	fmt.Print(block)
	if opts.update {
		return q.updateConfig(block, pool)
	}
	return nil
}

func (q *quickScan) report(in, pool, added []*scanPath, weak, spof []snet.PathInterface, ee float64) {
	fmt.Printf("%-10s %9s %6s %6s %6s %6s %6s %6s %6s  %-6s %s\n",
		"path", "e [us]", "var", "score", "se", "sigma", "picks", "loss", "rej", "status", "hops")
	for _, sp := range in {
		status := ""
		if slices.Contains(pool, sp) {
			status = "pool"
			if slices.Contains(added, sp) {
				status = "pool+"
			}
		}
		fmt.Printf("%-10s %+9.2f %6.2f %6.2f %6.2f %6.2f %6d %5.1f%% %5.1f%%  %-6s %s\n",
			sp.fp[:8], sp.mean()/1e3, sp.variation()/1e3, sp.score()/1e3, sp.se()/1e3, sp.sigma()/1e3, sp.n,
			100*sp.loss(), 100*float64(sp.rejected)/float64(max(sp.hits+sp.rejected, 1)), status, hops(sp.ifaces))
	}
	out := map[string]int{}
	for _, sp := range q.order {
		if sp.out != "" {
			out[sp.out]++
		}
	}
	fmt.Printf("\npaths: %d scanned, %d measured to the end, %d in the pool (%d added for resilience); left the race: %v\n",
		len(q.order), len(in), len(pool), len(added), out)
	fmt.Printf("expected error of the paths in use (score: |e| and variation over time): %.2f us\n", ee/1e3)
	fmt.Printf("rounds: %d evaluated, %d discarded as disturbed\n", q.processed, q.discarded)
	fmt.Printf("single points of failure of the pool: %s\n", ifaceList(spof))
	if len(weak) != 0 {
		fmt.Printf("interfaces without enough good paths around them (-remain): %s\n", ifaceList(weak))
	}
}

func ifaceList(ifaces []snet.PathInterface) string {
	if len(ifaces) == 0 {
		return "none"
	}
	var s []string
	for _, x := range ifaces {
		s = append(s, x.String())
	}
	return strings.Join(s, " ")
}

func scionPathsBlock(pool []*scanPath, spof []snet.PathInterface, ee float64, scanFile string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s written %s by \"timeservice preselectpaths -quick\" from %s\n",
		quickScanMarker, time.Now().UTC().Format(time.RFC3339), scanFile)
	fmt.Fprintf(&b, "%s pool of %d paths, expected error %.2f us, single points of failure: %s\n",
		quickScanMarker, len(pool), ee/1e3, ifaceList(spof))
	b.WriteString("scion_paths = [\n")
	for _, sp := range pool {
		fmt.Fprintf(&b, "  %q, # e %+.2f us, var %.2f us, %s\n", sp.fp, sp.mean()/1e3, sp.variation()/1e3, hops(sp.ifaces))
	}
	b.WriteString("]\n")
	return b.String()
}

// replaceScionPaths replaces the scion_paths block of a config, together with
// the marker comments before it, or appends the block if there is none.
func replaceScionPaths(content, block string) string {
	lines := strings.SplitAfter(content, "\n")
	start := -1
	for i, l := range lines {
		k, _, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok && strings.TrimSpace(k) == "scion_paths" {
			start = i
			break
		}
	}
	if start < 0 {
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		return content + "\n" + block
	}
	end := start
	for end < len(lines) {
		v, _, _ := strings.Cut(lines[end], "#")
		if strings.Contains(v, "]") {
			break
		}
		end++
	}
	for start > 0 && strings.HasPrefix(strings.TrimSpace(lines[start-1]), quickScanMarker) {
		start--
	}
	return strings.Join(lines[:start], "") + block + strings.Join(lines[min(end+1, len(lines)):], "")
}

func (q *quickScan) updateConfig(block string, pool []*scanPath) error {
	file := q.configFile
	st, err := os.Stat(file)
	if err != nil {
		return err
	}
	old, err := os.ReadFile(file) // #nosec G304
	if err != nil {
		return err
	}
	updated := replaceScionPaths(string(old), block)
	var cfg svcConfig
	err = toml.NewDecoder(bytes.NewReader([]byte(updated))).DisallowUnknownFields().Decode(&cfg)
	if err != nil {
		return fmt.Errorf("updated configuration does not load: %w", err)
	}
	var fps []string
	for _, sp := range pool {
		fps = append(fps, sp.fp)
	}
	if !slices.Equal(cfg.SCIONPaths, fps) {
		return errors.New("updated configuration does not contain the pool")
	}
	// #nosec G703 -- the config file is given on the command line
	if err := os.WriteFile(file+".prev", old, st.Mode().Perm()); err != nil {
		return err
	}
	// #nosec G703 -- the config file is given on the command line
	if err := os.WriteFile(file+".tmp", []byte(updated), st.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Rename(file+".tmp", file); err != nil {
		return err
	}
	q.log.LogAttrs(context.Background(), slog.LevelInfo, "configuration updated",
		slog.String("file", file), slog.Int("paths", len(pool)))
	return nil
}

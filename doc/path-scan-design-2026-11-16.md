# Path scan and selection against GNSS

- **Date:** November 16, 2026
- **Status:** design proposal, not implemented
- **Revision:** `a0b691c` (branch `pilot-sync-accuracy`)

At a site with a GNSS reference, a quick scan measures all SCION paths to the server in about 30 minutes, in batches of 7, ranks them by their error against GNSS and writes a path pool into the client configuration. Within that pool the existing path selection keeps doing what it does now: it picks 7 diverse paths, keeps them, and replaces failing ones from the pool. The scan runs as a maintenance task, when a new site is set up, weekly, and promptly after the client detects a route change. A week-long scan mode checks pools across weekday cycles.

Everything is Go and lives in the `timeservice` binary:

| Part | Where | What |
|---|---|---|
| Scan | `timeservice client`, config keys `scion_path_scan` and `scion_path_scan_dwell` | Rotates batches of 7 paths every 60 s and records each path's lucky packet per round together with the GNSS comparison. |
| Ranking | new subcommand `timeservice preselectpaths -scan FILE` | Offline: per-path error statistics, pool selection with resilience constraints, expected clock error, config line. |
| Quick scan | `timeservice preselectpaths -config FILE -quick` | Live, with the client stopped: narrows ~200 paths to a pool whose size follows from the measurements, in 30–60 minutes. |
| Survey | `timeservice preselectpaths -config FILE -survey` | Live, with the client stopped: measures all paths in rotation for days and only records them, for an analysis of the paths themselves. |
| Pool | `timeservice client`, config key `scion_paths` | Restricts the candidates of the existing path selection to the pool. |
| Rescan trigger | `timeservice client`, systemd timer and path unit | Requests a quick scan after a route change; runs it weekly otherwise. |

## Facts this design builds on

- **7 clients, interleaved, HW timestamps.** The client has 7 `SCIONClient`s (`scionRefClockNumClient`, [`timeservice.go`](../timeservice.go)), each with its own lucky-packet filter and interleaved state. The scan reuses them unchanged, so it measures exactly like production. The batch size is therefore 7.
- **A path switch is clean.** When a client gets a new path, it resets its filter (including the RTD-gate history) and its interleaved state ([`client_scion.go`](../core/client/client_scion.go), at `pathFingerprint != c.prev.path`). The first exchange on the new path is basic mode, all later ones are interleaved.
- **Rounds** come every ~1.41 s at Thun (1 s `sync_interval` plus up to 0.4 s sampling). Each round, each path contributes one lucky packet: the minimum-RTD exchange of its burst, gated by `filter_max_rtd_excess` against the 10th percentile of its picks in the last 5 min.
- **The path list** comes from the pather, refreshed every 15 s, without a cap ([`pather.go`](../net/scion/pather.go)).
- **Per-path error against GNSS** is e = measured offset − NTL CTS offset. This is the convention of `pilot/analysis/run11/pbins.py`. Run 11 confirms it: after the Nov 10 reroute, each path's e was flat while Thun's clock ramped by 8 µs. Because e does not depend on the clock, the scan may keep steering the clock while it measures.

## Dwell time

A dwell is the time a batch stays on its 7 paths. Per-path noise per round was measured at Thun in run 11 (Nov 10, 08:00–15:00 UTC, e per round after removing hourly means):

| Path | σ per round | SD of 30 s mean | SD of 60 s mean | SD of 120 s mean |
|---|---|---|---|---|
| d8218c56 | 4.4 µs | 0.93 µs | 0.67 µs | 0.47 µs |
| 20d7ed1a | 5.1 µs | 1.10 µs | 0.79 µs | 0.56 µs |
| 8ed94266 | 6.3 µs | 1.34 µs | 0.93 µs | 0.62 µs |
| dc338458 | 7.2 µs | 1.59 µs | 1.16 µs | 0.80 µs |
| 0418e1c8 | 11.2 µs | 2.49 µs | 1.79 µs | 1.21 µs |
| 4af6df81 | 12.3 µs | 2.60 µs | 1.87 µs | 1.29 µs |
| a467ac8e | 13.1 µs | 2.81 µs | 1.95 µs | 1.42 µs |

- **The noise is white.** Block means follow σ/√n up to 120 s. At 300 s, one path (dc338458) starts to show slower variation.
- **So the dwell length does not set the precision.** Each path is measured 7/n of the time whatever the dwell, so its hourly mean has the same precision with 30 s or 60 s dwells: about 0.15–0.45 µs with 20 candidates.
- **No warm-up transient is visible.** Over 63 path starts in runs 8, 9 and 11, rounds 1–10 after a path's first appearance deviate by −0.4 to +1.8 µs from its later mean, at a standard error of ~1.3 µs per round. The scan discards each path's first pick per dwell anyway, and `preselectpaths` repeats this check on the scan itself, with thousands of dwells.

**Recommendation: 60 s.** The first-pick discard then costs 2.4 % of the data (4.7 % at 30 s). A full cycle is ⌈n/7⌉ minutes: 2 min for 13 paths, 3 min for 20. That interleaves all paths finely enough to see the weekday ramp (tens of minutes) and to place a route change like Nov 10 within a few minutes. Dwells of several minutes would also work, but cycles become long when there are many paths.

**Scan length: at least 7 full days**, so that weekday business hours, nights and a weekend are all covered.

## Part 1: scan mode in the client

### Configuration

```toml
scion_path_scan = "/var/lib/timeservice/path-scan.csv"  # enables scan mode
scion_path_scan_dwell = 60                              # seconds, default 60
ntl_ctsoff = "..."                                      # required in scan mode
```

- Scan mode requires exactly one SCION reference clock and `ntl_ctsoff`; otherwise the client exits with an error, since without a reference a week of scanning cannot be ranked.
- The week-long scan measures every path the client may use. A batch with three or more strongly asymmetric paths (about ±88 to ±106 µs at the pilot sites) can pull the clock for a minute (see Effects); setting `scion_paths` to a quick scan's finalists avoids that.

### Scheduling

`ntpReferenceClockSCION.MeasureClockOffset` hands the current batch to `client.MeasureClockOffsetSCION` instead of all paths:

```go
ps = c.pather.Paths(c.remoteAddr.IA)
if len(c.paths) != 0 {
	if pre := client.PreselectedPaths(ps, c.paths); len(pre) != 0 {
		ps = pre
	} else {
		c.log.LogAttrs(ctx, slog.LevelWarn, "no preselected path available, using all paths")
	}
}
if c.scan != nil {
	ps = c.scan.paths(ps)
}
```

If `scion_paths` is set, the scan covers only the listed paths. That lets a week-long scan follow a quick scan (see Quick scan).

With only the 7 batch paths in `ps`, the existing logic in `MeasureClockOffsetSCION` assigns one to each client. No change is needed there.

The scheduler (`pathScan.paths`) is called once per round:

1. If the dwell has expired, it starts the next batch: the next 7 fingerprints of the current cycle.
2. At the start of a cycle, it takes all fingerprints currently offered by the pather and shuffles them. The shuffle varies which paths share a batch and when each path is measured.
3. A short last batch is topped up with paths from the start of the cycle, so 7 flows are always active, as in production.
4. It resolves the batch fingerprints against the fresh path list. A path that has disappeared is skipped for the rest of its dwell. New paths join at the next cycle.

```go
func (s *pathScan) paths(ps []snet.Path) []snet.Path {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	byFP := make(map[string]snet.Path, len(ps))
	for _, p := range ps {
		byFP[client.PathFingerprint(p)] = p
	}
	if s.batch == nil || now.Sub(s.start) >= s.dwell {
		if s.next >= len(s.order) {
			s.order = slices.Collect(maps.Keys(byFP))
			rand.Shuffle(len(s.order), func(i, j int) { s.order[i], s.order[j] = s.order[j], s.order[i] })
			s.next = 0
		}
		s.batch = slices.Clone(s.order[s.next:min(s.next+s.size, len(s.order))])
		s.next += s.size
		for _, fp := range s.order {
			if len(s.batch) == s.size {
				break
			}
			if !slices.Contains(s.batch, fp) {
				s.batch = append(s.batch, fp)
			}
		}
		s.start = now
		s.writeBatch(now, byFP) // p rows for new paths, then the b row; flushes the file
	}
	fmt.Fprintf(s.w, "n,%d\n", now.UnixNano())
	sel := make([]snet.Path, 0, len(s.batch))
	for _, fp := range s.batch {
		if p, ok := byFP[fp]; ok {
			sel = append(sel, p)
		}
	}
	return sel
}
```

### Recording

- **Lucky picks** come from a hook in the filter, which already knows offset, RTD, floor and the gate decision. That is the information it now logs as "picked lucky packet":

  ```go
  // core/client/filter.go
  OnPick func(off, rtd, floor time.Duration, ok bool)

  // in pickLucky, replacing the final check
  ok := (x.rtd - floor).Abs() <= f.maxRTDExcess
  if f.OnPick != nil {
  	f.OnPick(off, x.rtd, floor, ok)
  }
  if !ok {
  	return 0, errFilterRejected
  }
  return off, nil
  ```

  In scan mode, the client wiring sets the hook per client. The closure reads the client's current path, which `measureClockOffsetSCION` sets before it uses the filter:

  ```go
  for _, ntpc := range scionclk.ntpcs {
  	ntpc.Filter.OnPick = func(off, rtd, floor time.Duration, ok bool) {
  		scan.pick(ntpc.Path(), off, rtd, floor, ok)
  	}
  }
  ```

- **Failed rounds** (timeouts, SCMP errors) produce no pick. `preselectpaths` counts them as rounds of the dwell without a pick for that path. The `n` rows give the exact number of rounds.
- **The GNSS comparison** reaches the scan file through a sink parameter on the NTL CTS service: `service.StartNTLCTSOff(log, cfg.NTLCTSOff, sink func(off time.Duration))`. It is called with the same value that is now logged as "NTL CTS offset". The server passes `nil`.
- **Times are host REALTIME** (`time.Now()`) for all rows. Aligning picks with the 1 Hz CTS needs only ~0.1 s accuracy: with the clock steered, CTS changes by far less than 1 ns per 0.1 s.
- **Concurrency:** picks come from 7 client goroutines, CTS from its own goroutine, rounds from the sync loop. One mutex guards the buffered writer. The file is flushed at every batch start, so at most one dwell is lost if the process dies.

### File format

A CSV file, one record type per row, append-only:

```text
p,<id>,<fingerprint>,<IA#IF IA#IF ...>                path, written when first scheduled
b,<t_ns>,<id>,<id>,<id>,<id>,<id>,<id>,<id>           dwell start with the scheduled paths
n,<t_ns>                                              round start
m,<t_ns>,<id>,<offset_ns>,<rtd_ns>,<floor_ns>,<ok>    lucky pick; ok = 0 if the RTD gate rejected it
r,<t_ns>,<cts_ns>                                     NTL CTS offset
```

- Small integer ids keep `m` rows short; the `p` row carries the full fingerprint and the interface list that `preselectpaths` needs for diversity checks and for running `SelectPaths` offline.
- Picks from a path that is not in the id table (a slot that kept an old path for a round) are dropped.
- Size at Thun: about 430,000 `m` rows, 61,000 `n` rows and 86,000 `r` rows per day, about 25 MB/day or 175 MB per week.

### Effects on the running client

- The clock keeps being steered, from the fault-tolerant midpoint (FTM) of the current batch. Batch biases at Thun differ by a few µs. The PI needs many minutes to follow a step, so with 60 s dwells the clock only wobbles slightly around the average of all paths. That doesn't affect e.
- The server sees 7 flows from the client, as now.
- After the scan, remove `scion_path_scan`. The next start begins with fresh path selection.

## Part 2: `timeservice preselectpaths`

```text
timeservice preselectpaths -scan FILE [-from TIME] [-to TIME] [-tol 0.25us] [-tol-rel 0.25] [-max-error D] [-min-pool 10] [-remain 5]
```

The subcommand runs offline, without SCION connectivity, and prints a report and the config line. `-from`/`-to` restrict the analysis, for example to the time after a route change. The batch size k is read from the `b` rows.

### Processing

1. **Errors.** For each `m` row with ok = 1: e = offset − CTS(t), with CTS linearly interpolated between the neighbouring `r` rows. Picks without a CTS row within 2 s are dropped.
2. **Dwells.** Each pick belongs to the dwell whose `b` row precedes it. Each path's first pick in a dwell is discarded. A dwell value is the mean of the remaining e; also kept are the counts of picks, rejected picks and rounds, and the minimum RTD.
3. **Hours.** Dwell values are averaged per path and UTC hour into e_h. With 60 s dwells and 20 paths that is ~20 dwells per path and hour.

### Per-path metrics

| Metric | Definition | Use |
|---|---|---|
| bias | median of e_h | report |
| score | 95th percentile of \|e_h\| over all hours | ranking: error in a typical bad hour, so the weekday ramp counts |
| σ | pooled within-dwell SD of e per round | report, tie-break |
| loss | 1 − picks / rounds over its dwells | eligibility |
| rejected | share of picks rejected by the RTD gate | report |
| coverage | share of hours with at least one dwell | eligibility |
| RTD floor | minimum RTD per hour | route-change detection |

**Eligibility:** loss ≤ 1 % and coverage ≥ 90 %. Ineligible paths are listed with the reason.

### Pool selection

The pool is the candidate set for the existing `SelectPaths` and path-keeping logic, not a fixed set of 7. That leaves the runtime selection in charge of diversity and failover within the well-performing paths.

1. **Cutoff from the data.** Sort the eligible paths by score. For each pool size n, from `-min-pool` (default 10: 7 plus 3 spares) up to all eligible paths, estimate the clock error that the runtime selection would give with the best n paths:
   - run `SelectPaths` 100 times on them;
   - average the mean |e| of the 7 paths it picks (in the week-long scan, the 95th percentile over hours).

   The pool is the largest n whose expected error is within a tolerance of the best n: max(`-tol`, `-tol-rel` × best), default max(0.25 µs, 25 %); 0.5 µs before November 17. When many paths are similarly good, the pool is large; when quality drops off quickly, it stays near the minimum.
2. **Optional fixed bound.** `-max-error` replaces the cutoff with a fixed bound on the score, for sites where an absolute accuracy target matters more than the redundancy.
3. **Interface resilience.** For every interface that is not shared by all eligible paths, the pool must keep at least `remain` paths (default 5) that avoid it. Then losing any single link still leaves the fault-tolerant midpoint with f ≥ 1. While a constraint fails, add the best-scoring eligible path that avoids that interface, even beyond the cutoff; the report lists such additions. If no eligible path avoids an interface, the report lists it as weak; the scan does not fail, since this is a property of the topology, like a single point of failure.
4. Interfaces shared by all eligible paths cannot be avoided by any choice. They are reported as single points of failure; at Thun, every path seen so far uses 2:0:2c#1 and 64-3303#21.

**Why a cutoff, not simply every good path.** `SelectPaths` does not look at the error. It takes the shortest path first, then the paths that add the most new interfaces. The best paths tend to share links: in the Thun-like population below, 8 of the 10 best use 3303#30 → 15623#19. The paths `SelectPaths` prefers are therefore often the somewhat worse ones on other links. Every admitted path is likely to be used, so the cutoff sets the accuracy.

This was simulated with [`pilot/analysis/quickscan/poolsim.py`](../pilot/analysis/quickscan/poolsim.py). It is a Python copy of `SelectPaths`, run on the uplink 1 and uplink 2 paths of the quick-scan population (true errors, 500 selections each). Clock error is |FTM| of the 7 selected paths' errors.

| Pool | Paths | Clock error (median / p90) | Paths left after the worst single-interface loss |
|---|---|---|---|
| best 10 | 10 | 1.35 / 1.35 µs | 2 |
| best 10 + resilience rule | 14 | 2.05 / 2.40 µs | 5 |
| every path within 4 µs | 17 | 2.55 / 2.85 µs | 6 |
| every path within 5 µs | 20 | 3.45 / 3.75 µs | 7 |
| no pool (all 86 paths of both uplinks, 6730 excluded) | 86 | 12.35 / 13.90 µs | 42 |

More paths buy redundancy at a price in accuracy. How fast the price rises depends on the site, which is why the cutoff is taken from the data rather than set as a fixed bound. [`adaptive.py`](../pilot/analysis/quickscan/adaptive.py) applies it to three kinds of site. It uses the same paths and interfaces, and estimates with quick-scan noise (SE 0.7 µs); the resulting clock error is evaluated with the client's FTM:

| Site | Expected mean \|e\| of the paths in use, by pool size (10 / 15 / 20 / 30 / all) | Pool | Clock error (best 10) | Paths left after the worst single link failure (best 10) |
|---|---|---|---|---|
| Thun-like: quality falls off gradually | 1.3 / 2.0 / 2.8 / 4.6 / 11.6 µs | 13 of 86 | 2.00 µs (1.37) | 4 (2) |
| all paths similar (SD 0.8 µs) | 0.1 / 0.2 / 0.2 / 0.3 / 0.9 µs | 72 of 86 | 0.21 µs (0.15) | 34 (4) |
| steep: 8 good paths, the rest 5–15 µs | 2.1 / 3.0 / 3.4 / 4.6 / 8.7 µs | 11 of 86 | 0.49 µs (0.69) | 3 (3) |

At the Thun-like and steep sites, the resilience rule then adds a path or two to reach 5 left after any link failure. At the steep site, the minimum pool of 10 has to include 2 of the asymmetric paths, since only 8 are good.

**Why the mean |e| of the paths in use.** The criterion should measure how symmetric the paths are that the client will actually use. Two alternatives were simulated and rejected:

| Criterion (over the 7 paths `SelectPaths` picks) | Thun-like | all similar | steep |
|---|---|---|---|
| \|FTM\| of their errors, as the client combines them | 13 paths, 2.00 µs | 86 paths, 0.27 µs | 12 paths, 0.90 µs |
| \|mean\| of their errors | 13 paths, 2.00 µs | 86 paths, 0.27 µs | 16 paths, 1.05 µs |
| **mean \|e\|** | **13 paths, 2.00 µs** | **72 paths, 0.21 µs** | **11 paths, 0.49 µs** |

The FTM masks up to two asymmetric paths out of 7, so the pool would spend at selection time the fault tolerance the client needs for real faults at runtime. In the signed mean, opposite errors cancel; at the steep site that admitted 8 asymmetric paths. Mean |e| does neither.

A knee in the sorted |e| curve would be simpler, but at Thun that curve is smooth from 0 to 13 µs, with no knee.

The absolute tolerance of 0.5 µs matches the precision of quick-scan estimates; smaller differences are not meaningful. The relative part scales the tolerance at sites with larger errors.

### Expected clock error

To show what the pool buys, `preselectpaths` simulates the runtime selection with the real data. It does this both for the pool and for the status quo, which is all candidates.

1. Run `client.SelectPaths(candidates, k)` 200 times. The paths are rebuilt from the `p` rows; ties are broken at random as at runtime.
2. For each resulting set and each hour, simulate 100 rounds. For every round, draw one pick per path from that path's picks in that hour and take the FTM. The hour's expected error is the mean over the rounds, since the PI loop averages over minutes.
3. Report the median and the worst draw of "95th-percentile hourly |error|" for pool and status quo.

The bootstrap treats the paths as independent within a round. That is reasonable because e excludes the clock, and the remaining noise is mostly per path.

### Diagnostics

- **Route changes:** hours in which the RTD floor of at least half the paths jumps by more than 200 µs, with the interfaces those paths share. A change like Nov 10 splits the scan into two regimes; rerun with `-from`.
- **Common mode:** per hour, the median of e_h over all paths. Its range shows how much of the error no path choice can remove.
- **Warm-up check:** the mean e deviation by pick index within a dwell, for indices 1–10.

### Output

```text
path      bias    score   σ/round  loss   rej    dwells  status
d8218c56  ...     ...     ...      ...    ...    ...     pool
...
single points of failure: 64-2:0:2c#1 64-3303#21
route changes: none
expected clock error (p95 hourly |error|, median / worst of 200 selections):
  all candidates  ... / ...
  pool            ... / ...

scion_paths = [
  "d8218c56...",  # score ..., 64-3303 1>17 64-559 5>1
  ...
]
```

## Quick scan: `preselectpaths -quick`

```text
timeservice preselectpaths -config pilot/client-thun.toml -quick [-out FILE] [-update]
```

Thun has about 200 paths to the server (224 in November 2026). A week-long scan over all of them would give each path one 60 s dwell every 29 minutes. The quick scan instead finds a good set in about 30 minutes, by spending most of the measurement time on the paths that are still in contention.

### Running it

- **Stop the client service first.** The quick scan uses the same local address and the same 7 clients.
- **Setup:** it reads the client config (addresses, SCION connection, filter settings, authentication, `ntl_ctsoff`) and builds the SCION reference clock as `runClient` does, including the internal dispatcher, the pather and the CTS sink.
- **All paths:** it measures every path the path service offers, and it ignores an existing `scion_paths`, except to identify the incumbents (see No churn).
- **The clock follows GNSS during the scan.** Instead of running `sync.Run`, the quick scan calls `MeasureClockOffset` once per sync interval and uses the per-path picks only for ranking. A PI controller with the client's gains steers `sync_clock` (eth0's PHC, `/dev/ptp0` at the pilot) from the CTS offset once per second. The batches never steer the clock, and the site keeps GNSS time through the maintenance window.
  - e itself would not need this. Packets are timestamped by eth0's PHC, and the CTS compares that same clock with GNSS, so the clock's own error cancels in e = offset − CTS.
  - What steering protects is the time alignment. A pick and its CTS samples are up to ~0.5 s apart, so a clock off frequency by Δf adds Δf × 0.5 s: 50 ns at 0.1 ppm, 5 µs at 10 ppm. On GNSS, Δf stays near zero.
  - The CTS offset moves with the measured offsets when the clock moves (that is what makes e clock-independent), so the controller takes it with the same sign as the client's measured offset.
- **Self-test before the stages (2 min).** At a new site, a wrong `ntl_ctsoff` index order, or a CTS that compares a different clock than the one that timestamps the packets, would silently produce a wrong ranking. So the quick scan first runs this test, with the GNSS controller paused:
  1. measure one batch, the 7 shortest paths, for 30 s;
  2. step `sync_clock` by +100 µs and measure for another 30 s;
  3. step it back.

  The median change of the 7 paths' mean offsets and the change of the CTS offset must both be −100 µs ± 5 µs. A 30 s mean is only good to about 1 µs, so a smaller step would fail by chance. Otherwise the scan stops without touching the config. The test also confirms the controller's sign before it steers.
- **Server and local disturbances.** A server excursion like Nov 4 or Nov 9 shifts e on all paths at once. A round is discarded when most of its picks deviate from their paths' running means by more than 20 µs in the same direction. If more than 2 % of rounds are discarded, the scan stops without touching the config. A steady µs-level server offset cannot be told apart from a shared asymmetry and goes into every e alike; it does not change the ranking, only the absolute errors.
- **Output:** the same scan file as scan mode (default `path-quickscan-<UTC time>.csv`), with one extra row per stage, `s,<t_ns>,<stage>,<dwell_s>`, so that `preselectpaths -scan` can re-analyse it. Then the report and the `scion_paths` line, as in the offline mode.

### Stages

Each stage measures the remaining candidates in batches of 7.
- **Stages 1 and 2 select finalists by their mean error.** The standard error there combines the noise of the picks (σ per round over √picks, σ at least 3 µs while picks are few) with an assumed drift between short windows, τ = 2 µs. After each of these stages the cutoff is applied to the current estimates, which gives a provisional pool size n. A path is dropped when even its optimistic |e| (|mean| − 3 SE) is worse than the pessimistic |e| (|mean| + 3 SE) of path max(20, n). With `-max-error`, the bound itself is the limit. Paths with fewer than half the expected picks in stage 1, or more than 5 % failed rounds later, are dropped as well.
- **Stage 3 measures each batch of finalists continuously for 9 minutes.** That is long enough to see errors that vary over minutes; Thun's uplink 2 oscillated with a period of 9.5 minutes (see below). The finalists' statistics are reset at the start, so the pool is decided on stage-3 data only, without the selection bias of stages 1 and 2.
- **Each finalist gets a score: its error over time.** The score is √(mean² + variation²), where the variation is the spread of its 30-second means beyond their noise. A path that is symmetric on average but oscillates scores by its oscillation.

| Stage | Dwell | Paths | Time at Thun | Then keep |
|---|---|---|---|---|
| 0 | 2 × 30 s | 1 batch | 1 min | self-test (see Running it) |
| 1 | 20 s | all, 224 | 32 batches, 12 min | what the rule keeps, ~170 |
| 2 | 45 s | ~170 | ~25 batches, 19 min | what the rule keeps, at most 21, by \|e\| |
| 3 | 9 min, continuous | ≤ 21 | 3 batches, 27 min | the pool, by score (see Pool selection) |

Total: about 59 minutes for the 224 paths at Thun and about 42 minutes for the 110 at Lausanne, within the 30–60 minutes allowed.

**Pool selection in the quick scan** follows Pool selection above, with three differences:
- the score replaces |e|;
- the expected error of a pool is the root mean square of the scores of the 7 paths `SelectPaths` picks, so that one bad path among good ones counts by its square, not by a seventh;
- after the cutoff, a path stays only if its own score is within two tolerances of the best pool's expected error, because the expected error of a pool still dilutes a single bad path. The default tolerance is max(0.25 µs, 25 %).
- the resilience rule may only add paths below that ceiling, because accuracy and stability come first. Where no qualifying path avoids an interface, the pool depends on it, and the report lists it among the pool's single points of failure, which are now computed over the pool itself.

The third Thun scan (2026-11-17, 05:32–06:32 UTC) showed why the last point is needed:
- **Detection worked.** All six uplink-2 finalists had a variation of 2.9–5.5 µs, most uplink-1 paths 0–1.2 µs, and the cutoff kept the 10 best by score (0.17–3.11 µs).
- **The old resilience rule then undid it.** It added 8 paths, 5 of them via uplink 2, to get around uplink 1 and the link 3303#31 → 15623#6, raising the expected error from about 1.7 to 4.06 µs. `SelectPaths` would have favoured exactly those paths.
- **With the fix,** the pool is the 10 uplink-1 paths.

### First scan at Thun (November 16) and resulting changes

The first scan (17:05–17:46 UTC, 224 paths, version 1 schedule 20 / 45 / 120 s, cap 35) produced a pool of 23 paths and was deployed. Re-analysis with [`scanfile.py`](../pilot/analysis/quickscan/scanfile.py) and [`capcheck.py`](../pilot/analysis/quickscan/capcheck.py):

- **Noise:** σ per round 11–14.5 µs (median), more than the 4–13 µs of run 11. Stage 1 therefore kept 168 paths, and the scan took 41 minutes.
- **Drift per path:** estimates of the same path from different stages differed by more than their noise. Stage 1 vs stage 2 (154 paths): SD of the change 4.8 µs against 4.0 µs from noise. Stage 2 vs stage 3 (35 finalists): 4.6 against 3.0 µs. That is about 2 µs of drift per path and window.
- **No common mode:** the mean error per batch varied by 1.02 µs, as expected from noise (1.01 µs). A reference path in every batch would not help; separate windows per path do.
- **Selection bias:** the finalists' stage-2 values did not predict their stage-3 values (slope −0.13), and their |e| grew by 0.9 µs on average from stage 2 to stage 3.
- **The cap dropped good paths:** 9 paths whose stage-2 |e| was within the pool's range never reached stage 3. The revised cap (42 by |e|) would have kept all 9.

These findings led to a first revision: three 60 s windows per finalist in stage 3, the pool decided on stage-3 data only, standard errors that include the drift, and a cap of 42 by |e|. Lausanne was scanned with that revision. The night of November 16/17 then showed that the drift was not a property of every path, and stage 3 was changed again.

### Night of November 16/17: an unstable uplink

With the scanned pools deployed ([`pilot/analysis/run12/`](../pilot/analysis/run12/)):

- **Lausanne was smooth.** The GNSS comparison went from +3.8 to +2.5 µs, varying by 0.25 µs (30 s means), with no periodic component.
- **Thun oscillated.** The GNSS comparison went from +2.2 to +5.0 µs, with a 570 s (9.5 min) oscillation of ±0.57 µs. The combined offset oscillated by ±2.6 µs.

The cause is uplink 2 (`2:0:2c#2` ↔ `64-3303#25`):

| Paths in use | Error amplitude at 570 s | Round-trip delay amplitude at 570 s |
|---|---|---|
| 4 via uplink 2 | 4.2–4.8 µs | 6.0–7.5 µs |
| 3 via uplink 1 | none | none |

- **Diversity amplified it.** 7 of the 23 pool paths went via uplink 2, but `SelectPaths` picked 4 of them for its 7 slots, because they add new interfaces. Diversity over-represents any distinct group in the pool, and the FTM cannot mask 4 paths moving together.
- **The scan had seen it.** Between stage 1 and stage 2, uplink-1 paths varied exactly as noise predicts (excess 0.0 µs) and uplink-2 paths by 4.1 µs more. The "τ = 2 µs drift per path" was uplink 2 alone.
- **Short windows could not single it out.** A replay of the first scan with a variation-aware score still kept 3 uplink-2 paths, which took 24–34 % of the picks. A per-interface test flagged downstream interfaces instead of uplink 2.
- **One continuous window per path does.** On the night data, 9-minute windows flagged 74 % of the uplink-2 windows (χ²/dof > 2) against 4 % of uplink 1, with a variation of 3.6 µs against 0.0 µs. Hence the continuous 9-minute stage 3 and the score.
- **The fix at Thun** was to remove the 7 uplink-2 paths from `pilot/client-thun.toml` (November 17).
- **A separate effect:** from 21 to 04 UTC, six of Thun's seven paths drifted 2–4 µs more negative, and one stayed flat; Lausanne drifted the other way. Path errors differ between the evening, when the scan ran, and the night.

### Expected duration and quality

The schedule was simulated with [`pilot/analysis/quickscan/qsim.py`](../pilot/analysis/quickscan/qsim.py), 300 repetitions. The population is Thun-like:
- the 43 paths measured in runs 0–11, with their own error and per-round noise, shifted by the Nov 10 step;
- the same paths via uplink 2, at ±11 µs;
- 100 paths at ±100–120 µs for the 6730 interfaces.

With a fixed bound (`-max-error`; [`qsim_bound.py`](../pilot/analysis/quickscan/qsim_bound.py), schedule 20 / 60 / 120 s):

| Bound | Duration | Pool | Worst path in the pool (median / p90) | Paths > 1 µs beyond the bound admitted | Paths > 1 µs within the bound missed |
|---|---|---|---|---|---|
| 3 µs | 26 min | 12 | 3.8 / 4.4 µs | 0.2 | 0.6 |
| 4 µs | 27 min | 15 | 4.4 / 5.5 µs | 0.3 | 0.5 |
| 5 µs | 29 min | 19 | 5.5 / 7.6 µs | 0.5 | 0.5 |

Pool membership is right except for about one borderline path per run.

The schedule itself was compared with an earlier rank-based variant ([`qsim.py`](../pilot/analysis/quickscan/qsim.py), keep the best 20): 15 / 45 / 90 s took 24 min and 20 / 60 / 240 s took 41 min. Neither changed the 10 best picks by more than about 0.1 µs relative to 20 / 60 / 120 s (31 min). A variant that keeps measuring until the best paths are clearly separated did not finish within 2 hours, because many paths are equally good.

**With the data-driven cutoff**, the proposed schedule 20 / 45 / 120 s with a stage-3 cap of 35 was simulated with [`qsim_adaptive.py`](../pilot/analysis/quickscan/qsim_adaptive.py), using the implemented criterion (mean |e| of the paths in use). It uses the same paths and interfaces with three error patterns, the 100 paths at ±100–120 µs, and 10 repetitions per site. The clock error is evaluated with the client's FTM:

| Site | Stages 1–3 | Pool (range) | Clock error | Ideal best 10 |
|---|---|---|---|---|
| Thun-like, quality falls off gradually | 29 min | 13 (11–15) | 1.85 µs | 1.27 µs |
| all paths similar | 29 min | 28 (24–30) | 0.21 µs | 0.01 µs |
| steep: 8 good paths, the rest 5–15 µs | 29 min | 11 (10–14) | 0.87 µs | 0.58 µs |

- The duration does not depend on the criterion. With the earlier FTM-based criterion the same schedule gave pools of 12, 35 and 14 (range 12–34) with clock errors of 1.61, 0.33 and 0.82 µs. The differences in clock error are within the simulation's noise of about ±0.2 µs, but the pool no longer swings to 34 paths at the steep site.
- At the all-similar site the pool is limited by the stage-3 cap (35 measured paths) and by the slowly rising mean |e|: 28 of 86 good paths, still ample redundancy.
- The previous schedule (20 / 60 / 120 s, cap 49) took 36 min.

**Version 1 used 20 / 45 / 120 s with a stage-3 cap of 35.** After the first scan at Thun, the last stage became 3 passes of 60 s with a cap of 42, and after the night of November 16/17 one continuous 9-minute window per batch with a cap of 21 (see Stages): about 59 minutes at Thun.

### Limits of a quick scan

- **It sees only those 30 minutes.** The weekday ramp moves some paths by 4–6 µs. Run it at night for the quiet baseline and check the pool with a week-long scan.
- **The simulation assumes stationary conditions and Gaussian noise.** Paths with heavier tails or drifting delays need more time. The report lists each finalist's mean per stage, so drift during the scan is visible.

### Uplink 2

Thun's config excluded uplink 2 (`2:0:2c#2` ↔ `64-3303#25`) until November 16: in October, its paths were 20–25 µs round trip more return-slower than uplink 1's, i.e. 10–12.5 µs lower in e. On Nov 10, uplink 1's paths moved by −8.5 µs. If uplink 2 itself did not change, its paths are now only about 1.5–4 µs below uplink 1's.

The quick scan's first stage will show this within minutes. If it is confirmed, a pool spanning both uplinks removes the single point of failure at 2:0:2c#1.

### From quick scan to pool

1. Quick scan at night: ~200 paths become the pool, printed as `scion_paths`. For the validation, use a looser cutoff (e.g. `-tol 1.5us`) so that borderline paths get checked too.
2. Week-long scan mode with `scion_paths` set to that pool: 3 batches, a 3-minute cycle, about 20 dwells per path and hour.
3. `preselectpaths -scan` on that file gives the final pool, by worst-hour error and the resilience rule.

If a week is not available, the quick scan's own pool can be used directly.

### As a maintenance task

The intended routine at each site: stop the service, run the quick scan for as long as it takes, write the new pool into the client config, and start the service again.

```text
timeservice preselectpaths -config /etc/timeservice/client.toml -quick -update
```

**What `-update` writes:**
- Only the `scion_paths` block changes. It is replaced if present, otherwise appended after the last top-level key (the client configs have no tables). All other lines and comments stay as they are.
- The block holds the pool as defined in Pool selection: the data-driven cutoff, at least `-min-pool` paths, plus resilience additions. Each entry carries a comment with its error and hops, and a header comment names the scan file and time:

  ```toml
  # Written by "timeservice preselectpaths -quick" at <UTC time> from <scan file>.
  # Pool of <n> paths, expected clock error <x> µs, single points of failure: <interfaces>
  scion_paths = [
    "<fingerprint>",  # e ... µs, 2:0:2c 1>21 3303 1>17 559 5>1 2:0:9
  ]
  ```
- The new file is loaded with the client's own `loadConfig` before it replaces the old one (write to `<file>.tmp`, then rename). The previous version is kept as `<file>.prev`.

**Safeguards for unattended runs.** The config stays unchanged, the reason is logged, and the exit status is non-zero when:
- there is no CTS data;
- the server is unreachable: more than half of the first 50 or more rounds without any measurement (checked every round), or more than 5 % of all rounds (checked at the end);
- fewer than `-min-pool` paths are eligible;
- the CTS offset drifts by more than 0.5 ppm during the scan, i.e. the clock was not held on GNSS and alignment errors could exceed 0.25 µs.

**No churn.** The paths of the current pool (the incumbents) go through the elimination rule like every path, but not through the stage cap, so they are measured in stage 3. The bound gets a hysteresis band of two standard errors:
- an incumbent leaves only if it is clearly beyond the cutoff (|mean| − 2 SE > the score of the last path inside it);
- a new path joins only if it is clearly within it (|mean| + 2 SE ≤ that score).

If neither happens, the file is not rewritten and the summary says "unchanged". Repeated runs therefore do not shuffle the pool on noise.

**Starting and stopping with systemd** (unit names and paths to adapt):

```ini
# /etc/systemd/system/timeservice-pathscan.service
[Unit]
Description=timeservice quick path scan

[Service]
Type=oneshot
ExecCondition=/usr/local/bin/timeservice preselectpaths -config /etc/timeservice/client.toml -due 168h
ExecStartPre=/bin/systemctl stop timeservice.service
ExecStart=/usr/local/bin/timeservice preselectpaths -config /etc/timeservice/client.toml -quick -update
ExecStopPost=/bin/systemctl --no-block start timeservice.service
TimeoutStartSec=2h

# /etc/systemd/system/timeservice-pathscan.timer
[Timer]
OnCalendar=*-*-* 02:00:00 UTC

[Install]
WantedBy=timers.target

# /etc/systemd/system/timeservice-pathscan.path
[Path]
PathExists=/etc/timeservice/client.toml.rescan
Unit=timeservice-pathscan.service

[Install]
WantedBy=paths.target
```

`preselectpaths -due` exits with status 0 when a scan is due and 1 otherwise; with 1, systemd skips the unit without stopping the service. The scan removes `client.toml.rescan` when it finishes, whatever the result, so a failed scan does not retrigger at once.

`ExecStopPost` runs whether the scan succeeded or failed, so the service always comes back, with the new or the old config.

**Maintenance window.** About 59 minutes at Thun and 42 at Lausanne, plus a few minutes for incumbents. The clock stays on GNSS meanwhile (see Running it). After the restart, the client moves it from GNSS to where the new pool's combined bias puts it, typically a few µs, which takes several minutes. Schedule it at night.

**Prerequisite: a GNSS comparison at the site.** Ranking by symmetry is only possible against an independent clock. At a site without `ntl_ctsoff`, a quick scan can only find paths that agree with each other, which cannot detect an asymmetry they share. The quick scan refuses to run without CTS.

**When it runs.**
- **Weekly, at night.** A daily timer at 02:00 UTC starts the unit, and `ExecCondition` lets it proceed only when a scan is due:
  - the last successful scan is older than `-due` (default 7 days);
  - a rescan request exists;
  - or a confirmation is pending.

  The state file `<config file>.scanstate` records the last scan and any pending confirmation. Because the clock stays on GNSS during the scan, a nightly scan would also cost no accuracy at pilot sites (`-due 24h`); it only interrupts SCION time for half an hour.
- **After a route change, promptly.** The client detects one itself:
  - Every 5 minutes, it compares each path's RTD floor (the filter's 10th percentile of the last 5 minutes) with the floor 15 minutes earlier, for paths it kept over that time.
  - If at least two thirds of them moved by more than 200 µs in the same direction, it logs a WARN.
  - If there is no further shift in the next 15 minutes, it writes `<config file>.rescan`, with time and reason. A systemd path unit then starts the scan.
  - It writes at most one request per 6 hours, so a flapping link cannot cause a loop.
  - Nov 10 (`pilot/tmp/thun-20261110.log`): the floors of all 7 paths dropped by 1.67 ms at 06:51:50, and the RTD gate rejected 224 picks on all 7 paths in that minute.
  - A floor shift of more than 200 µs always causes such rejections first. In runs 9–11 (three sites, 3 days), the only other minutes with rejections on two or more paths were Lausanne on Nov 9 at 23:12 (2 of 7 paths, during the cw0 excursion) and Zurich on Nov 10 at 15:27 (both paths, a single round). Neither moved the floors, so neither would trigger.
  - About 40 lines in the client.
  - A triggered daytime scan marks a confirmation as pending in the state file, so that the next night's run confirms the pool under quiet conditions.
- **Not detected by the client:** an asymmetry change without a delay change. The weekly scan catches it. The weekday business-hours ramp (4–6 µs on some paths) is not seen by night scans; the week-long scan mode can check it.

## Survey: `preselectpaths -survey`

```text
timeservice preselectpaths -config pilot/client-thun.toml -survey [-dwell 20m] [-duration 168h] [-out FILE]
```

Implemented on November 19 for the operator of AS 64-3303, who offered to analyse the asymmetries and oscillations on Thun's paths. A quick scan sees every path for 20–45 s at one time of day and drops the bad paths after its first stage; the client sees only its 7 paths. The survey measures every path repeatedly over days, long enough per window to resolve the 9.5-minute oscillation of uplink 2.

- **Rules.** It takes all paths to the server and re-reads them at the start of each cycle. Each cycle shuffles the paths into batches of 7 and measures each batch continuously for `-dwell`. The clock is held on GNSS after the same self-test as in the quick scan. It stops after `-duration`.
- **It only records.** No statistics, elimination, pool or config update. It does not stop for a server outage, discarded rounds, a gap in the CTS offsets or clock drift, only for a failed self-test or a write error. The analysis decides which data to use.
- **File.** The scan file format, flushed after every round. The `s` row starts a cycle: `s,<t_ns>,<cycle>,<dwell_s>`. Rows before the first `s` row belong to the self-test. `p` rows of paths that appear later are written at the start of the cycle that first measures them. A path that disappeared stays in the rotation and yields no picks.
- **Forward and return delay** of a pick, with e = offset − CTS interpolated at the pick: forward (client → server) = RTD/2 + e, return = RTD/2 − e. This splits run 12's uplink-2 oscillation into 6.7–7.6 µs forward and 1.7–2.5 µs return amplitude, and the Nov 10 reroute into −844 µs forward and −827 µs return.
- **Coverage at Thun** (224 paths, 20 min dwell): 32 batches, 10.7 h per cycle, about 16 windows per path and week at varying times of day. 98.6 % of batches contain paths on both uplinks. A 20-minute mean is good to about 0.4 µs. About 1.1 MB per hour, 0.36 MB gzipped.
- **Cost.** The site has no SCION time while the survey runs; its clock stays on GNSS.

## Part 3: `scion_paths` in the client

```go
// core/client/paths.go

func PathFingerprint(p snet.Path) string {
	return snet.Fingerprint(pathInterfaces(p)).String()
}

// PreselectedPaths returns the paths of ps whose fingerprints are listed in
// fps, the preselection (e.g. by a path scan) that SelectPaths chooses from.
func PreselectedPaths(ps []snet.Path, fps []string) []snet.Path {
	var pre []snet.Path
	for _, p := range ps {
		if slices.Contains(fps, PathFingerprint(p)) {
			pre = append(pre, p)
		}
	}
	return pre
}
```

- **The scan-based pool is the only path selection mechanism.** `scion_excluded_interfaces` was removed on November 17: it overlapped with the pool, needed precedence rules and consistency checks, and its findings are kept as comments in the configs. Exclusions by interface, geography or other criteria are to return later as a general path policy, applied as a hard pre-filter before both the scan and the client.
- `SelectPaths` picks 7 diverse pool paths and the path-keeping logic holds them. A path that keeps failing is replaced by another pool path.
- **With fewer than 7 preselected paths available** (for example after a topology change), the client uses those it has: accuracy first. The FTM still tolerates one bad path while at least 4 are available.
- **With no listed path available,** it falls back to all paths, as without `scion_paths`, and logs a WARN that a rescan is needed.
- The client logs nothing extra in normal operation: its per-path "measured clock offset" lines show which pool paths are in use. In the fallback it logs "no preselected path available, using all paths" at WARN in every round. The caller decides the fallback, so `PreselectedPaths` only selects.
- Paths that appear after the scan are not used until the next scan.
- **One SCION server per config.** `scion_paths` applies to every SCION reference clock, but its fingerprints are those of the paths to the scanned server. With a second SCION server in the config, none of that server's paths would match: it would use all its paths and log the WARN in every round. The quick scan therefore refuses configs with more than one SCION reference clock. Lists per server can come with the general path policy.

## Code changes

| File | Change | Lines |
|---|---|---|
| `core/client/filter.go` | `OnPick` hook | ~8 |
| `core/client/paths.go` | `PathFingerprint`, `PreselectedPaths` | ~25 |
| `service/ntlctsoff_linux.go`, `_std.go` | sink parameter | ~5 |
| `timeservice.go` | 3 config keys, `paths`/`scan` fields, wiring in `createClocks` and `runClient`, `MeasureClockOffset`, `preselectpaths` dispatch | ~50 |
| `timeservice_pspaths.go` (new) | scheduler and writer (~110), `preselectpaths` (~280) | ~390 |
| `timeservice_pspaths.go` | quick mode: config loading, round loop, stages and elimination | ~130 |
| `timeservice_pspaths.go` | `-update`: incumbents, safeguards, config rewrite and validation | ~90 |
| `timeservice_pspaths.go` | quick mode: clock held on GNSS (PI on the CTS offset), drift check | ~30 |
| `timeservice_pspaths.go` | self-test, disturbance and loss checks, `-due` and state file | ~60 |
| `timeservice.go` | route-change detection (floor shift on two thirds of the paths), rescan request | ~40 |
| tests | `PreselectedPaths`, scheduler (batch composition, top-up, vanished paths), `preselectpaths` on a synthetic file with known biases | ~120 |

That is about 830 lines of Go plus tests. The earlier estimate of 25 lines covered only the config keys and assumed a Python script for the analysis.

## Phasing

**Status (November 17):** version 1 is implemented and has run at Thun (November 16 and 17) and Lausanne (November 16); see Quick scan. It consists of `core/client/paths.go` (`PathFingerprint`, `PathInterfaces`, `PreselectedPaths`), `core/client/filter.go` (`OnPick`), `service/ntlctsoff_*.go` (sink), `timeservice.go` (`scion_paths`, `preselectpaths`) and `timeservice_pspaths.go`, about 1200 lines of Go plus 380 lines of tests, twice the estimate below, mostly in `timeservice_pspaths.go` (about 1130 lines). Unit tests cover `PreselectedPaths`, batching, the config rewrite, the cutoff, the resilience rule, and the statistics pipeline with synthetic picks and CTS samples. The self-test, GNSS steering and measurements need a site with SCION connectivity and an NTL card.

| Version | Content | Lines |
|---|---|---|
| **1: manual quick scan** | `scion_paths` in the client (`PreselectedPaths`), filter hook, CTS sink, `preselectpaths -quick` (stages, cutoff, resilience rule, self-test, GNSS steering, disturbance, loss and drift checks, scan file), simple `-update` (replace the block, validate, keep `.prev`) | ~520 |
| 2: automation | incumbents and hysteresis, `-due` and state file, route-change detection in the client, systemd units | ~160 |
| 3: validation | week-long scan mode, `preselectpaths -scan` with hourly metrics and bootstrap | ~250 |

- **Version 1 is complete on its own.** Run it by hand at night, paste or `-update` the pool, and restart.
- **The first real scans calibrate the later versions.** The simulated numbers rest on a modelled population. Before automating, the first scans at Thun, Lausanne and Zurich should check the tolerance, the stage-3 cap, the dwells and the 200 µs trigger threshold, and settle the uplink 2 question.
- **The scan file format is fixed in version 1,** so that version 3 can re-analyse those files.
- **What version 1 lacks:** a reaction to route changes. Until version 2, a shift like Nov 10 shows up only in the CTS logs or on the dashboard and needs a manual scan.

## Workflow

**New site:**
1. Write a base config: `local_address`, the SCION connection, `ntp_reference_clocks` with the server, `sync_clock`, `ntl_ctsoff`, `filter_size`, `filter_max_rtd_excess` and the PI gains. No `scion_paths` is needed.
2. Run `timeservice preselectpaths -config client.toml -quick -update` once by hand. It appends `scion_paths`.
3. Start the service, and enable `timeservice-pathscan.timer` and `timeservice-pathscan.path`.

**Routine, at each site with a GNSS comparison:** the systemd timer runs `preselectpaths -quick -update` at night (see As a maintenance task). It stops the service, scans for about 30 minutes, updates `scion_paths` if a clearly better pool exists, and starts the service again. Run it once by hand first, at Thun to settle the uplink 2 question.

**Validation, occasionally:** to check that a pool also holds during weekday business hours, run the week-long scan over a quick scan's pool with a looser cutoff:
1. Set `scion_paths` to that pool and add `scion_path_scan`. Run for at least 7 full days.
2. Run `timeservice preselectpaths -scan path-scan.csv` on the file.
3. Put the printed pool into `scion_paths`, remove `scion_path_scan`, and restart.

## Review: new site and network change

Checked on November 16 against two cases: setting up a new site, and the Nov 10 reroute at Thun (`pilot/tmp/thun-20261110.log` and `.pdf`). Target: a client config with an optimal path preselection, from a scan of about 30 minutes over ~200 paths.

**What "optimal" means here.** The pool is the largest set of paths whose expected error over time (|e| and variation, root mean square over the paths `SelectPaths` picks) is within max(0.25 µs, 25 %) of the best achievable at scan time, each path itself within two tolerances of that best, and that keeps at least 5 paths after any single link failure. It is optimal for the conditions during the scan. It is not optimal across day and night, nor after later changes; the triggers below cover that.

**New site.** With the base config (see Workflow), `preselectpaths -quick -update` does the following:
1. It steers the clock to GNSS, stepping it first if it is far off.
2. It runs the self-test (2 min), which catches a wrong `ntl_ctsoff` index order or a CTS that does not compare the timestamping clock.
3. It runs the three stages (29 min) and appends `scion_paths`.

At a Thun-like site, the simulation gives a pool of 13 paths (11–15) and a clock error of 1.85 µs, against 1.3 µs for the ideal 10. The difference is the price of the extra redundancy and lies within the tolerance.

**Nov 10, replayed with the design:**

| Time (UTC) | Actual | With the design |
|---|---|---|
| 06:50:22–06:51:49 | All 7 paths fail (SCMP External Interface Down) | Same |
| 06:51:50 | RTD −1.67 ms on all paths; 224 picks rejected by the RTD gate within a minute; floors adapt | Same |
| 06:52–07:10 | Clock ramps to +8 µs | Same |
| ~06:55 | — | Floor check: all 7 floors moved by −1.67 ms against 15 min earlier → WARN |
| ~07:10 | — | No further shift for 15 min → rescan request → scan starts; the clock is steered back to GNSS within minutes |
| ~07:41 | — | New pool written, service restarted |
| from ~07:50 | Clock stays at +8 µs, still on Nov 16 | Clock at the new pool's bias, about 1.9 µs in the simulation, possibly with uplink-2 paths |
| following night | — | Confirmation scan under quiet conditions |

**Gaps found and closed in this review:**
1. **Scan time** (superseded after the first real scan, where up to 60 minutes became acceptable; see Stages). With 20 / 60 / 120 s and a stage-3 cap of 49, the data-driven cutoff took 36 minutes. Then 20 / 45 / 120 s with a cap of 35 took 29 minutes plus 2 for the self-test, with comparable accuracy (see Expected duration and quality).
2. **No trigger after a network change.** Monthly scans would have left Thun 8 µs off for weeks. Added: route-change detection in the client, a rescan request, and a systemd path unit.
3. **New-site misconfiguration.** A wrong CTS index order or clock would have produced a wrong ranking silently. Added: the self-test.
4. **Server excursions during a scan** (like Nov 4 and Nov 9) would have biased every path. Added: the disturbance check.
5. **Lossy or unreachable paths** had no rule in the quick scan. Added: the loss rule.
6. **Scheduler and stages** were not coupled. Specified: explicit candidates and dwell per stage.
7. **Weekly runs only.** Now a daily timer with `ExecCondition` runs the scan when due, which also covers confirmation scans.

**Remaining limits:**
- An asymmetry change without a delay change is caught only by the weekly scan.
- Night scans do not see the weekday business-hours ramp.
- A steady µs-level server offset enters every e alike.
- The simulated numbers rest on a Thun-like population: the measured uplink-1 paths, an assumed uplink 2 at ±11 µs, Gaussian noise and stable conditions. The first real quick scan at Thun will show how close they are.

## Limits

- **Pilot sites only.** Ranking needs a GNSS reference. Without one, the same scan could rank paths only relative to each other.
- **Shared segments are not selectable.** All Thun paths in use share 2:0:2c#1 → 64-3303#21. The Nov 10 reroute moved every path by about −8.5 µs, and no pool avoids that, unless uplink 2 now qualifies (see Quick scan).
- **Absolute ranking chases the current common mode.** Ranking by |e| favours paths whose own asymmetry offsets the shared uplink's current one. If the uplink changes route, the pool is no longer optimal; hence the rescan trigger.
- **The pool is a snapshot.** Results hold for the site and the scanned week.

## Open decisions

1. **Score:** absolute 95th-percentile hourly |e| (proposed), or the deviation from the hourly common mode, which ignores the shared uplink.
2. **Pool rule:** data-driven cutoff on the scores with tolerance max(0.25 µs, 25 %) and a per-path ceiling, at least 10 paths, `remain` = 5.
3. **Dwell:** 60 s.
4. **Path policy:** exclusions (interfaces, geography) to return as a general pre-filter for scan and client; `scion_excluded_interfaces` was removed on November 17.
5. **Quick-scan schedule:** 20 s / 45 s / one continuous 9-minute window, cap 21 after stage 2 (proposed).
6. **Maintenance:** monthly at night (proposed), plus after a flagged reroute.

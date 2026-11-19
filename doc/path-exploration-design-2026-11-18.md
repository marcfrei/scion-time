# Continuous path exploration

- **Date:** November 18, 2026
- **Status:** design proposal, not implemented
- **Revision:** `4b75847` (branch `pilot-sync-accuracy`)
- **Builds on:** [Path scan and selection against GNSS](path-scan-design-2026-11-16.md)

The client keeps synchronizing over 7 paths per server. In the pause between two synchronization rounds, a path explorer measures up to 7 other paths with a second set of clients. At the pilot sites every path to the server is then measured two to four times an hour, around the clock. From a week of these measurements the explorer keeps a pool of paths that are accurate and stable, and the existing path selection picks its 7 paths from that pool. A path in use that leaves the pool is replaced by the existing mechanism.

Three results from the pilot data shape the design:

1. **Only an independent reference can tell which paths are symmetric.** Seven reference-free rules were tested on 334 paths at Thun and Lausanne. They miss by 8 to 104 µs; selection against GNSS reaches 1 to 3 µs.
2. **Everything else works without a reference.** Paths can be compared with each other as precisely as against GNSS, and a path's error lasts for weeks. So a pool found once can be watched and maintained without GNSS.
3. **Seven paths cannot judge themselves.** In both incidents that degraded Thun, four of the seven paths in use moved together, and the other three looked just as unstable. The explorer's wider set of paths, or GNSS, is needed to see which group moved.

The proposal therefore uses GNSS for one thing only, to rank paths, and limits its influence: it is slow, it is checked against the paths' own history, and it never steers the clock.

## Terms

| Term | Meaning |
|---|---|
| pick | The lucky packet of one path in one round: its offset and round-trip delay (RTD). |
| e | A path's error: the offset of a pick minus the reference at that time. |
| reference | The offset of the local clock as known independently of the path: from GNSS (NTL CTS offset), or, without GNSS, from the paths in use. |
| sample | One path, one minute: the mean of e over its picks, and the noise of that mean. |
| score | A path's typical error over the last week, in µs. Lower is better. |
| pool | The paths the client may use for a server (the preselected paths, today `scion_paths`). |
| paths in use | The 7 paths the sync clients currently measure. |
| candidate | Any other available path to the server. |
| cycle | One pass of the explorer over all candidates. |

## What the data says

All scripts are in [`pilot/analysis/explore/`](../pilot/analysis/explore/). They use the three quick scans (every path against GNSS, clock held on GNSS) and the client logs of runs 5 to 13 (the paths in use, around the clock).

### No reference-free rule finds the symmetric paths

| Rule for choosing paths without a reference | Thun (224 paths) | Lausanne (110 paths) |
|---|---|---|
| Zero is the median of all paths | −7.7 µs | −9.2 µs |
| Zero is the densest cluster (2 µs wide) | −12.0 µs | −8.1 µs |
| The 10 paths with the lowest RTD | −11.6 µs | −104.0 µs |
| The 10 paths with the fewest AS hops | −14.4 µs | −104.0 µs |
| The 10 paths with the least pick noise | −10.8 µs | −104.0 µs |
| The 10 paths whose picks stay closest to the RTD floor | +86.9 µs | −104.5 µs |
| The fastest packet in each direction took a symmetric route | −11.2 µs | −103.4 µs |
| **Against GNSS: the 10 paths with the lowest \|e\|** | **−0.05 µs** (mean \|e\| 0.7) | **−2.0 µs** (mean \|e\| 2.1) |

Each value is the error against GNSS of what the rule selects ([`population.py`](../pilot/analysis/explore/population.py), [`predictors.py`](../pilot/analysis/explore/predictors.py), [`dirmin.py`](../pilot/analysis/explore/dirmin.py)).

- **Most paths are not symmetric.** Only 8 % of Thun's paths and 4 % of Lausanne's are within ±2 µs. The bulk lies between −30 and 0 µs, and a separate cluster of about 40 paths lies near +88 µs (Thun) or −104 µs (Lausanne).
- **Lucky-packet quality says nothing about symmetry.** Within the main cluster, the rank correlation of |e| with RTD floor, hop count, pick noise, RTD excess and gate rejections is between −0.32 and +0.14, and for three of the five the sign differs between the sites. At Lausanne, the paths with the lowest delay and the least noise are the ones 104 µs off.
- **The error belongs to how a path crosses an AS.** At Thun, where a path leaves AS 3303 decides most of it. On uplink 1, paths through exits 30 and 31 have median errors of +1.9 and −3.0 µs, and paths through the other eight exits −9 to −18 µs ([`byhop.py`](../pilot/analysis/explore/byhop.py)). The two good exits are the minority, so a majority rule over routes fails too.
- **A model of AS crossings does not replace measuring.** Fitting each path's error as a sum of its crossings explains the far clusters. But it predicts an unmeasured path only to ±4.0 µs (Thun) and ±3.3 µs (Lausanne), far from what selection needs ([`tomography.py`](../pilot/analysis/explore/tomography.py)).

This matches theory. A two-way exchange cannot separate a clock offset from a delay asymmetry [4]. With several paths, the differences between their asymmetries are measurable, but deciding which group of paths is the symmetric one needs an assumption or an outside reference [2].

### What works without a reference

- **Comparing paths.** The offset of a path relative to the other paths measured in the same round is as precise as its error against GNSS: 2.25 against 2.24 µs for a 30 s mean ([`precision.py`](../pilot/analysis/explore/precision.py)). The pick noise dominates; the reference adds nothing.
- **Remembering.** A path's error at the same time of day changes little between runs: by a median of 0.4 µs (at most 1.8 µs) over up to 24 days at Lausanne, and by at most 0.15 µs at Zurich ([`persistence.py`](../pilot/analysis/explore/persistence.py)). Changes come as steps (a reroute) or as daily cycles, not as drift.
- **Seeing a reroute.** The RTD floor of every Thun path in use jumped at the Nov 10 reroute, and a 100 µs threshold flags all seven at 06:56 UTC, with no false alarm in ten other runs ([`rtdstep.py`](../pilot/analysis/explore/rtdstep.py)). It is a reason to look again, not a verdict: one Lausanne path took a 242 µs detour for four hours in the night of Nov 9 without any change in its error.

### Where a small set of paths fails

Over 118 path-runs, a path's variation relative to the other six in use tracks its variation against GNSS well (rank correlation +0.74). It fails in the two cases that mattered ([`stability.py`](../pilot/analysis/explore/stability.py)):

| Run | Paths that moved | Variation against GNSS: moved / stable | Variation relative to the others: all seven |
|---|---|---|---|
| 12 (uplink 2 oscillation) | 4 of 7 | 2.5–2.8 µs / 0.9–1.4 µs | 1.3–1.7 µs |
| 13 (weekday cycle) | 4 of 7 | 3.2–3.5 µs / 0.7–1.0 µs | 1.6–1.9 µs |

Four paths that move together are the majority of seven, so the stable three look as unstable as the rest. The RTD separates the groups in run 12 but not in run 13. A wider and more varied set of paths is needed to tell who moved, and that is what the explorer measures.

### Measuring: precision, side effects, outliers

| Window on one path | 30 s | 60 s | 2 min | 5 min | 9 min | 15 min |
|---|---|---|---|---|---|---|
| Precision of the mean e (median path) | 2.2 µs | 1.6 µs | 1.15 µs | 0.7 µs | 0.6 µs | 0.43 µs |

- **The noise is white,** so precision depends only on the total time spent on a path, not on how it is split. Seven explorer slots give each of Thun's 217 candidates 46 minutes a day, so its daily mean is precise to 0.23 µs. Thun's cycle is 31 minutes, Lausanne's 15.
- **More parallel streams bias the measurement.** On October 23, 13 parallel streams instead of 7 shifted the shared paths by −2.2 to −3.2 µs at Thun and raised their RTD by 8–11 µs. The explorer must not measure while the sync clients do.
- **Plain statistics break on server bursts.** In run 11, the server bursts of Nov 9 push a mean-and-standard-deviation score to 340–800 µs for every path. A median-and-quartile score stays at 3–8 µs ([`replay.py`](../pilot/analysis/explore/replay.py)).
- **Raw samples are not logged.** The logs hold one pick per path and round. Rules that need the delay distribution within a round, as in [1], cannot be tested on existing data.

## Design

### Overview

```text
sync clients (7 paths in use)    |==round===|........ pause, 1.0 s ........|==round===|
explorer clients (7 candidates)              .........|==round===|.........
                                 0           0.4 s    0.7 s       1.1 s    1.4 s
```

```text
picks of the paths in use  ─┐
                            ├─►  samples  ─►  history per path  ─►  score  ─►  pool  ─►  path selection
picks of the candidates    ─┘      ▲            (one week)                 (per server)   (unchanged)
                               reference
```

Each SCION reference clock (server) gets its own explorer. The explorer adds one goroutine and 7 `SCIONClient`s per server. It does not touch the measurement, filter, combination or clock control of the sync path. Its only output is the pool. Peer clocks are not explored.

The rules in one place:

1. **Sample:** one value per measured path and minute.
2. **Guard:** a minute in which nearly all measured paths shift the same way is set aside.
3. **Score:** a path's typical error over the last week.
4. **Eligible:** a path with at least a day of history that it still agrees with.
5. **Decide:** after each cycle, select the pool from the eligible paths. Incumbents stay. No evidence, no change.
6. **A day decides:** a day of disagreement, or of a held shift, starts new histories.

### Measuring

- **A second set of 7 clients,** built and configured exactly like the sync clients: interleaved mode, hardware timestamps, lucky-packet filter, DSCP, authentication. A candidate is therefore measured as it would be when in use.
- **In the pause.** After each sync round the explorer runs one round of its own, centred in the pause, with the sync timeout. Both kinds of round then follow the same quiet time, and they never overlap. With the defaults a sync round takes 0.4 s and the pause 1 s.
- **Batches.** At the start of a cycle the explorer takes all available paths that are not in use, shuffles them, and measures them 7 at a time for 60 s each. A short last batch is topped up from the start. This is the batch loop of the quick scan.
- **Paths in use are measured anyway.** Their picks come from the sync clients through the existing `Filter.OnPick` hook.
- **Samples.** Per path and minute, the explorer keeps the number of picks, the mean and standard deviation of their offsets, and the minimum RTD. The first pick after a path switch is dropped, as in the quick scan.
- **Quiet logging.** The explorer's clients log at WARN only. Their "measured clock offset" lines would double the log, and the analysis scripts would take them for paths in use.

**Load.** The client sends twice as many requests. The server keeps 16 interleaved-mode entries per client host (`tssItemCap`), and 14 are needed.

### Reference

The reference is one value per minute: the mean offset of the local clock during that minute, as known independently of the path. A sample's e is the mean offset of its picks minus the reference of its minute. Within a minute the local clock moves by 0.04 µs against GNSS (standard deviation, run 13), while the picks scatter by about 10 µs, so nothing finer is needed. The explorer gets the reference as a function, so that the rest does not depend on its source:

```go
// reference returns the mean offset of the local clock in a minute, if known.
type reference func(minute time.Time) (off time.Duration, ok bool)
```

- **GNSS:** the mean of the NTL CTS offsets of the minute. e then contains the path's asymmetry and the server's own error, and does not depend on how the local clock is steered.
- **Paths in use (later, see Without GNSS):** the mean combined offset of the sync rounds of the minute. e is then the path's error relative to the paths in use.

**Guard: the reference may not move all paths at once.** Each minute, the explorer has samples of up to 14 paths: the 7 in use and 7 candidates. If all but at most two of them deviate from the median of their own history in the same direction by more than 2 µs, the minute tells something about the reference, the server, or a link that all paths share, and nothing about single paths. Its samples are set aside. Paths without a history do not vote, and with fewer than 8 voters the guard does not judge.

- **A server burst is set aside this way.** The burst of Nov 9 at 23:11 UTC is flagged at Thun and at Lausanne in the same four minutes ([`guard.py`](../pilot/analysis/explore/guard.py), replayed with the paths in use as voters).
- **A step of the reference by 5 µs or more is held back.** At 4 µs, about four minutes in five are. Both figures are estimates from the sample noise.
- **A shift that lasts a day is accepted.** If the guard has set aside nearly every minute for 24 hours, the samples of that day become the new histories, and a WARN says so. A real change of a link that all paths share looks the same from the client and has to be followed eventually.
- **The candidates are the independent voters.** The 7 candidates of a minute are a random draw from all paths. With only the paths in use as voters, a correlated group of four plus one noisy path trips the guard in 13–19 % of the minutes of runs 12 and 13.

### Scoring

- **History:** a path's samples of the last 7 days. A week covers weekday business hours, nights and a weekend.
- **Score:** the path's typical error over that time, robust against outliers:

  ```go
  // score = sqrt(median² + spread²) over the samples of the history;
  // spread is what the samples vary by beyond their own noise.
  func score(h []sample) float64 {
  	m := means(h)
  	spread2 := max(sq(iqr(m)/1.349)-mean(noise(h)), 0)
  	return math.Sqrt(sq(median(m)) + spread2)
  }
  ```

  A constant asymmetry enters through the median. A weekday cycle or an oscillation enters through the spread. This is the score of the quick scan, with the mean and standard deviation replaced by the median and the interquartile range.
- **Agreement:** a path agrees with its history when the median of its latest samples is within 4 µs of the median of the history. The latest samples are the last 30 minutes for a path in use and the last 5 samples for a candidate. For a noisy path the threshold is 5 standard errors, if that is more.
- **Eligible:** a history of at least 24 hours and 24 samples, and agreement. A path is judged by its history only after it has been seen by day and by night, and only while it still behaves as that history says.
- **A day of disagreement starts a new history.** If a path has disagreed for 24 hours, its history is cut where the disagreement began. A rerouted path is thus out for a day and then judged on its new route. A path that swings with the weekday cycle never disagrees for a full day, so its history keeps both halves of the cycle and its score shows the swing.

Replays of the agreement rule ([`agree.py`](../pilot/analysis/explore/agree.py), [`agreecand.py`](../pilot/analysis/explore/agreecand.py)):

| Data | Result |
|---|---|
| Undisturbed runs, paths in use (lausanne-12, thun-7: 21 paths) | All agree all the time. |
| The same at a candidate's cadence (thun-7, lausanne-7, lausanne-12: 116 series) | None ever disagrees. |
| Run 13, weekday cycle | The 3 flat paths agree all the time. The 4 swinging paths disagree for 33–46 % of it, in stretches of at most 7.5 hours. |
| Run 11, reroute at 06:52 UTC | 5 of the 7 paths disagree from 07:01–07:07 UTC to the end of the run. The other 2 wander by themselves and disagree on and off, for 11–13 % of the run. |

### Deciding

After each cycle:

1. **Select.** Run the quick scan's `selectPool` on the eligible paths and their scores. It keeps the largest pool whose expected error (the root mean square score of the 7 paths `SelectPaths` picks) is within max(0.25 µs, 25 %) of the best. The pool has at least 10 paths, each below a ceiling, plus paths below that ceiling as needed so that 5 remain after the loss of any one interface.
2. **Keep incumbents.** A path already in the pool stays while it is eligible and its score is within one more tolerance of the ceiling. Score noise then does not move paths in and out.
3. **No evidence, no change.** With fewer than 10 eligible paths the explorer does not select. This covers the first day, a missing reference, and a held reference shift.

Between decisions, a pool path that stops being eligible is left out, unless fewer than 7 would remain; then nothing better is known and the pool stays as it is.

The pool is handed to the reference clock, which replaces its `paths` list. Nothing else is needed: `MeasureClockOffsetSCION` keeps a client on its path while that path is among the offered ones, and gives it a new one from `SelectPaths` otherwise. A better path entering the pool does not displace a path in use. The pool says which paths are good enough; which 7 are used stays with `SelectPaths` and path-keeping.

### State and observability

- **Sample files.** One CSV file per server and UTC day in a state directory, in the style of the scan file: `p` rows for paths, `x` rows for samples (minute, path, in use or candidate, picks, mean and standard deviation of the offsets, minimum RTD), and `r` rows for the minute's reference values (GNSS, and the combined offset of the paths in use). About 1 MB per day at Thun.
- **The files hold measurements, not conclusions.** At start the explorer reads the last 7 days and rebuilds histories, the guard's verdicts and scores with the same code that runs live. Rules can therefore be changed and tested by replay, also with another reference.
- **Pool file.** The current pool, written at each change in the format of the `scion_paths` block. It is read at start, so a restart does not reshuffle the paths.
- **Report.** `timeservice preselectpaths -report DIR` prints the ranking, the pool, its expected error and its single points of failure from the files, like the quick-scan report.
- **Log.** INFO when the pool changes, with the paths and scores. WARN for a stretch of minutes set aside, an accepted reference shift, a path in use that stops agreeing, and a missing reference.

### Configuration

```toml
scion_path_exploration = "observe"                        # "observe" or "apply"; absent: off
scion_path_exploration_dir = "/var/lib/timeservice/paths"
ntl_ctsoff = "..."                                        # the reference, required for now
scion_paths = [ ... ]                                     # optional: the pool until the explorer has decided
```

- **`observe`** measures, writes the files and reports, and leaves the pool alone.
- **`apply`** also updates the pool.
- **`scion_paths`** remains the pool while the explorer has not decided, and the only pool when exploration is off. The explorer never rewrites the configuration.
- Window, dwell and thresholds are constants in the code at first, like those of the quick scan.

## How far to trust GNSS

**As far as needed, and no further.** GNSS is needed to say which paths are symmetric; the first table of this document leaves no alternative at the microsecond level. The telecom standard for this situation does the same: with assisted partial timing support, a clock measures the asymmetry of its network path against GNSS while GNSS is available, and relies on that calibration when GNSS fails [5].

What limits its influence:

| Limit | How |
|---|---|
| It only ranks paths | GNSS never corrects a measurement and never steers the clock. A wrong reference can at worst make the client use real paths whose asymmetry matches the error. |
| It is slow | A path needs a day of history to enter the pool, and scores cover a week. A disturbance of minutes or hours changes nothing. |
| It is checked against the paths | The guard sets aside a shift that nearly all paths show at once. The paths' week of history is the yardstick, and it is precise: a common shift of 5 µs is evident within a minute. |
| It is visible | Every held stretch and every accepted shift is logged. `observe` mode shows what GNSS would decide before it decides anything. |

What remains:

- **A lasting error of the reference is followed after a day.** The guard holds it for 24 hours and then accepts it, because a real change of a link shared by all paths looks the same. At Lausanne, with its single uplink, the two cannot be told apart at all. After acceptance the pool moves to the paths that match the new reference.
- **A shift below about 4 µs is not held.** It enters the histories like any measurement.
- **How far the pool can follow depends on the paths.** Thun has paths at almost every error between −30 and +5 µs, so within that range a wrong reference would find a matching pool.
- **The pool also absorbs a constant error of the server.** A path whose asymmetry offsets it scores best. That is what the scans do today; it holds as long as the server's error stays constant.

Options if this is not enough: accept a held shift only after an operator confirms it, or lengthen the hold. Both cost accuracy after a genuine network change. For the pilot I recommend the automatic acceptance with a WARN.

## Without GNSS

**Holdover.** When the GNSS reference is missing, the explorer can switch to the paths in use as reference. Everything else stays the same. It then keeps the pool consistent: a path in use that departs from the others stops agreeing and is dropped, and a candidate that agrees with them over a week can replace it. The frame of the last GNSS-based pool is kept, because path errors last for weeks. What this cannot do is notice a movement of the majority of the paths in use, as in runs 12 and 13.

**Sites that never have GNSS.** Exploration without a reference makes the pool stable, not accurate. At the pilot sites the result would sit 8 to 12 µs from GNSS. Three ways to give such a site an accurate pool:

1. **Share the pool within an AS.** Path fingerprints are the same for every client in an AS, and so are the errors of everything beyond the border router. One client with GNSS can supply the pool file to the others. This is the cheapest route to accurate clients without GNSS, and the pool file has the format for it. It assumes that the stretch between client and border router adds little asymmetry, which a second client in a pilot AS can check.
2. **Calibrate at commissioning** with a temporary reference and the quick scan, then run in holdover.
3. **No calibration:** the client uses all paths as today, and gains only the removal of unstable ones.

**Heuristics worth an experiment.** None is part of the design; each needs data first.

| Idea | What it could give | What it needs |
|---|---|---|
| Delay spread per direction within a round [1] | An indicator of load in one direction, and so of the weekday cycle, without a reference. In run 13 the cycle is mostly a forward delay of 8–10 µs that is present by day ([`oneway.py`](../pilot/analysis/explore/oneway.py)). | Two more columns per sample: median minus minimum of the forward and of the reverse delay over the round's exchanges. Then a week of explorer data. |
| RTD floor jump | A reference-free reason to distrust a path's history after a reroute. | Nothing new; already replayed. |
| Two packet sizes | The part of an asymmetry that comes from different link rates in the two directions grows with packet size. | Padded requests and responses, so a server change. |
| Cyclic measurements [2] | Nothing new: sending out on one path and back on another yields the same differences that simultaneous offsets already give. | — |

The first weeks of explorer files in `observe` mode are the data set for all of this: every path, at every time of day, with offsets and reference kept apart, so that a replay can use the GNSS reference, the paths in use, or none.

## Behaviour in the pilot's events

| Event | Without the explorer | With the explorer (expected) |
|---|---|---|
| Nov 9, server bursts | Clock excursions | The guard sets the minutes aside and the scores are robust anyway. The excursions themselves are a server matter. |
| Nov 10, reroute of Thun's uplink 1, every path in use about 8.5 µs off | Noticed in the logs; pool replaced after a manual scan on Nov 16 | Within about an hour the paths in use stop agreeing with their histories (5 of 7 in the replay) and are left out where a better known path exists. After 24 hours the rerouted paths have new histories, and the pool is chosen for the new routes. |
| Nov 16/17, uplink 2 oscillation | 7 of 23 pool paths oscillated; found by analysis the next day | The spread of these paths is 3–5 µs. They do not enter the pool. |
| Nov 17/18, weekday cycle, 4 of 7 paths swing by 6.7 µs | Found by analysis; day and night scans proposed | Every path is seen by day and by night within 24 hours. Swinging paths score about 4 µs and disagree for part of each day. They leave the pool once 10 better paths are known. |

The last row also answers the question left open after run 13. The explorer in `observe` mode collects the day and night data for all paths without stopping the client, so the two manual scans are not needed.

## Code changes

| File | Change | Lines |
|---|---|---|
| `timeservice.go` | 2 config keys; pool as an atomic value in `ntpReferenceClockSCION`; explorer start in `createClocks`; one call after the sync measurement; CTS sink in `runClient`; `-report` dispatch | ~45 |
| `timeservice_pspaths.go` | `selectPool` takes scores from the caller and returns its ceiling | ~15 |
| `timeservice_psexplore.go` (new) | explorer loop and batches (~60), samples and guard (~70), history, score and agreement (~60), decision (~40), files (~70) | ~300 |
| `timeservice_psexplore.go` | report from the files | ~40 |
| tests | score, guard, agreement and decision on synthetic picks; replay of a recorded file | ~200 |

The quick scan stays as it is. It remains the tool for a new site, where it gives a pool in an hour instead of a day, and it shares the pick handling and the pool selection with the explorer.

## Phasing

| Phase | Content | To be learned first |
|---|---|---|
| **1: observe** | Explorer loop, samples, files. The report shows the scores and the pool as it would be. No pool changes. | — |
| **2: apply** | The same rules live: guard, agreement, decisions, pool hand-over. | From phase 1: whether measuring in the pause disturbs the sync paths; whether a path scores the same in use and as a candidate; how many paths swing with the weekday cycle; the thresholds. |
| **3: holdover** | Paths in use as reference when GNSS is missing; pool file import for clients without GNSS. | From replaying phase 1 files without the reference. |

- **Phase 1 is useful by itself.** It replaces the manual day and night scans and the planned week-long scan mode, and it yields the data to check every number in this proposal.
- **Phase 2 changes behaviour only through the pool,** which is the mechanism in production since November 16.
- **What this replaces from the earlier design:** scan mode in the client, the offline ranking of a week-long scan, the systemd timer and the rescan trigger. Those were ways to repeat a snapshot; the explorer keeps the picture current.

## Alternatives considered

- **Rotate the sync clients themselves** (the earlier scan mode). The clock then follows whatever is being measured, and three strongly asymmetric paths in a batch pull it for a minute.
- **A separate process** that scans and rewrites the configuration. It cannot see when sync rounds run, so it cannot stay out of their way, and the client would need a reload mechanism.
- **Fewer explorer clients.** Less load, but candidates would be measured among fewer parallel streams than paths in use, and a cycle would take longer.
- **Correct paths instead of selecting them.** Subtracting each path's measured error would make every stable path usable. It would also make the clock depend on stored corrections and give the reference direct influence on the time. Selection keeps the reference one step away.
- **A model of AS crossings** to predict unmeasured paths. Not precise enough (±4 µs), and there is time to measure every path.
- **Restart a path's history at every change.** Simple, but a path with a daily cycle would be restarted at every ramp and could never show its swing in a score. Requiring agreement, and a new history only after a full day, keeps the cycle in the history.

## Limits and open decisions

**Limits**

- **A link shared by all paths cannot be selected away.** The explorer reports its shift and then finds the best pool for the new situation.
- **The first day has no decisions,** and the first week does not yet cover a weekend. A quick scan gives the starting pool.
- **A change that hits most of the pool costs a day.** The changed paths are out until they have a day of new history. Meanwhile the client uses the best paths that did not change, even if the changed ones happen to be better.
- **Candidates learn of a reroute late.** A candidate looks unchanged until it has been sampled five times, which takes 2.5 hours at Thun. Until then the explorer may pick it on old evidence; once in use, it is caught within half an hour.
- **Instability that sets in slowly is caught slowly.** A path in use that starts to oscillate without moving its median keeps agreeing. Its score rises only as the week fills with the new behaviour, which takes about two days.
- **Many more paths.** With 1000 paths a cycle takes 2.4 hours, which still gives 10 samples per path and day. Beyond that the explorer would have to prioritise.
- **The numbers come from two sites and four weeks.** The thresholds (2 µs and all but two for the guard, 4 µs for agreement, 24 hours, 7 days) are starting values for phase 1 to confirm.

**Open decisions**

1. **Reference shifts:** accept automatically after 24 hours with a WARN (proposed), or wait for an operator.
2. **Load:** explore in every pause (proposed for the pilot), or in every n-th pause where many clients share a server.
3. **Scope:** start with `observe` at Thun and Lausanne (proposed). Zurich has only 2 paths, which leaves nothing to explore.
4. **Clients without GNSS:** is sharing a pool within an AS the intended route? It decides how much of phase 3 is needed.
5. **Files:** the explorer never deletes sample files (proposed); cleanup is left to the operator.

## Sources

1. I. Hadžić, D. R. Morgan, "On packet selection criteria for clock recovery", ISPCS 2009. The minimum-delay filter works only while unqueued packets exist; under load the delay floor itself rises.
2. A. Finkenzeller et al., "PTPsec: securing the Precision Time Protocol against time delay attacks using cyclic path asymmetry analysis", INFOCOM 2024. Asymmetry differences between redundant paths are measurable; at least one path must be known to be symmetric.
3. M. Moradi, A. H. Jahangir, "Enhanced time-delay attack detection algorithm for precision time protocol", Cybersecurity 8:88, 2025. Localises a delay attack to a link by reports from the clocks.
4. L. Narula, T. Humphreys, "Requirements for secure clock synchronization", [arXiv:1710.05798](https://arxiv.org/abs/1710.05798). A delay is indistinguishable from a clock offset without further assumptions.
5. ITU-T G.8273.4, assisted partial timing support: GNSS calibrates the asymmetry of the network path that backs it up. Overview: [Calnex, standards for time and phase](https://calnexsolutions.atlassian.net/wiki/spaces/GDW/pages/8388791/2.+Standards+aimed+at+delivering+time+and+phase+to+better+than+1.5us).
6. A. Shpiner et al., [RFC 8039, Multipath Time Synchronization](https://www.rfc-editor.org/rfc/rfc8039.html). Leaves the combining algorithm open; an attack on a segment shared by the paths is not mitigated.
7. D. L. Mills, [the huff-n'-puff filter](https://www.eecis.udel.edu/~mills/ntp/html/huffpuff.html). Corrects the offset by half the delay above the minimum. In the pilot data, e and RTD are unrelated (R² median 0.04 over 118 path-runs), so it does not apply.

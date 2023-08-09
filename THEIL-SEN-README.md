# Theil-Sen

This branch contains the implementation of an alternative sample offset interpolation algorithm, based on the [Theil-Sen estimator](https://en.wikipedia.org/wiki/Theil%E2%80%93Sen_estimator).
Currently, the standard sample offset interpolation algorithm (also called a clock discipline algorithm) in `scion-time` is a Phase-Locked Loop (PLL), taken from [Ntimed](https://github.com/bsdphk/Ntimed/blob/master/pll_std.c#L50).
Various alternative estimator algorithms were investigated (Kalman Filters, Least Absolute Deviations), with Theil-Sen being chosen as a first target.
It offers simplicity and is well-studied from a mathematical standpoint.

## Implementation

Like in the original paper by Sen, the implementation ignores pairs of coordinates with the same x-coordinate when computing the slope.
It would in principle be possible to implement the slope calculation with O(n) complexity, since one could cache the previously calculated slopes. 
There also exist deterministic and randomized algorithms that compute the Theil-Sen estimator from scratch in O(n log n) time. 
However, since we only keep a small number of samples (64 by default), the naive implementation requiring O(n²) operations is not a bottleneck, yet is much more straightforward to understand.

## Issues with oscillations

When running Theil-Sen with 64 samples and no dropping, increasing oscillations were observed.
Offset predictions of Theil-Sen lag behind the true offset, since the median slope of the last 64 samples (∼2 minutes, by default in G-SINC a new sample arrives every two seconds) is near zero despite the oscillations. 
Because of the inertia of Theil-Sen, the delayed corrections then continue beyond when the offset is zero again, which amplifies the oscillations further. 
As a countermeasure to this, we introduced dropping.
There are likely other ways to fix the issue as well.

## Dropping

One approach that is also used in chrony for their regression algorithms is to introduce an error metric for the quality of the prediction.
If the error is too high, the oldest samples are dropped from the calculations until the error decreases to a satisfactory level. 
Like in chrony, we chose the sum of absolute differences between the predictions and actual data points as error metric. Other error metrics (Mean Squared Error, or errors weighted by recency) could be interesting to consider as well.

Dropping does indeed reduce the oscillations significantly.

## Current state of the implementation

Theil-Sen with dropping performs well on a server when a reference clock (e.g. GNSS) is available (offsets less than 1µs), outperforming the PLL (offsets less than 1.5µs).
On the client, Theil-Sen is worse (offsets of the order of 30µs) than the PLL (offsets of the order of 5µs).

The error metric and the error threshold could be tuned.
Alternatives to dropping to combat oscillations could be investigated.
One could also abandon the Theil-Sen estimator and look into e.g. Kalman filters.
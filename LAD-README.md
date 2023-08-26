# Least Absolute Deviations (LAD)

This branch contains the implementation of an alternative sample offset interpolation algorithm, based on [Least Absolute Deviations](https://en.wikipedia.org/wiki/Least_absolute_deviations).
Currently, the standard sample offset interpolation algorithm (also called a clock discipline algorithm) in `scion-time` is a Phase-Locked Loop (PLL), taken from [Ntimed](https://github.com/bsdphk/Ntimed/blob/master/pll_std.c#L50).
Various alternative estimator algorithms were investigated (e.g. Kalman Filters), with Theil-Sen being chosen as a first target, and LAD being a second target.

## Implementation

The implementation follows the LAD implementation in chrony, found in `regress.c`. chrony says that they themselves used the book "Numerical Recipes for C".
chrony deviates from the vanilla LAD algorithm by introducing a dropping mechanism where the oldest samples are dropped if a newer set of samples performs better.

## Current state of the implementation

The implementation works, however the performance is still lacking in comparison to Theil-Sen and PLL.
It would be good to investigate and validate further how chrony processes the offsets from LAD until the final adjustment.
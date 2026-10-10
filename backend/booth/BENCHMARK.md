# ThinkPad booth measurements — October 9, 2026

Measured on the teammate's Lenovo ThinkPad E15, Windows, Python 3.13.14,
cryptography 50.0.2. Each sample is a complete real isolated-process attack of
both independent DH channels, including launch and event collection. ML-KEM
send/positive-control work precedes the attack timer. Power and machine load
were not independently controlled. These are not demo-Mac measurements.

| Manual bits | Runs | Median ms | p95 ms | Maximum ms | Correctness |
|---|---:|---:|---:|---:|---|
| 40 | 20 | 1999.8435 | 2443.145 | 2777.035 | 20 PASS |
| 36 | 20 | 716.961 | 849.641 | 901.814 | 20 PASS |

Nearest-rank p95 is sample 19 after sorting 20 samples. The 40-bit group missed
the laptop's under-two-second target. The 36-bit option met it and its p95 was
below one second. No automatic switch was made; the production default is 40.
Repeat on the demo Mac and apply the team's timing gate to choose the size.

40-bit samples (ms):

```
1891.334, 1837.193, 1988.368, 2301.686, 1716.394,
2162.088, 1866.236, 1729.299, 2011.319, 1314.849,
2443.145, 1640.814, 2386.028, 1894.834, 2777.035,
2086.133, 2066.725, 2354.432, 1977.103, 2297.187
```

36-bit samples (ms):

```
771.038, 637.672, 696.007, 712.448, 731.242,
765.612, 751.759, 592.848, 819.707, 770.202,
761.31, 721.474, 684.112, 901.814, 696.574,
692.25, 849.641, 699.68, 696.416, 709.558
```

Protocol/control/runner validation: 16 tests passed, including twenty fresh
32-bit sessions, independent per-channel exponent verification, combiner and
disclosure controls, sabotage, damaged ciphertext, actual localhost HTTP API,
timeout, cancellation, overlap prevention, and recovery. This verifies booth
behavior, not full application integration, OpenSSL, UI, or demo-Mac behavior.

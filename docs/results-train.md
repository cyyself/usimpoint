# Validation: 10 SPEC CPU 2026 train workloads on the SpacemiT K3

Checkpoints captured with QEMU on x86 (`tools/validate.py capture`), replayed
on the K3 as replay-mode ELFies under `usp-run` (pinned to CPU 3, 3 repetitions,
median). Ground truth: full native run of the same static binary on the K3
(`usp-run -w 0`, 3 repetitions, median; run-to-run spread ≤ 0.5%).

Error = weighted checkpoint CPI vs full-run CPI. It is split into
- **SimPoint error**: weighted *native* CPI of the chosen intervals (from one
  native run sampled every 20M instructions with `perf record -c 20000000`)
  vs full-run CPI — what perfect checkpoints would give;
- **checkpoint bias**: measured checkpoint CPI vs native CPI of the same
  intervals — cold start / restore effects.

## Run 2: defaults maxK 100, warmup 100M (5 intervals), 1 point per cluster

| workload | insts | pts | full CPI | ckpt est | error | SimPoint | ckpt bias |
|---|---|---|---|---|---|---|---|
| gcc-200     | 104.3G | 52 | 1.1314 | 1.1313 | −0.01% | −0.71% | +0.71% |
| gcc-scilab  | 101.1G | 51 | 1.1598 | 1.1786 | +1.62% | +1.20% | +0.42% |
| gcc-train01 |  14.4G | 16 | 1.1554 | 1.2017 | +4.01% | +3.76% | +0.24% |
| lbm         | 227.9G | 31 | 1.0269 | 0.9928 | −3.32% | −1.08% | −2.27% |
| zstd        | 763.3G | 31 | 1.0592 | 1.0613 | +0.20% | −1.70% | +1.93% |
| abc-ucsb    | 118.5G | 32 | 0.5044 | 0.5218 | +3.46% | +3.56% | −0.09% |
| abc-des     |  84.3G | 39 | 0.7809 | 0.7963 | +1.97% | −0.01% | +1.98% |
| abc-sparc   |  66.6G | 58 | 1.6848 | 1.5590 | −7.47% | −9.11% | +1.81% |
| sqlite-main | 141.6G | 66 | 0.9399 | 0.9587 | +2.00% | +1.58% | +0.41% |
| sqlite-cte  |  45.5G | 54 | 0.7208 | 0.7297 | +1.23% | −0.07% | +1.30% |

Mean |error| 2.53% (run 1: 3.09%), max −7.47% (run 1: +9.53%).

## Run 1: maxK 30, warmup 20M

Errors: gcc-200 +0.79, gcc-scilab +6.03, gcc-train01 −2.80, zstd +1.13,
abc-ucsb +9.53, abc-des +5.33, abc-sparc −1.73, sqlite-main −0.21,
sqlite-cte +0.23, lbm −0.39 (%). Mean |error| 3.09%.

## Findings

- **Checkpoints reproduce native behaviour within ~2%.** Bias is −0.1..+2.0%
  everywhere except lbm (−2.3%, restored run *faster* than native; not yet
  explained — likely physical page / TLB layout of the ELFie image versus the
  native heap). 100M warmup removed the large cold-start bias seen with 20M
  (abc-des +5.7% → +2.0%, zstd +2.7% → +1.9%).
- **Remaining error is dominated by SimPoint point selection**, and it varies
  run to run: the same workload moves by several percent between captures
  (abc-sparc −4.2% → −9.1%, gcc-train01 −3.4% → +3.8%) because SimPoint picks
  one interval per cluster and CPI varies inside clusters. Offline simulation
  with true per-interval CPI (10 workloads × 3 seeds) gives mean/max |error|
  of 1.35%/7.4% for 1 point per cluster and 1.05%/4.5% for 5 closest points
  per cluster at maxK 100 (`usp-capture.py --per-cluster 5`).
- Next steps to tighten: several points per cluster (needs checkpoint page
  deduplication — abc-sparc / lbm checkpoints are ~0.7–1.5 GB each), and
  understanding the lbm bias.

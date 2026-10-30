# First end-to-end result: 721.gcc_r train01 on SpacemiT K3 (2026-10-28)

Workload: `721.gcc_r train01.c -O3 -finline-limit=50000 -o d.s`, static
`rv64gc_zba_zbb_zbs`, env `{PATH=/usr/bin:/bin, LC_ALL=C}`, 14.39 G instructions.

Pipeline: QEMU profile (20.4 s) → SimPoint (maxK 30, seed 1, 23 points) →
QEMU capture with warmup = 1 interval (13.3 s) → replay-mode ELFies →
`usp-run -w <warmup≈20M> -m 20M --cpu 3` on K3, 3 repetitions (median).

## Results

| Quantity | CPI | vs true |
|---|---|---|
| True CPI: full native run, all 719 intervals measured | **1.1528** | — |
| Full native runs under `perf stat` (3×) | 1.1517 / 1.1544 / 1.1552 | — |
| SimPoint estimate from **checkpoints** (replay ELFies) | **1.1092** | −3.8% |
| SimPoint estimate from the same windows **in a native run** | 1.0963 | −4.9% |
| SimPoint estimate from the true per-interval CPI of the chosen intervals | 1.0940 | −5.1% |

- **Checkpoint fidelity.** A restored window vs the same window inside a native run: a
  weighted +1.2% CPI bias (per point −2.6%…+4.4%). The direction is as expected for cold
  microarchitectural state after a 20M warmup. Per-point repeatability: ≤2.5%
  (checkpoints) vs ≤6% (native windows; gcc is not instruction-deterministic natively).
- **The −5% gap is SimPoint's representative choice, not the checkpoints.** The same
  choice evaluated with true native CPIs gives the same error. It varies with the seed:

| maxK | seed 1 | seed 7 | seed 42 |
|---|---|---|---|
| 30 | −5.10% | +2.13% | −1.63% |
| 50 | −0.94% | −1.64% | +0.68% |
| 100 | −0.94% | −1.64% | +0.68% |

  train01 has only 720 intervals; refrate runs have 50k–800k intervals, so this needs
  re-checking there. Mitigations: maxK 50, several seeds (the NEMU flow already produces
  10 clusterings), or selecting the clustering by BIC/variance.
- All 23 checkpoints replayed with no divergence; in live mode all finish gcc with
  byte-identical output.
- Replayed syscall cost: ~6.5k cycles each (seccomp trap + SIGSYS), ~120 user insts.
  The gcc windows contain 0–7 syscalls → <0.1% of window cycles.

- Launcher precision: with W = M = 20,000,000 (W a multiple of M) every run stays in
  exact overflow mode: warmup boundary 0…+34 insts late, window length within ±26 insts
  of 20M (138 runs). The first experiment used W = manifest warmup (e.g. 19,999,997),
  which forced the period-rearm fallback (+7.5k insts at the window end); the re-run
  gives the same weighted CPI (1.1082 vs 1.1092), so precision was not a factor.
  Rule: pass `-w` as a multiple of `-m`.

Raw data: `tmp/exp/gcc-train01/` (res2/ = exact-overflow re-run), (res/*.json, perinterval.txt, points.txt).

# Validation: all 47 SPEC CPU 2026 train workloads on the SpacemiT K3

## Setup

- **Build:** gcc-15 -O3, full RVA23 (`build-rv23`), static. Train inputs (`/mnt/work/usimpoint/spec26-train.json`).
- **Capture:** QEMU 11.0.2 linux-user on x86 with the usp plugin.
  - 20M-instruction intervals, SimPoint maxK 100.
  - BBVs clustered on `10*sqrt(count)` (`--bbv-transform sqrt`).
  - The 3 intervals closest to each centroid (`--per-cluster 3`).
  - 100M warmup (5 intervals). Replay-mode ELFies. About 5,700 checkpoints in total.
  - gmsh-sphere uses maxK 200.
- **Replay:** `usp-run` pinned to CPU 3 (X100 core, 2.2 GHz fixed), 3 repetitions, median. THP madvise (default), 4K pages.
  - Everything that touches the K3 (uploads, decoding, measuring) is serialized under one lock. Any concurrent transfer inflates CPI by 8–50%.
- **Ground truth:** 3 full native runs (`perf stat`, all threads), median.
  - Per-interval native CPI comes from one more native run sampled every 20M instructions.
- **Columns:**
  - error = weighted checkpoint CPI vs full-run CPI.
  - simpoint = weighted per-interval native CPI of the chosen intervals vs full-run CPI.
  - bias = error − simpoint. Spread = max−min of the 3 full runs.

Reproduce:

    USP_VAL=/mnt/work/usimpoint/suite-s3 USP_WORKLOADS=/mnt/work/usimpoint/spec26-train.json \
    USP_BUILD=build-rv23 USP_CAPTURE_OPTS="--bbv-transform sqrt --per-cluster 3" \
    tools/validate.py run && tools/validate.py report

## Results

| workload | insts | pts | full CPI | spread | ckpt est | error | simpoint | bias |
|---|---|---|---|---|---|---|---|---|
| stockfish-nnue | 342.4G | 216 | 0.9715 | 0.07% | 0.9758 | +0.45% | +0.22% | +0.23% |
| stockfish-classical | 67.9G | 72 | 0.7591 | 0.11% | 0.7638 | +0.61% | +0.57% | +0.05% |
| ntest | 441.7G | 120 | 0.4959 | 0.46% | 0.5140 | +3.67% | +0.71% | +2.93% |
| sqlite-main | 137.2G | 151 | 0.9566 | 3.62% | 0.9247 | −3.33% | −3.57% | +0.25% |
| sqlite-cte | 42.8G | 111 | 0.6282 | 0.50% | 0.6319 | +0.59% | −0.18% | +0.77% |
| cactus | 517.7G | 75 | 0.8723 | 0.13% | 0.8692 | −0.36% | −0.53% | +0.17% |
| omnetpp-general | 63.2G | 54 | 1.5813 | 0.44% | 1.5572 | −1.52% | +0.19% | −1.71% |
| omnetpp-onefifo | 74.7G | 176 | 1.0402 | 0.36% | 1.0601 | +1.92% | +2.90% | −0.96% |
| cpython-coreml | 127.3G | 39 | 0.7886 | 0.76% | 0.7887 | +0.01% | −0.65% | +0.66% |
| cpython-dna | 133.1G | 109 | 0.8176 | 0.06% | 0.8262 | +1.05% | +0.03% | +1.02% |
| gcc-200 | 102.5G | 188 | 1.1338 | 4.14% | 1.1112 | −2.00% | +2.76% | −4.63% |
| gcc-scilab | 98.9G | 183 | 1.1944 | 2.58% | 1.1497 | −3.75% | −3.89% | +0.15% |
| gcc-train01 | 14.0G | 58 | 1.1414 | 0.41% | 1.1160 | −2.22% | −2.58% | +0.37% |
| palm | 312.6G | 188 | 0.9534 | 0.26% | 0.9420 | −1.19% | −2.03% | +0.85% |
| llvm-train | 39.0G | 75 | 1.5288 | 0.22% | 1.5631 | +2.25% | +0.48% | +1.75% |
| llvm-elfobject | 116.2G | 149 | 1.4109 | 0.13% | 1.3766 | −2.43% | −1.16% | −1.29% |
| cppcheck-lcode | 177.4G | 222 | 1.1968 | 0.19% | 1.1624 | −2.88% | +0.09% | −2.96% |
| cppcheck-mesh | 270.4G | 69 | 0.7967 | 0.13% | 0.7894 | −0.92% | −0.27% | −0.65% |
| abc-ucsb152 | 116.9G | 48 | 0.4759 | 0.29% | 0.4682 | −1.60% | −3.34% | +1.79% |
| abc-desperf | 88.4G | 88 | 0.7939 | 0.38% | 0.7989 | +0.63% | +0.10% | +0.52% |
| abc-sparct1 | 58.8G | 170 | 2.0377 | 0.24% | 2.0389 | +0.06% | +0.48% | −0.41% |
| astcenc | 267.8G | 130 | 0.8851 | 0.07% | 0.8843 | −0.10% | −0.07% | −0.03% |
| vpr-place | 125.9G | 156 | 0.8768 | 0.70% | 0.8920 | +1.74% | −2.07% | +3.89% |
| vpr-route | 158.5G | 221 | 0.8724 | 0.32% | 0.9065 | +3.91% | +1.16% | +2.72% |
| gem5 | 194.4G | 40 | 1.5242 | 1.36% | 1.5334 | +0.60% | −0.07% | +0.68% |
| ocio-metadata | 18.7G | 14 | 0.5184 | 0.30% | 0.5139 | −0.85% | −0.74% | −0.11% |
| ocio-aces | 159.3G | 57 | 0.5941 | 0.03% | 0.5943 | +0.03% | −0.01% | +0.04% |
| ocio-lut1d | 67.5G | 31 | 0.6436 | 0.22% | 0.6436 | +0.01% | −0.74% | +0.75% |
| ocio-heavy | 235.0G | 143 | 0.7556 | 0.02% | 0.7565 | +0.12% | −0.01% | +0.14% |
| gmsh-sphere | 28.9G | 60 | 1.2555 | 0.74% | 1.2074 | −3.83% | −1.85% | −2.01% |
| gmsh-spec | 65.1G | 147 | 2.1217 | 0.15% | 2.1126 | −0.43% | −0.83% | +0.40% |
| flightdm-balloon | 41.8G | 127 | 0.9229 | 0.64% | 0.9229 | −0.01% | −0.14% | +0.14% |
| flightdm-f16 | 24.0G | 80 | 1.1140 | 0.18% | 1.1151 | +0.09% | −0.45% | +0.54% |
| flightdm-c3105 | 64.8G | 107 | 1.0992 | 0.12% | 1.0992 | +0.01% | +0.32% | −0.31% |
| flightdm-s23 | 55.7G | 38 | 1.1952 | 0.03% | 1.2006 | +0.46% | +0.06% | +0.39% |
| fotonik3d | 104.0G | 136 | 4.0354 | 0.05% | 3.9897 | −1.13% | −0.34% | −0.80% |
| sealcrypto | 473.9G | 198 | 0.5896 | 0.19% | 0.5908 | +0.21% | +0.12% | +0.10% |
| ns3-tcp | 127.8G | 130 | 1.4519 | 0.12% | 1.4570 | +0.35% | −0.05% | +0.40% |
| ns3-udp | 62.7G | 86 | 1.4869 | 0.37% | 1.5021 | +1.02% | −0.15% | +1.17% |
| roms | 462.1G | 228 | 1.9062 | 0.16% | 1.9005 | −0.30% | −0.20% | −0.11% |
| femflow | 508.1G | 174 | 0.8080 | 0.09% | 0.8069 | −0.14% | −0.04% | −0.11% |
| nest-balanced | 54.4G | 50 | 0.5091 | 0.20% | 0.5095 | +0.08% | +0.09% | −0.01% |
| nest-cubaps | 101.9G | 117 | 1.5748 | 8.72% | 1.5887 | +0.88% | +6.96% | −5.69% |
| nest-cuba | 144.6G | 174 | 1.2372 | 7.02% | 1.3769 | +11.28% | +1.20% | +9.96% |
| marian | 704.1G | 132 | 1.4411 | 0.17% | 1.4342 | −0.48% | +1.55% | −2.00% |
| zstd | 551.1G | 138 | 1.3112 | 0.25% | 1.3080 | −0.24% | −0.34% | +0.10% |
| lbm | 235.0G | 77 | 0.9120 | 1.67% | 0.9184 | +0.69% | −1.62% | +2.35% |
<!-- error     mean |.| 1.33%, max +11.28% -->
<!-- simpoint  mean |.| 1.02%, max +6.96% -->
<!-- bias      mean |.| 1.26%, max +9.96% -->

**Mean |error| 1.33%. 27 workloads within 1%, 10 within 1–2%, 9 above 2%.**
The previous selection (1 point per cluster, raw BBVs, ~1,800 checkpoints) gave
1.85% mean on the same workloads, with marian −12.8% and abc-sparct1 +6.8%.

## Findings

- **The remaining errors above 2% are mostly native run-to-run variation on the K3, not checkpoint defects.**
  - Per-interval CPI of the same 20M interval (~5 ms) varies by several percent between processes. Native and restored runs vary alike: ntest interval 7791 measured 0.498–0.527 natively and 0.519–0.572 restored.
  - Branch, L1 and TLB event counts are identical between fast and slow runs, which points at physical page placement (L2/DRAM).
  - Some programs vary as whole runs too. Full native runs span gcc-scilab 2.6%, sqlite-main 3.6%, gcc-200 4.1%, nest-cubaps 8.7% and nest-cuba 7.0%. nest-cuba alone spans 1.24–1.76 CPI between runs.
  - For gcc-scilab and sqlite-main, the "simpoint" column mostly reflects the per-interval native run differing from the full runs by −2.8% and −2.2%. Against that same run the checkpoints agree within −0.3% and −0.7%.
  - gcc-200 and nest-cubaps are noisier. Their per-interval runs differ from the full runs by +2.8% and +6.5%, and their checkpoints by about −6% from those.
- **The median bias over the suite is about +0.2%,** so there is no systematic restore penalty.
- **Changes that did not help:**
  - **THP=always:** native and checkpoint each become stable, but checkpoint code is anonymous memory and gets huge pages, while native code is file-backed and does not. Code-heavy workloads then read 3–10% fast.
  - **Memory compaction before each run:** shifts both native and checkpoint runs, but neither becomes deterministic.
  - **Longer warmup:** ntest's bias is unchanged 320M instructions after the restore point.
  - **Not backing zero pages:** changes ntest by only ~0.5%. Backing them is still needed: fotonik3d reads −29% without it.
- **Selection:** sqrt-weighted BBVs keep hot loops from dominating the clustering, and several points per cluster average out within-cluster variation.
  - Offline, against native per-interval CPI: mean SimPoint error 1.04% → 0.62%, and the worst workload 11.8% → 3.9%.
  - Random members are unbiased but noisier than the centroid-closest ones.
  - maxK 200 helps a little more (0.47%) for about 45% more checkpoints. It is used only for gmsh-sphere.
- **Profiles from older plugin versions may not replay.** `USP_REUSE_FROM` then profiles again. 7 workloads needed this.

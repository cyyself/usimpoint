# usimpoint — userspace SimPoint checkpoints for RISC-V Linux

usimpoint makes SimPoint checkpoints of a single Linux user process (e.g. a SPEC
CPU benchmark). Each checkpoint is an **ELFie**: a static ELF that, when run,
restores the process image and continues the program from the chosen interval.
It runs as an ordinary process on the target's Linux. You don't need a
full-system simulator, a hypervisor or root.

- **Capture** runs on an x86 host in QEMU linux-user with a TCG plugin, so it
  is deterministic and can run many jobs in parallel.
- **Replay** runs natively on the RISC-V target (e.g. XiangShan on FPGA, or a
  SpacemiT K3) under `usp-run`. `usp-run` counts warmup and measured user
  instructions with the PMU.

Accuracy on all 47 SPEC CPU 2026 train workloads is in
[docs/results-spec26-train.md](docs/results-spec26-train.md): mean |CPI error|
1.33% against full native runs on the K3. The checkpoint format is described in
[docs/ckpt-format.md](docs/ckpt-format.md).

## Layout

| Path | What |
|---|---|
| `patches/qemu/` | patch for QEMU 11.0.2 (`third_party/qemu` submodule): plugin API additions, vdso |
| `tools/plugin/usp.c` | QEMU plugin: BBV profiling, syscall log, checkpoint capture |
| `tools/usp-capture.py` | profile → SimPoint → capture, for one command |
| `tools/usp-mkelf.py` | checkpoint directory → self-restoring ELFie |
| `restorer/` | freestanding restorer stub embedded in every ELFie |
| `launcher/usp-run.c` | target-side runner: warmup W / measure M user instructions, JSON result |
| `tools/validate.py` | end-to-end SPEC validation (capture on host, measure on a target over ssh) |
| `tools/usp-swap-restorer.py` | replace the restorer inside existing ELFies |

## Requirements

- **x86-64 Linux host:**
  - gcc and glib-2.0 development headers to build QEMU and the plugin.
  - `riscv64-linux-gnu-gcc` for the restorer and `usp-run`.
  - Python 3.
  - SimPoint 3.2. The `simpoint` binary is expected at `tmp/simpoint/bin/simpoint`; override with `USP_SIMPOINT`. A copy ships with NEMU (`resource/simpoint`).
- **RISC-V Linux target:**
  - A PMU with user-mode `instructions`/`cycles` and overflow interrupts (Sscofpmf).
  - `perf_event_paranoid` low enough for your user (≤ 2).
  - The benchmark must be a **static** binary.
- **The capture CPU model must match the target.** The default is RVA23U64 with VLEN 256, like the K3. For other hardware, pass `--cpu` with a QEMU CPU string describing the target, so glibc picks the same ifuncs.

## Build

```sh
git submodule update --init third_party/qemu

# QEMU linux-user with plugins
(cd third_party/qemu && git apply ../../patches/qemu/0001-usimpoint-qemu.patch)
mkdir -p tmp/qemu-build && cd tmp/qemu-build
../../third_party/qemu/configure --target-list=riscv64-linux-user --enable-plugins \
    --disable-system --disable-tools --disable-docs --disable-werror
make -j"$(nproc)" && cd ../..

make -C tools/plugin                               # tools/plugin/libusp.so
make -C restorer                                   # restorer/build/restorer.bin
make -C launcher CC=riscv64-linux-gnu-gcc          # launcher/usp-run (static riscv64)
```

Copy `launcher/usp-run` to the target. Or build it there natively with
`make -C launcher`.

## Make checkpoints for one program

Run `usp-capture.py` from the program's run directory, which holds its inputs:

```sh
cd /path/to/run_dir          # contains the static riscv64 binary and its inputs
/path/to/usimpoint/tools/usp-capture.py -o out \
    --bbv-transform sqrt --per-cluster 3 -- ./bench arg1 arg2
```

This runs the program twice in QEMU:

1. **Profile:** basic-block vectors every 20M instructions, plus a log of all
   syscall results. Written to `out/prof/`.
2. **Capture:** replays the logged syscall results, so execution is identical,
   and dumps a checkpoint 5 intervals (100M instructions) before each chosen
   interval, so the extra intervals serve as warmup. Written to
   `out/ckpt/ckpt_<interval>/`, together with a trace of the syscalls in the
   window.

The run directory is restored between the two passes. Useful options:

| Option | Default | Meaning |
|---|---|---|
| `--interval N` | 20000000 | SimPoint interval (instructions) |
| `--warmup N` | 5 | checkpoint this many intervals before each simulation point |
| `--max-k K` | 100 | SimPoint maxK |
| `--bbv-transform sqrt` | none | cluster on sqrt-compressed BBVs (recommended, see results) |
| `--per-cluster N` | 1 | checkpoints per cluster (the N closest to the centroid; weight split) |
| `--pick random` | closest | random cluster members instead |
| `--cpu MODEL` | K3-like RVA23 | QEMU CPU model, must match the target |
| `--stdin FILE` | | feed FILE to the program's stdin |
| `--reuse-profile` | | skip pass 1 if `out/prof` exists (e.g. to try other selections) |

Multi-threaded programs are supported. Threads are serialized during capture,
and points whose window contains a thread switch are not selected.

Then build an ELFie for each checkpoint. The weight of each point is in its
`manifest.json`:

```sh
for c in out/ckpt/ckpt_*; do
  k=${c##*_}
  tools/usp-mkelf.py --mode replay "$c" -o elf/ck_$k.elf
  python3 -c "import json;m=json.load(open('$c/manifest.json'));print(m['interval'],m['weight'])" >> elf/points.txt
done
```

Two replay modes:

- **`--mode replay`** (default): the ELFie answers the program's syscalls from
  the captured trace, so it needs no input files and gives identical results.
  This is the mode used for measurement.
- **`--mode live`**: issues real syscalls, recreating fds and files from the
  manifest. Useful for running beyond the window.

## Run on the target

Copy `elf/` to the target and run each ELFie under `usp-run`. Its first
`--warmup` intervals (100M instructions by default) are warmup, and the next
interval is the measurement:

```sh
ulimit -s unlimited
while read k w; do
  usp-run -q --cpu 3 -w 100000000 -m 20000000 -o res/ck_$k.json -- ./elf/ck_$k.elf
done < elf/points.txt
```

Each JSON has `insts`, `cycles` and `cpi`. With `-e`, it also has extra PMU
events, e.g. `-e branch-misses,L1-dcache-load-misses`. The program's estimated
CPI is `Σ weight × cpi` over all points. ELFies need no files besides themselves
and can run from any directory.

## Validate against full native runs

`tools/validate.py` automates the whole flow for SPEC CPU 2026:

1. Capture on the host, `USP_JOBS` jobs in parallel.
2. Stream ELFies to the target as zstd `--patch-from` chains, about 37× smaller.
3. Run them and the full native program on the target.
4. Report the error.

It expects the SPEC tree at `tmp/CPU2026LiteWrapper` and the target reachable as
`ssh $USP_TARGET` (default `10.12.10.8`), with work under `~/usimpoint/` there.

```sh
export USP_VAL=/big/disk/suite                  # results and ELFies per workload
export USP_WORKLOADS=spec26-train.json          # [{name, bench, args, stdin, inputs}, ...]
export USP_BUILD=build-rv23                     # binary dir inside each benchmark
export USP_CAPTURE_OPTS="--bbv-transform sqrt --per-cluster 3"
tools/validate.py run                           # or: run gcc-200 lbm
tools/validate.py report
```

Other knobs:

| Variable | Effect |
|---|---|
| `USP_REUSE_FROM=<old USP_VAL>` | reuse profiles and native results; only re-select, capture and measure |
| `USP_KEEP_ELF=1` | keep ELFies after measuring |
| `USP_THP=always` | THP mode on the target during measurement (restored afterwards) |

Subcommands `capture`, `native` and `ckpt` run the individual steps.

**Measurement hygiene matters on a small board.** All target-side work,
measurements and uploads alike, takes one lock (`/tmp/usp-measure.lock`). Any
concurrent transfer inflated CPI by 8–50% on the K3, so run one `validate.py`
at a time.

## Limitations

- The program must be a static Linux user binary. Threads are serialized during capture.
- Programs that fork, exec or use POSIX timers are rejected at profile time.
- Programs that use sockets, pipes or `fchdir` can only be checkpointed in replay mode.
- Replay mode covers the warmup + measurement window plus 1 interval of slack.
  Running further needs `--mode live`.
- Expect a few percent of per-interval noise on real hardware, from physical
  page placement. See the results document.

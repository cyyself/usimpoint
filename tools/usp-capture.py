#!/usr/bin/env python3
"""Profile a command in QEMU, cluster with SimPoint, and capture checkpoints.

usage: usp-capture.py -o OUTDIR [--interval N] [--cpu MODEL] [--max-k K] -- prog args...

Runs in the current directory (the benchmark run dir). Produces:
  OUTDIR/prof/{bbv.bb,syscalls.log,profile.json,simpoints,weights}
  OUTDIR/ckpt/ckpt_<interval>/{manifest.json,mem.bin,files/}
"""
import argparse
import bisect
import json
import math
import os
import random
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QEMU = os.environ.get("USP_QEMU", os.path.join(ROOT, "tmp/qemu-build/qemu-riscv64"))
PLUGIN = os.environ.get("USP_PLUGIN", os.path.join(ROOT, "tools/plugin/libusp.so"))
SIMPOINT = os.environ.get("USP_SIMPOINT", os.path.join(ROOT, "tmp/simpoint/bin/simpoint"))

# Guest VA limit: keep every address below 256 GiB so images fit Sv39.
RESERVED_VA = "0x4000000000"
GUEST_STACK = "1024M"
# Capture CPU model: RVA23U64 with the SpacemiT K3's VLEN and extension set, so
# hwprobe/AT_HWCAP (glibc ifuncs, vlenb) look exactly like the K3: the profile
# adds K3's zbc/zfh/zvfh/zvbc/zvkg/zvkned/zvknh[ab]/zvksed/zvksh and drops supm
# (absent on the K3). Old non-vector builds: "xiangshan-kunminghu,v=false".
DEFAULT_CPU = ("rva23u64,vlen=256,elen=64,zbc=true,zfh=true,zvfh=true,zvbc=true,"
               "zvkg=true,zvkned=true,zvknha=true,zvknhb=true,zvksed=true,zvksh=true,"
               "supm=false")
# Fixed, minimal environment: profile and capture must see identical stacks.
GUEST_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def qemu(cpu, plugin_args, cmd, log, stdin=None):
    opts = ",".join(f"{k}={v}" for k, v in plugin_args.items())
    # 1 GiB guest stack (QEMU ignores an unlimited RLIMIT_STACK; roms needs >8M)
    argv = [QEMU, "-R", RESERVED_VA, "-s", GUEST_STACK, "-cpu", cpu,
            "-plugin", f"{PLUGIN},{opts}"] + cmd
    t = time.time()
    with open(log, "w") as f:
        rc = subprocess.call(argv, env=GUEST_ENV, stdout=f, stderr=subprocess.STDOUT,
                             stdin=open(stdin) if stdin else subprocess.DEVNULL)
    return rc, time.time() - t


def load_switches(prof):
    """Global icounts of thread switches (multi-threaded guests), sorted."""
    p = os.path.join(prof, "switches.txt")
    if not os.path.exists(p):
        return []
    return sorted(int(l.split()[0]) for l in open(p) if l.strip())


def switch_free(switches, interval, warmup, margin):
    """Predicate: does the trace window of simpoint interval i, i.e. from the
    checkpoint at interval max(i - warmup, 0) to the end of interval i (+/-
    margin), contain no thread switch?  The restored image is the one thread
    running at the checkpoint, so its window must not hand over to another."""
    def ok(i):
        lo = max(i - warmup, 0) * interval - margin
        hi = (i + 1) * interval + margin
        k = bisect.bisect_left(switches, lo)
        return k == len(switches) or switches[k] >= hi
    return ok


def sqrt_bbv(src, dst):
    """Rewrite a BBV file with every count n replaced by 10*sqrt(n) (SimPoint
    reads integers; the factor keeps resolution without lengthening lines)."""
    with open(src) as f, open(dst, "w") as o:
        for line in f:
            if not line.startswith("T"):
                o.write(line)
                continue
            o.write("T" + " ".join(f":{b}:{max(1, round(10 * math.sqrt(int(n))))}"
                                   for _, b, n in (x.split(":") for x in line[1:].split())) + "\n")


def select_per_cluster(prof, n, ok=lambda i: True, pick_random=None):
    """Pick the n intervals closest to each cluster centroid (or, with
    pick_random set to a seed, n random members) for which ok(i) holds; split
    the weight.  Clusters without such an interval are dropped (their weight
    is missing from the estimate).  Random members are an unbiased sample of
    the cluster; the centroid-closest ones are not when CPI varies within it."""
    clusters = {}
    for i, line in enumerate(open(os.path.join(prof, "labels"))):
        c, dist = line.split()
        clusters.setdefault(int(c), []).append((float(dist), i))
    total = sum(len(v) for v in clusters.values())
    rng = random.Random(pick_random)
    with open(os.path.join(prof, "simpoints.multi"), "w") as sp, \
            open(os.path.join(prof, "weights.multi"), "w") as wt:
        pid = 0
        for c in sorted(clusters):
            pick = [x for x in sorted(clusters[c]) if ok(x[1])]
            pick = rng.sample(pick, min(n, len(pick))) if pick_random is not None else pick[:n]
            if not pick:
                print(f"warning: cluster {c} ({len(clusters[c])} intervals, weight "
                      f"{len(clusters[c]) / total:.4f}): every interval's window has a "
                      "thread switch; dropped")
                continue
            if pick_random is None and pick[0] != sorted(clusters[c])[0]:
                print(f"cluster {c}: interval {pick[0][1]} instead of {sorted(clusters[c])[0][1]} "
                      f"(thread switch in window), distance {pick[0][0]:.4g} vs "
                      f"{sorted(clusters[c])[0][0]:.4g}")
            for _, i in pick:
                sp.write(f"{i} {pid}\n")
                wt.write(f"{len(clusters[c]) / total / len(pick):.9g} {pid}\n")
                pid += 1
    return "simpoints.multi", "weights.multi"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--interval", type=int, default=20_000_000)
    ap.add_argument("--cpu", default=DEFAULT_CPU,
                    help="QEMU -cpu string (default: K3-like RVA23, VLEN=256)")
    ap.add_argument("--max-k", type=int, default=100)
    ap.add_argument("--per-cluster", type=int, default=1,
                    help="checkpoints per cluster (default: the N intervals closest to the centroid)")
    ap.add_argument("--pick", choices=["closest", "random"], default="closest",
                    help="per-cluster selection: closest to the centroid, or random members "
                         "(unbiased; use with --per-cluster 3..5)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--bbv-transform", choices=["none", "sqrt"], default="none",
                    help="cluster on sqrt(block counts): hot loops then dominate the BBV less, "
                         "so phases that differ in colder code separate (SimPoint error on the "
                         "SPEC26 train set: worst 11.8%% -> 5.7%% at one point per cluster)")
    ap.add_argument("--warmup", type=int, default=5,
                    help="checkpoint this many intervals before each simpoint")
    ap.add_argument("--reuse-profile", action="store_true",
                    help="keep an existing OUT/prof (profile pass already done)")
    ap.add_argument("--max-interval", type=int,
                    help="capture only points below this interval (testing)")
    ap.add_argument("--stdin", help="file fed to the guest's stdin (both runs)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        ap.error("missing command")

    out = os.path.abspath(a.out)
    prof, ckpt = os.path.join(out, "prof"), os.path.join(out, "ckpt")
    os.makedirs(prof, exist_ok=True)
    cpu_tag = a.cpu.replace(",", ":")

    # The guest may write into its cwd; the capture run must start from the same
    # files the profile run saw (outputs left behind change program paths).
    snap = os.path.join(out, "cwd.orig")
    cwd = os.getcwd()
    if not (a.reuse_profile and os.path.isdir(snap)):
        shutil.rmtree(snap, ignore_errors=True)
        subprocess.check_call(["rsync", "-a", "--exclude", os.path.relpath(out, cwd) + "/",
                               cwd + "/", snap + "/"])

    if a.reuse_profile and os.path.exists(os.path.join(prof, "profile.json")):
        rc, dt = 0, 0.0     # same command, cpu and interval assumed
    else:
        rc, dt = qemu(a.cpu, {"mode": "profile", "out": prof, "interval": a.interval},
                      cmd, os.path.join(prof, "guest.log"), a.stdin)
    info = json.load(open(os.path.join(prof, "profile.json")))
    print(f"profile: rc={rc} {info['icount']} insts, {info['intervals']} intervals, {dt:.1f}s")
    if info["unsupported"]:
        sys.exit("guest did something unsupported; see guest.log")

    fv = "bbv.bb"
    if a.bbv_transform == "sqrt":
        fv = "bbv.sqrt.bb"
        sqrt_bbv(os.path.join(prof, "bbv.bb"), os.path.join(prof, fv))
    subprocess.check_call(
        [SIMPOINT, "-loadFVFile", fv, "-saveSimpoints", "simpoints",
         "-saveSimpointWeights", "weights", "-saveLabels", "labels", "-maxK", str(a.max_k),
         "-numInitSeeds", "40", "-iters", "100000",
         "-seedkm", str(a.seed), "-seedproj", str(a.seed + 1)],
        cwd=prof, stdout=open(os.path.join(prof, "simpoint.log"), "w"))
    points, weights = "simpoints", "weights"
    switches = load_switches(prof)
    if info.get("threads", 1) > 1:
        print(f"threads: {info['threads']} created, {len(switches)} thread switches "
              f"(one per {info['icount'] / max(len(switches), 1) / 1e6:.1f}M insts)")
        if info.get("serialization_broken"):
            print("warning: thread serialization was broken (see guest.log); "
                  "capture may not reproduce the profile")
    seed = a.seed if a.pick == "random" else None
    if switches:
        ok = switch_free(switches, a.interval, a.warmup, a.interval // 100)
        points, weights = select_per_cluster(prof, a.per_cluster, ok, seed)
    elif a.per_cluster > 1 or seed is not None:
        points, weights = select_per_cluster(prof, a.per_cluster, pick_random=seed)
    if a.max_interval is not None:
        # test shortcut: only points before an interval (capture stops early);
        # the dropped points' weight is missing from the estimate
        keep = {l.split()[1]: l for l in open(os.path.join(prof, points))
                if int(l.split()[0]) < a.max_interval}
        wl = [l for l in open(os.path.join(prof, weights)) if l.split()[1] in keep]
        with open(os.path.join(prof, "simpoints.cut"), "w") as f:
            f.writelines(keep.values())
        with open(os.path.join(prof, "weights.cut"), "w") as f:
            f.writelines(wl)
        print(f"--max-interval {a.max_interval}: {len(keep)} points, weight "
              f"{sum(float(l.split()[0]) for l in wl):.4f}")
        points, weights = "simpoints.cut", "weights.cut"
    npts = sum(1 for _ in open(os.path.join(prof, points)))
    print(f"simpoint: {npts} points")

    subprocess.check_call(["rsync", "-a", "--delete", "--exclude", os.path.relpath(out, cwd) + "/",
                           snap + "/", cwd + "/"])
    rc, dt = qemu(a.cpu, {"mode": "capture", "out": ckpt, "interval": a.interval,
                          "points": os.path.join(prof, points),
                          "weights": os.path.join(prof, weights),
                          "syslog": os.path.join(prof, "syscalls.log"),
                          "cpu": cpu_tag, "stop": 1, "warmup": a.warmup,
                          # trace must cover warmup + one measured interval, plus slack
                          "window": (a.warmup + 2) * a.interval},
                  cmd, os.path.join(out, "capture.log"), a.stdin)
    # A thread switch inside a checkpoint's warmup + measured window (the
    # plugin truncates the trace there and leaves its offset in "switch")
    # makes it unusable; selection avoids that, this catches the rest.
    bad = 0
    for d in sorted(os.listdir(ckpt)) if os.path.isdir(ckpt) else []:
        sw = os.path.join(ckpt, d, "switch")
        if d.startswith("ckpt_") and os.path.exists(sw):
            m = json.load(open(os.path.join(ckpt, d, "manifest.json")))
            need = m.get("warmup", 0) + a.interval
            if int(open(sw).read()) < need:
                print(f"{d}: thread switch {int(open(sw).read())} insts after the checkpoint, "
                      f"window needs {need}: unusable, moved to bad_{d}")
                os.rename(os.path.join(ckpt, d), os.path.join(ckpt, "bad_" + d))
                bad += 1
    got = len([d for d in os.listdir(ckpt) if d.startswith("ckpt_")]) if os.path.isdir(ckpt) else 0
    print(f"capture: rc={rc} {got}/{npts} checkpoints, {dt:.1f}s")
    log = open(os.path.join(out, "capture.log")).read()
    if "diverged" not in log:
        shutil.rmtree(snap, ignore_errors=True)
    if "diverged" in log or got + bad != npts:
        sys.exit("capture incomplete or replay diverged; see capture.log")


if __name__ == "__main__":
    main()

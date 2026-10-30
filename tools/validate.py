#!/usr/bin/env python3
"""End-to-end validation: SimPoint checkpoint estimate vs full native run.

  validate.py capture [NAME...]  # host: QEMU profile+capture, build ELFies
  validate.py measure [NAME...]  # copy to the replay machine, run full runs + checkpoints
  validate.py report    # compare weighted checkpoint CPI with full-run CPI
  validate.py run [NAME...]      # pipelined: capture on the host while the replay
                                 # machine measures, deleting each workload's ELFies
                                 # once measured (bounded disk use)

USP_WORKLOADS=<json> replaces the built-in list (entries: name, bench, args,
stdin, inputs); USP_BUILD selects the build dir (default build-rv); USP_CAPTURE_OPTS adds
usp-capture options (e.g. "--bbv-transform sqrt --per-cluster 3"); USP_REUSE_FROM
reuses an earlier USP_VAL's profiles and native results; USP_CPU is
passed to usp-capture.py --cpu.

Workloads are SPEC train invocations from tmp/CPU2026LiteWrapper (static RISC-V
builds in build-rv/). Everything lives under tmp/val/<workload>/.
"""
import concurrent.futures as cf
import glob
import json
import os
import queue
import re
import shlex
import shutil
import statistics as st
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, "tmp/CPU2026LiteWrapper")
VAL = os.path.abspath(os.environ.get("USP_VAL", os.path.join(ROOT, "tmp/val")))
WARMUP = int(os.environ.get("USP_WARMUP", "5"))   # warmup length in intervals
HOST = os.environ.get("USP_TARGET", "10.12.10.8")
RHOME = "usimpoint/" + os.path.basename(VAL)   # relative to $HOME on the replay machine
REPS = 3
FULL = int(os.environ.get("USP_FULL", "1"))       # 0: skip the full native runs
INTERVAL = 20_000_000
BUILD = os.environ.get("USP_BUILD", "build-rv")
JOBS = int(os.environ.get("USP_JOBS", "4"))
KEEP_ELF = os.environ.get("USP_KEEP_ELF", "0") == "1"   # keep local ELFies after measuring
# USP_THP=always|never: replay machine's THP mode while measuring (default: as is)
THP_ENV = f"USP_THP={shlex.quote(os.environ['USP_THP'])} " if os.environ.get("USP_THP") else ""
# USP_REUSE_FROM=<earlier USP_VAL>: take each workload's profile and native results
# from there (only re-select and re-capture; e.g. with other USP_CAPTURE_OPTS)
REUSE = os.environ.get("USP_REUSE_FROM")
MIN_FREE = float(os.environ.get("USP_MIN_FREE_GB", "40")) * 1e9

# name, benchmark, args (train inputs)
WORKLOADS = [
    ("gcc-200",     "721.gcc_r",    "200.c -O2 -o 200.c.opts-O2.s"),
    ("gcc-scilab",  "721.gcc_r",    "scilab.c -O3 -o scilab.c.opts-O3.s"),
    ("gcc-train01", "721.gcc_r",    "train01.c -O3 -finline-limit=50000 -o train01.s"),
    ("lbm",         "782.lbm_r",    "120 reference.dat 0 0 200_200_130_ldc.of"),
    ("zstd",        "777.zstd_r",   "-b3 -e12 --verbose -i15"),
    ("abc-ucsb",    "729.abc_r",    "-F ucsb_152.in"),
    ("abc-des",     "729.abc_r",    "-F des_perf.in"),
    ("abc-sparc",   "729.abc_r",    "-F sparcT1_core.in"),
    ("sqlite-main", "708.sqlite_r", "--memdb --size 500 --testset main --verify"),
    ("sqlite-cte",  "708.sqlite_r", "--memdb --size 500 --testset cte --verify"),
]
WL = {n: {"name": n, "bench": b, "args": a, "stdin": None,
          "inputs": ["data/all/input", "data/train/input"]} for n, b, a in WORKLOADS}
if os.environ.get("USP_WORKLOADS"):
    WL = {w["name"]: w for w in json.load(open(os.environ["USP_WORKLOADS"])) if w.get("ok", True)}
    WORKLOADS = [(w["name"], w["bench"], w["args"]) for w in WL.values()]


def prep_rundir(bench, run, inputs=("data/all/input", "data/train/input")):
    os.makedirs(run, exist_ok=True)
    for sub in inputs:
        src = os.path.join(SPEC, bench, sub)
        if os.path.isdir(src):
            shutil.copytree(src, run, dirs_exist_ok=True, symlinks=True)
    shutil.copy2(os.path.join(SPEC, bench, BUILD, bench), run)


def capture_one(wl, reuse=None):
    name, bench, args = wl
    if reuse is None:
        reuse = REUSE
    w = WL[name]
    d = os.path.join(VAL, name)
    run, out, elf = (os.path.join(d, x) for x in ("run", "out", "elf"))
    shutil.rmtree(d, ignore_errors=True)
    prep_rundir(bench, run, w["inputs"])
    with open(os.path.join(d, "cmd.txt"), "w") as f:
        f.write(f"./{bench} {args}" + (f" < {shlex.quote(w['stdin'])}" if w.get("stdin") else "") + "\n")
    opt = ["--warmup", str(WARMUP)]
    if reuse:
        src = os.path.join(reuse, name)
        os.makedirs(os.path.join(out, "prof"))
        for f in os.listdir(os.path.join(src, "out/prof")):
            # read-only inputs; SimPoint's outputs are rewritten
            if f in ("bbv.bb", "profile.json", "syscalls.log", "switches.txt"):
                os.link(os.path.join(src, "out/prof", f), os.path.join(out, "prof", f))
        shutil.copytree(os.path.join(src, "res"), os.path.join(d, "res"),
                        ignore=shutil.ignore_patterns("ck_*"))
        if os.path.exists(os.path.join(src, "perint.txt")):
            shutil.copy2(os.path.join(src, "perint.txt"), d)
        opt.append("--reuse-profile")
    if os.environ.get("USP_CPU"):
        opt += ["--cpu", os.environ["USP_CPU"]]
    opt += shlex.split(os.environ.get("USP_CAPTURE_OPTS", ""))
    if w.get("stdin"):
        opt += ["--stdin", w["stdin"]]
    with open(os.path.join(d, "capture.txt"), "w") as log:
        rc = subprocess.call([os.path.join(ROOT, "tools/usp-capture.py"), "-o", out] + opt
                             + ["--", "./" + bench] + shlex.split(args),
                             cwd=run, stdout=log, stderr=subprocess.STDOUT)
    if rc and reuse and "diverged" in open(os.path.join(out, "capture.log")).read():
        # profiles from older plugins (e.g. before thread serialization) may
        # not replay: profile again (native results are kept)
        res = os.path.join(d, "res")
        keep = os.path.join(VAL, f".{name}.res")
        shutil.rmtree(keep, ignore_errors=True)
        shutil.move(res, keep)
        msg = capture_one(wl, reuse="")
        shutil.rmtree(os.path.join(d, "res"), ignore_errors=True)
        shutil.move(keep, res)
        if os.path.exists(os.path.join(res, "perint.txt")):
            shutil.copy2(os.path.join(res, "perint.txt"), d)
        return msg + " (profiled again)"
    if rc:
        shutil.rmtree(run)      # still measured natively: give it a clean run dir
        prep_rundir(bench, run, w["inputs"])
        return f"{name}: capture failed, see {d}/capture.txt"
    os.makedirs(elf)
    pts = []
    for c in glob.glob(os.path.join(out, "ckpt", "ckpt_*")):
        m = json.load(open(os.path.join(c, "manifest.json")))
        k = m["interval"]
        subprocess.check_call([sys.executable, os.path.join(ROOT, "tools/usp-mkelf.py"),
                               "--mode", "replay", c, "-o", os.path.join(elf, f"ck_{k}.elf")],
                              stdout=subprocess.DEVNULL)
        pts.append((k, m["weight"]))
        # the ELFie holds the whole image; keep only the manifest
        for f in ("mem.bin", "syscalls.bin"):
            os.remove(os.path.join(c, f))
        shutil.rmtree(os.path.join(c, "files"), ignore_errors=True)
    with open(os.path.join(elf, "points.txt"), "w") as f:
        for k, wt in sorted(pts):
            f.write(f"{k} {wt}\n")
    # the capture run wrote outputs into run/; give the replay machine a clean copy
    shutil.rmtree(run)
    prep_rundir(bench, run, w["inputs"])
    with open(os.path.join(d, "cmd.txt"), "w") as f:
        f.write(f"./{bench} {args}" + (f" < {shlex.quote(w['stdin'])}" if w.get("stdin") else "") + "\n")
    prof = json.load(open(os.path.join(out, "prof", "profile.json")))
    return f"{name}: {prof['icount'] / 1e9:.1f}G insts, {len(pts)} checkpoints"


MEASURE_SH = r"""#!/bin/sh
# Runs on the replay machine inside $HOME/usimpoint/<val>/<workload>
#   measure.sh native REPS FULL   full native runs (+ per-interval CPI profile)
#   measure.sh ckpt REPS M W      every checkpoint ELFie
set -u
ulimit -s unlimited
# one measurement at a time on the machine, even across concurrent validate.py runs
exec 9>/tmp/usp-measure.lock; flock 9
# USP_THP=always: transparent huge pages for this session only (4K-page runs
# of TLB-bound programs vary up to 30% with physical placement)
if [ -n "${USP_THP:-}" ]; then
  T=/sys/kernel/mm/transparent_hugepage/enabled
  THP0=$(sed 's/.*\[\(.*\)\].*/\1/' $T)
  trap 'echo $THP0 | sudo tee $T >/dev/null' EXIT
  echo $USP_THP | sudo tee $T >/dev/null
fi
CPU=3; H=$PWD; L=$H/../usp-run
mkdir -p res
if [ "$1" = native ]; then
  REPS=$2; FULL=$3
  for rep in $(seq 1 $REPS); do
    [ "$FULL" = 1 ] || break
    # perf stat follows every thread (usp-run counts only the first one)
    rm -rf r && cp -a run r && sync && (cd r && eval "env -i PATH=/usr/bin:/bin LC_ALL=C taskset -c $CPU \
        perf stat -x, -o $H/res/full_$rep.csv -e instructions:u,cycles:u -- $(cat ../cmd.txt)" >/dev/null 2>&1)
    awk -F, '/instructions/{i=$1} /cycles/{c=$1} END{printf "{\"insts\": %s, \"cycles\": %s, \"cpi\": %.6f, \"complete\": true}\n", i, c, c/i}' \
        res/full_$rep.csv > res/full_$rep.json
  done
  # true CPI of every 20M interval, to separate SimPoint error from checkpoint bias
  rm -rf r && cp -a run r && sync && (cd r && eval "env -i PATH=/usr/bin:/bin LC_ALL=C taskset -c $CPU \
      perf record -q -e '{instructions:u,cycles:u}:S' -c 20000000 -o $H/perint.data -- $(cat ../cmd.txt)" \
      >/dev/null 2>&1)
  perf script -i perint.data -F period,event > res/perint.txt 2>/dev/null; rm -rf r perint.data
else
  REPS=$2; M=$3; W=$4; PTS=${5:-elf/points.txt}
  for rep in $(seq 1 $REPS); do
    while read k w; do
      $L -q --cpu $CPU -w $W -m $M -o res/ck_${k}_$rep.json -- ./$(dirname $PTS)/ck_$k.elf >/dev/null 2>&1 </dev/null
    done < $PTS
  done
fi
echo DONE
"""


# ELFies and run dirs compress ~5x with zstd -1, cheap at both ends
RSYNC_Z = ["--compress", "--compress-choice=zstd", "--compress-level=1"]


# Any transfer disturbs a measurement on the replay machine (sshd, disk I/O
# and memory traffic reach CPU 3 even with the receiver pinned elsewhere:
# +8..40% CPI seen), so uploads and decoding take the measurement lock too.
LOCK = "flock /tmp/usp-measure.lock"
RSYNC_BG = ["--rsync-path", f"{LOCK} taskset -c 4-7 rsync"]


# One persistent connection: every new ssh login on the replay machine starts a
# user session (systemd --user, pipewire, an OTA daemon) that runs for seconds
# on the measurement cluster, outside the measurement lock.
SSH_MUX = ["-o", "ControlMaster=auto", "-o", "ControlPersist=30m",
           "-o", "ControlPath=" + os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "usp-ssh-%C")]


def remote(argv, **kw):
    """ssh/rsync to the replay machine, retrying transient connection resets."""
    if argv[0] == "ssh":
        argv = ["ssh", *SSH_MUX] + argv[1:]
    elif argv[0] == "rsync":
        argv = ["rsync", "-e", shlex.join(["ssh", *SSH_MUX])] + argv[1:]
    for i in range(5):
        rc = subprocess.call(argv, **kw)
        if rc == 0:
            return
        time.sleep(30 * (i + 1))
    raise subprocess.CalledProcessError(rc, argv)


def write_cmd(d, bench, args, w):
    with open(os.path.join(d, "cmd.txt"), "w") as f:
        f.write(f"./{bench} {args}" + (f" < {shlex.quote(w['stdin'])}" if w.get("stdin") else "") + "\n")


def remote_setup():
    remote(["ssh", HOST, f"mkdir -p {RHOME}"])
    with open(os.path.join(VAL, "measure.sh"), "w") as f:
        f.write(MEASURE_SH)
    remote(["rsync", "-a", os.path.join(ROOT, "launcher/usp-run"),
                           os.path.join(VAL, "measure.sh"), f"{HOST}:{RHOME}/"])


def measure_native(name):
    d = os.path.join(VAL, name)
    remote(["rsync", "-a", *RSYNC_Z, *RSYNC_BG, "--mkpath", "--delete", os.path.join(d, "run") + "/",
                           f"{HOST}:{RHOME}/{name}/run/"])
    remote(["rsync", "-a", os.path.join(d, "cmd.txt"), f"{HOST}:{RHOME}/{name}/"])
    remote(["ssh", HOST, f"cd {RHOME}/{name} && {THP_ENV}sh ../measure.sh native {REPS} {FULL}"],
                          stdout=subprocess.DEVNULL)
    remote(["rsync", "-a", f"{HOST}:{RHOME}/{name}/res/", os.path.join(d, "res") + "/"])
    if os.path.exists(os.path.join(d, "res/perint.txt")):
        shutil.copy2(os.path.join(d, "res/perint.txt"), os.path.join(d, "perint.txt"))
    remote(["ssh", HOST, f"rm -rf {RHOME}/{name}/run"])




PATCH_MAX = 2 << 30      # zstd --long=31 window: bigger ELFies go whole


def upload_batches(names, batch_bytes, q):
    """Producer: stream each workload's ELFies to the replay machine in small
    batches, q (bounded) holding the uploaded, not yet measured ones.  The link
    is slow, so ELFies go as a zstd --patch-from chain in interval order:
    checkpoints of one workload share most of their image, and a chain is
    ~30x smaller than the ELFies (vs ~5x for zstd alone).  The replay machine
    decodes each against the previous one and keeps the last as base.elf for
    the next batch."""
    try:
        for name in names:
            d = os.path.join(VAL, name)
            pts = sorted((l.split() for l in open(os.path.join(d, "elf/points.txt"))),
                         key=lambda p: int(p[0]))
            batches, cur, size = [], [], 0
            for k, w in pts:
                sz = os.path.getsize(os.path.join(d, f"elf/ck_{k}.elf"))
                if cur and size + sz > batch_bytes:
                    batches.append(cur)
                    cur, size = [], 0
                cur.append((k, w))
                size += sz
            batches.append(cur)
            prev = None         # local path of the chain's previous ELFie
            remote(["ssh", HOST, f"rm -f {RHOME}/{name}/base.elf"])
            for i, b in enumerate(batches):
                up = os.path.join(d, f"elf/up_{i}")
                shutil.rmtree(up, ignore_errors=True)
                os.makedirs(up)
                with open(os.path.join(up, "batch.txt"), "w") as f:
                    f.writelines(f"{k} {w}\n" for k, w in b)
                with open(os.path.join(up, "decode.sh"), "w") as dec:
                    here = set()        # chain members already in this batch's dir
                    for k, _ in b:
                        src = os.path.join(d, f"elf/ck_{k}.elf")
                        zst = os.path.join(up, f"ck_{k}.zst")
                        big = os.path.getsize(src) > PATCH_MAX
                        pf = []
                        if prev and not big:
                            pf = ["--patch-from=" + prev[0]]
                            base = f"ck_{prev[1]}.elf" if prev[1] in here else "../base.elf"
                        subprocess.check_call(["zstd", "-q", "-9", "-T16", "--long=31", *pf,
                                               src, "-o", zst])
                        dec.write(f"zstd -d -q --long=31 {'--patch-from=' + base if pf else ''} "
                                  f"ck_{k}.zst -o ck_{k}.elf && rm ck_{k}.zst || exit 1\n")
                        here.add(k)
                        if not big:
                            prev = (src, k)
                    if prev and prev[1] in here:
                        dec.write(f"ln -f ck_{prev[1]}.elf ../base.elf\n")
                    # write back now, not during the next measurement (the
                    # disk interrupt is handled on the measurement CPU)
                    dec.write("sync\n")
                rdir = f"elf_{i}"
                remote(["ssh", HOST, f"rm -rf {RHOME}/{name}/{rdir}"])
                remote(["rsync", "-a", *RSYNC_BG, "--mkpath", up + "/",
                        f"{HOST}:{RHOME}/{name}/{rdir}/"])
                remote(["ssh", HOST, f"cd {RHOME}/{name}/{rdir} && {LOCK} taskset -c 4-7 sh decode.sh"])
                shutil.rmtree(up)
                q.put((name, rdir, "batch.txt", i == len(batches) - 1))
    except BaseException as e:      # surfaces in the consumer
        q.put(e)
    q.put(None)


def measure_ckpt(*names, batch_bytes=4e9, ahead=2):
    """Stream ELFies to the replay machine and measure them: the next batches
    are encoded (and uploaded between measurements, under the lock) while the
    current one is measured; each is deleted once measured."""
    q = queue.Queue(ahead)
    threading.Thread(target=upload_batches, args=(names, batch_bytes, q), daemon=True).start()
    while (item := q.get()) is not None:
        if isinstance(item, BaseException):
            raise item
        name, rdir, lst, last = item
        remote(["ssh", HOST, f"cd {RHOME}/{name} && {THP_ENV}sh ../measure.sh ckpt {REPS} {INTERVAL} "
                f"{WARMUP * INTERVAL} {rdir}/{lst} && rm -rf {rdir}"], stdout=subprocess.DEVNULL)
        if last:
            remote(["ssh", HOST, f"rm -f {RHOME}/{name}/base.elf"])
            d = os.path.join(VAL, name)
            remote(["rsync", "-a", f"{HOST}:{RHOME}/{name}/res/", os.path.join(d, "res") + "/"])
            if not KEEP_ELF:
                for f in glob.glob(os.path.join(d, "elf/*.elf")):
                    os.remove(f)
            if len(names) > 1:
                print(f"{name}: ckpt measured", flush=True)


def measure(only):
    remote_setup()
    # one workload at a time, pinned to one core, so runs don't disturb each other
    for name, _, _ in WORKLOADS:
        d = os.path.join(VAL, name)
        if (only and name not in only) or not os.path.exists(os.path.join(d, "elf/points.txt")):
            continue
        print(f"measuring {name} ...", flush=True)
        measure_native(name)
        measure_ckpt(name)


def run(only):
    """Capture JOBS workloads at a time on the host; one replay-machine worker
    measures checkpoints as soon as they exist (to free disk) and native runs
    in between. At most JOBS captured-but-unmeasured workloads exist at once."""
    import queue
    import threading
    os.makedirs(VAL, exist_ok=True)
    remote_setup()
    todo = [w for w in WORKLOADS if not only or w[0] in only]
    todo.sort(key=lambda w: -WL[w[0]].get("insts", 0))     # longest captures first
    q = queue.PriorityQueue()          # (0, ckpt) before (1, native)
    slots = threading.Semaphore(JOBS)
    left = [len(todo) * 2]
    lock = threading.Lock()

    def cap(w):
        slots.acquire()
        # a capture can need tens of GB; wait for the replay side to free some
        while shutil.disk_usage(VAL).free < MIN_FREE:
            time.sleep(60)
        try:
            msg = capture_one(w)
        except Exception as e:      # noqa: BLE001 - report and keep going
            msg = f"{w[0]}: capture error {e!r}"
        print(msg, flush=True)
        if REUSE:
            with lock:
                left[0] -= 1
        else:
            q.put((1, "native", w[0]))
        if os.path.exists(os.path.join(VAL, w[0], "elf/points.txt")):
            q.put((0, "ckpt", w[0]))
        else:
            slots.release()
            with lock:
                left[0] -= 1

    def k3():
        while True:
            with lock:
                if left[0] == 0:
                    return
            try:
                _, kind, name = q.get(timeout=30)
            except queue.Empty:
                continue
            t = time.time()
            try:
                (measure_ckpt if kind == "ckpt" else measure_native)(name)
                print(f"{name}: {kind} measured in {time.time() - t:.0f}s", flush=True)
            except Exception as e:  # noqa: BLE001
                print(f"{name}: {kind} measure error {e!r}", flush=True)
            if kind == "ckpt":
                slots.release()
            with lock:
                left[0] -= 1

    th = threading.Thread(target=k3)
    th.start()
    with cf.ThreadPoolExecutor(JOBS) as ex:
        list(ex.map(cap, todo))
    th.join()


def perint_cpi(d):
    """Native CPI of each interval, from perf script -F period,event output."""
    p = os.path.join(d, "perint.txt")
    if not os.path.exists(p):
        return None
    nums = [int(l.split()[0]) for l in open(p) if re.match(r"\s*\d+ +(instructions|cycles)", l)]
    return [nums[i + 1] / nums[i] for i in range(0, len(nums) - 1, 2)]


def report():
    """error = checkpoint estimate vs full run; split (when the per-interval
    profile exists) into SimPoint error (native CPI of the chosen intervals vs
    full run) and checkpoint bias (checkpoint vs native CPI, same intervals)."""
    print(f"{'workload':14} {'insts':>7} {'pts':>4} {'full CPI':>9} {'(spread)':>8} {'ckpt est':>9} "
          f"{'error':>7} {'simpoint':>8} {'bias':>7}")
    errs, sps, bs = [], [], []
    for name, _, _ in WORKLOADS:
        d = os.path.join(VAL, name)
        full = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(d, "res/full_*.json")))]
        full = [x for x in full if x.get("insts")]
        if not full or not os.path.exists(os.path.join(d, "elf/points.txt")):
            continue
        fc = [x["cycles"] / x["insts"] for x in full]
        truth = st.median(fc)
        cpi = perint_cpi(d)
        est = sp = W = Ws = 0.0
        bad = 0
        pts = [l.split() for l in open(os.path.join(d, "elf/points.txt"))]
        for k, w in pts:
            rs = [json.load(open(f)) for f in glob.glob(os.path.join(d, f"res/ck_{k}_*.json"))]
            ok = [r for r in rs if r.get("complete")]
            if not ok:
                bad += 1
                continue
            m = st.median(r["cpi"] for r in ok)
            est += float(w) * m
            W += float(w)
            if cpi and int(k) < len(cpi):
                sp += float(w) * cpi[int(k)]
                Ws += float(w)
        if not W:
            continue
        est /= W
        err = 100 * (est / truth - 1)
        errs.append(err)
        dec = ""
        if Ws:
            sp /= Ws
            sps.append(100 * (sp / truth - 1))
            bs.append(100 * (est / sp - 1))
            dec = f" {sps[-1]:+7.2f}% {bs[-1]:+6.2f}%"
        spread = 100 * (max(fc) - min(fc)) / truth
        print(f"{name:14} {full[0]['insts'] / 1e9:6.1f}G {len(pts):4} {truth:9.4f} {spread:7.2f}% "
              f"{est:9.4f} {err:+6.2f}%{dec}" + (f"  ({bad} incomplete)" if bad else ""))
    for lbl, v in (("error", errs), ("simpoint", sps), ("bias", bs)):
        if v:
            print(f"{lbl:9} mean |.| {st.mean(abs(e) for e in v):.2f}%, max {max(v, key=abs):+.2f}%")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    only = set(sys.argv[2:])
    if cmd == "capture":
        os.makedirs(VAL, exist_ok=True)
        todo = [w for w in WORKLOADS if not only or w[0] in only]
        # bounded: raw checkpoints and ELFies coexist until each workload is packed
        todo.sort(key=lambda w: w[0] != "lbm")      # longest first
        with cf.ThreadPoolExecutor(JOBS) as ex:
            for msg in ex.map(capture_one, todo):
                print(msg, flush=True)
    elif cmd == "measure":
        measure(only)
    elif cmd == "native":       # (re)do native runs that are missing, on clean run dirs
        remote_setup()
        for name, bench, _ in WORKLOADS:
            d = os.path.join(VAL, name)
            if (only and name not in only) or glob.glob(os.path.join(d, "res/full_*.json")):
                continue
            shutil.rmtree(os.path.join(d, "run"), ignore_errors=True)
            prep_rundir(bench, os.path.join(d, "run"), WL[name]["inputs"])
            write_cmd(d, bench, WL[name]["args"], WL[name])
            t = time.time()
            measure_native(name)
            print(f"{name}: native measured in {time.time() - t:.0f}s", flush=True)
    elif cmd == "ckpt":         # (re)measure checkpoints of the named workloads
        remote_setup()
        measure_ckpt(*[w[0] for w in WORKLOADS if w[0] in only])
    elif cmd == "run":
        run(only)
    elif cmd == "report":
        report()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()

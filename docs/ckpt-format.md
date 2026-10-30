# usimpoint checkpoint format (v2)

A checkpoint is a directory produced by the capture plugin (or by the test-only
ptrace dumper). `usp-mkelf` turns it into a self-restoring static ELF ("ELFie").

```
ckpt/
  manifest.json
  mem.bin          # concatenated contents of all non-zero page runs, page aligned
```

All addresses/values in JSON are hex strings (`"0x10074"`) unless stated.
Page size is 4096.

## manifest.json

```jsonc
{
  "version": 2,                  // 1: no "vector" (still accepted by usp-mkelf)
  "arch": "riscv64",
  "source": "qemu-plugin" | "ptrace",
  "icount": "0x...",            // user instructions executed before this point (exact for qemu)
  "interval": 4711,             // SimPoint interval index (optional)
  "weight": 0.0123,             // SimPoint weight (optional)
  "cpu": "rva23u64:vlen=256:...",   // capture -cpu string (',' -> ':'), informational

  // CPU state. gpr[] uses Linux struct user_regs_struct order:
  // pc, ra, sp, gp, tp, t0, t1, t2, s0, s1, a0..a7, s2..s11, t3..t6  (32 entries)
  "gpr": ["0x...", ...32],
  "fpr": ["0x...", ...32],       // f0..f31 raw 64-bit
  "fcsr": "0x0",

  // v2, only if the capture CPU has V. State at the checkpoint TB boundary.
  // CSRs as read from QEMU: vtype includes vill in bit 63; vcsr = vxrm << 1 | vxsat
  // (vxrm/vxsat are informational, vcsr is what gets restored).
  "vector": {
    "vlenb": 32,                      // decimal; must equal the target's vlenb
    "vstart": "0x0", "vl": "0x4", "vtype": "0x97", "vcsr": "0x0",
    "vxrm": "0x0", "vxsat": "0x0",
    // v0..v31: each register as one little-endian number of vlenb bytes,
    // i.e. byte i of the hex value (counting from the right) = byte i of the
    // register in memory order (what vs1r.v would store), = element 0 lowest.
    "v": ["0x0000...0000", ...32]
  },

  // Address space. Every mapped guest region, sorted, non-overlapping, page aligned.
  "regions": [
    {
      "start": "0x10000", "end": "0x8c000",
      "prot": "r-x",                       // r/w/x or '-'
      "name": "exe" | "heap" | "stack" | "vdso" | "anon",   // informational
      // runs of pages that are not all-zero; other pages are zero-filled
      "runs": [ { "vaddr": "0x10000", "npages": 124, "file_off": "0x0" } ]
    }
  ],

  "brk":  { "start": "0x97000", "cur": "0xb9000" },
  // values for prctl(PR_SET_MM_MAP); derived from initial stack / exe regions
  "mm": {
    "start_code": "0x...", "end_code": "0x...",
    "start_data": "0x...", "end_data": "0x...",
    "start_stack": "0x...",
    "arg_start": "0x...", "arg_end": "0x...",
    "env_start": "0x...", "env_end": "0x..."
  },

  // Open file descriptors at capture time (excluding nothing: 0/1/2 included)
  "fds": [
    { "fd": 0, "kind": "stdin" },
    { "fd": 1, "kind": "stdout" },
    { "fd": 2, "kind": "stderr" },
    { "fd": 3, "kind": "file", "path": "200.c",       // relative to run dir if under it, else absolute
      "flags": "0x0", "offset": "0x1234" },          // open(2) flags, as numbers for riscv64 Linux
    { "fd": 4, "kind": "file", "path": "out.s", "flags": "0x241", "offset": "0x99",
      "content": "files/4.bin" }                     // optional: file contents at capture to restore first
  ],

  "cwd": "/abs/path/at/capture",     // informational; restore runs in the launcher's cwd
  "umask": "0x12",
  "tid_address": "0x970f0",          // set_tid_address() value, "0x0" if never set
                                     // (of the checkpointed thread; also from CLONE_CHILD_CLEARTID)
  "sigmask": "0x0",                  // blocked signal mask (64-bit) of the checkpointed thread
  "sigactions": [                    // only non-default ones
    { "sig": 11, "handler": "0x...", "flags": "0x...", "mask": "0x..." }
  ]
}
```

## Restore contract (implemented by the ELFie restorer)

1. Restorer runs at a VA hole that no region uses (chosen by `usp-mkelf`).
2. Unmaps everything outside itself (kernel stack, vdso, vvar).
3. For each region: anonymous `mmap(MAP_FIXED)` RW, then `mmap(MAP_FIXED|MAP_PRIVATE)`
   each run from the ELFie file at its (page-aligned) offset, then `mprotect` to `prot`.
4. `prctl(PR_SET_MM, PR_SET_MM_MAP, ...)` with `mm` + `brk` (exe_fd = -1). If that
   fails, print a warning to stderr and continue (heap growth via brk will then fail
   and glibc falls back to mmap).
5. fds: close everything ≥ 3 inherited, then for each `file` entry open `path`
   (relative to cwd) with `flags` (writing files: O_CREAT, contents restored from
   `content` if present), `dup2` to `fd`, `lseek` to `offset`. 0/1/2 are inherited
   from the launcher.
6. `umask`, `set_tid_address`, `rt_sigaction` for each entry.
7. Final switch via `rt_sigreturn` on a crafted `struct rt_sigframe` whose
   `uc_mcontext` holds gpr/fpr/fcsr, `uc_sigmask` = `sigmask`, `uc_stack.ss_flags =
   SS_DISABLE`. Without `vector` the extension area is zero (END header). With it,
   the first extension header is `RISCV_V_MAGIC` and its payload
   (`struct __riscv_v_ext_state` + register file) follows the sigcontext, then END.
   This restores every register (incl. vl/vtype via the kernel's `vsetvl`, so `vill`
   comes back as captured) and the PC atomically. Vector registers cannot be
   restored "by hand" before the final ecall: Linux discards the vector state on
   every syscall entry (vl=0, vtype=vill, v* = all ones), the rt_sigreturn included.

The restored program cannot tell it was restored, except via syscall-visible
differences listed in DESIGN.md (pid, time, etc.).

Multi-threaded guests (DESIGN.md F) add, after `vector`:

```jsonc
  "thread": { "ordinal": 1,          // creation order of the checkpointed thread (0 = main)
              "live_threads": 2, "threads_created": 2,
              "switches_before": 3 }  // thread switches before this point
```

The image restores only that thread (gpr incl. `tp`, fpr, vector, sigmask,
tid_address are its own); the other threads exist only as memory. If another
thread ran within the trace window, the plugin ends `syscalls.bin` there and
writes `switch` (decimal: instructions after the checkpoint) into the
checkpoint directory; the image is usable only for windows shorter than that.

## syscalls.bin — replay trace (v1)

Recorded by the capture plugin for the `window` instructions after the checkpoint
(default 3 × interval), for the checkpointed thread only. With it, the replayed program never needs a real kernel
except for address-space changes: every syscall is answered from the trace.

```
header:  char magic[8] = "USPTRC01"; u64 count; u64 start_icount; u64 window
record:  u64 icount_rel        // insts since checkpoint at the syscall (TB granularity)
         i64 num               // syscall number
         u64 args[6]           // a0..a5 as issued (for divergence checks)
         i64 ret               // return value (negative errno on failure)
         u64 nwrites
         nwrites × { u64 addr; u64 len; u8 data[len]; pad to 8 bytes }
```

`writes` are every byte range the kernel (QEMU) stored into guest memory during
the syscall, hooked generically at QEMU's `unlock_user()`. For a file-backed `mmap`
the mapped file contents are included as a write at the returned address.
`exit`/`exit_group` are recorded at entry (they never return).

Replay rules (restorer, seccomp `SECCOMP_RET_TRAP` + SIGSYS handler):
- Address-space syscalls are **executed**, forced to the recorded result:
  `mmap` → `MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS` at `ret`, apply writes, then final
  prot; `munmap`, `mprotect`, `madvise` → executed as issued; `mremap` → executed with
  `MREMAP_MAYMOVE|MREMAP_FIXED` to `ret`; `brk` → grow/shrink an anonymous mapping
  from the current break (starts at manifest `brk.cur`) to `ret`, return `ret`.
- `exit`, `exit_group` → executed.
- `riscv_flush_icache` (259) → executed and **not** matched against the trace: QEMU
  handles it in its CPU loop before the syscall layer, so it never appears in a
  trace. It is cache maintenance, so it must really happen on hardware (JITs).
- Everything else → not executed: apply `writes`, return `ret`.
- If `num` (or the args, for divergence checks) differs from the next record, or the
  trace is exhausted → report divergence and `exit_group(126)`.

## Restorer / mkelf implementation notes (non-normative)

Code: `restorer/` (stub), `tools/usp-mkelf.py`, test producer `tools/usp-ptdump/`.
The ELFie's binary descriptor (regions/runs/fds/sigs/regs, replay trace location)
is defined in `restorer/usp_desc.h`; it is private to mkelf+restorer.

- `usp-mkelf --mode replay` (default) needs `syscalls.bin`; `--mode live` uses the
  manifest's fds/brk/mm/sigactions instead. Replay mode always loads memory eagerly
  (anonymous mappings filled with `pread`), so `madvise(MADV_DONTNEED)` zero-fills
  like on the capture side. Live mode maps runs lazily from the ELFie file
  (`--eager` to copy instead).
- The kernel's own `[vvar*]`/`[vdso]` of the ELFie process are `mremap`ed into a
  1 MiB slot reserved by mkelf next to the restorer (the vdso `.mremap` hook updates
  `mm->context.vdso`, so signal-handler returns via the kernel trampoline keep
  working); everything else outside the restorer is unmapped. The checkpoint's own
  vdso region (QEMU's) is restored like any other region. If the `mremap` fails the
  restorer warns and unmaps them. `USP_NO_KVDSO=1` disables the relocation (debug);
  `USP_VERBOSE=1` traces the restore steps.
- Regions named `stack` are mapped `MAP_GROWSDOWN` and always filled eagerly, so
  the stack can grow below the captured extent.
- The restorer re-execs itself once with `ADDR_NO_RANDOMIZE` if ASLR is on
  (future `mmap` placement then matches a non-randomized run; `--no-reexec` disables).
- Live-mode fds: writable files with `content` are recreated from it (truncate +
  write) and reopened without `O_TRUNC/O_EXCL`; writable files without `content`
  are opened with `O_CREAT` and, if `flags` had `O_TRUNC`, truncated to `offset`.
- Live mode: if `PR_SET_MM_MAP` fails the kernel break stays at the restorer's
  segment end, which lies above the image heap, so glibc's `brk` *appears to
  succeed* with unmapped memory (it does not fall back to `mmap`). The restorer
  warns; such images are only usable if no heap growth happens.
- Replay mode: seccomp allows syscalls whose IP is inside the restorer PT_LOAD
  (mkelf keeps it within one 4 GiB-aligned window, away from every region and every
  address the trace maps), everything else traps to a SIGSYS handler on an
  alternate stack inside the restorer. On riscv the SIGSYS ucontext pc already
  points past the `ecall` and `a0` holds the original argument. The handler ends
  with its own `rt_sigreturn` ecall (inside the allowed range). The seccomp-allowed
  range also covers the relocated kernel vdso. `riscv_flush_icache` (259) is
  executed for real without consuming a record. All six argument
  registers are compared with the record. Trace exhaustion or divergence prints
  `usp-replay: ...` and exits 126. Each replayed syscall costs ~6.5k cycles on
  the K3 (vs ~380 for a native `getppid`) and adds ~120 user instructions to
  `instructions:u`.
- Vector restore (`USP_F_VECTOR`, descriptor v3): the restorer first checks
  `AT_HWCAP` 'V' and that `csrr vlenb` equals the image's vlenb (else exit 127).
  That CSR read is the task's first vector use, so the kernel turns V on; a V
  sigreturn frame is rejected (SIGSEGV) for a task with V off. The kernel also
  demands that the V header size equals its `riscv_v_sc_size` exactly, which is
  sized for the *largest VLEN of any hart*, not the running one: on the K3,
  8 + 48 + 4096 although the X100 cores have vlenb 32 (harts 8-15 are A100 "AI"
  cores, outside the default affinity mask 0-7; their VLEN is evidently 1024).
  The restorer's vlenb check also catches an image restored on a hart with
  another VLEN; a process migrating between such harts afterwards would break
  anyway. The registers are restored packed with the running hart's
  vlenb from the start of the area. The restorer therefore sends itself one
  SIGUSR1 and takes the size from the kernel-built frame's V header
  (`AT_MINSIGSTKSZ` would also encode it, less directly).
- Replay mode and vector state: the SIGSYS frame carries the V state the kernel
  saved, and the handler's `rt_sigreturn` restores it, so the handler (rv64gc
  code) cannot disturb it. Because the kernel discards V state at syscall entry
  *before* seccomp runs, a replayed syscall leaves the same (discarded) vector
  state as a native one. QEMU linux-user does not discard on syscalls; code that
  follows the kernel's vector ABI (Documentation/arch/riscv/vector.rst: v0-v31,
  vl, vtype, vstart are clobbered by syscalls) cannot observe the difference, and
  the state captured at a checkpoint is always QEMU's real state.
- ptrace producer: `[vvar*]` pages are emitted as zero-filled `r--` regions (a zero
  vvar makes the vDSO fall back to real syscalls); the `[vdso]` is dumped as code.

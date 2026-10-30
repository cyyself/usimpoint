#!/usr/bin/env python3
"""usp-mkelf: turn a usimpoint checkpoint directory into a self-restoring
static ELF ("ELFie").

  usp-mkelf.py [-r restorer.bin] [--base VA] [--eager] [--no-reexec] CKPT_DIR -o OUT.elf

Layout of the output file (see restorer/usp_desc.h for the descriptor):
  0x0      ELF header, PT_LOAD (restorer), PT_GNU_STACK
  0x1000   restorer segment file image: blob | descriptor | tables | strtab
  ...      fd content blobs (page aligned)
  ...      mem.bin (page aligned); runs are mmapped from here by the restorer
Only the restorer is a PT_LOAD; the image memory is plain file data, so the
kernel's ELF loader (and its brk setup) never sees it.
"""
import argparse
import json
import os
import struct
import sys

PAGE = 4096
SV39_TOP = 1 << 38

USP_BLOB_MAGIC = 0x52505355
USP_DESC_MAGIC = 0x44505355
USP_DESC_VERSION = 3
USP_F_HAVE_MM, USP_F_NO_REEXEC, USP_F_EAGER, USP_F_REPLAY, USP_F_VECTOR = 1, 2, 4, 8, 16
USP_R_STACK = 1
USP_FD_INHERIT, USP_FD_FILE = 0, 1
NO_CONTENT = (1 << 64) - 1

DESC_FMT = '<IIQQQIIIIQQQQQ32Q32QQQQQ11Q8Q6Q'
KVDSO_SLOT = 1 << 20  # hole for the kernel's [vvar]+[vdso] (mremap'ed there)
REGION_FMT = '<QQIIII'
RUN_FMT = '<QQQ'
FD_FMT = '<iIIIQQQQ'
SIG_FMT = '<QQQQ'


def die(msg):
    sys.exit('usp-mkelf: error: ' + msg)


def H(v):
    if isinstance(v, int):
        return v
    return int(v, 0)


def align(v, a):
    return (v + a - 1) // a * a


def prot_bits(s):
    if len(s) < 3:
        die('bad prot %r' % s)
    return (1 if s[0] == 'r' else 0) | (2 if s[1] == 'w' else 0) | (4 if s[2] == 'x' else 0)


def parse_trace(data):
    """Parse syscalls.bin; returns (count, [(start, end)] address ranges the
    replayed program will map via mmap/mremap/brk)."""
    if len(data) < 32 or data[:8] != b'USPTRC01':
        die('syscalls.bin: bad magic')
    count = struct.unpack_from('<Q', data, 8)[0]
    o, ranges = 32, []
    for i in range(count):
        if o + 80 > len(data):
            die('syscalls.bin: truncated at record %d' % i)
        num = struct.unpack_from('<q', data, o + 8)[0]
        args = struct.unpack_from('<6Q', data, o + 16)
        ret, nw = struct.unpack_from('<qQ', data, o + 64)
        o += 80
        for _ in range(nw):
            _a, ln = struct.unpack_from('<QQ', data, o)
            o += 16 + align(ln, 8)
        if ret < 0 and ret > -4096:
            continue
        if num == 222:      # mmap
            ranges.append((ret, ret + align(args[1], PAGE)))
        elif num == 216:    # mremap
            ranges.append((ret, ret + align(args[2], PAGE)))
        elif num == 214:    # brk
            ranges.append((0, align(ret, PAGE)))  # treated as "below brk"
    if o > len(data):
        die('syscalls.bin: truncated')
    return count, ranges


def parse_vector(m):
    """Manifest v2 "vector" object -> (vstart, vl, vtype, vcsr, vlenb, regfile bytes)."""
    v = m.get('vector')
    if not v:
        return None
    vlenb = int(v['vlenb'])
    if vlenb <= 0 or vlenb & (vlenb - 1) or vlenb > 256:
        die('bad vlenb %d' % vlenb)
    if len(v['v']) != 32:
        die('vector.v must have 32 entries')
    regs = b''.join(H(x).to_bytes(vlenb, 'little') for x in v['v'])
    return (H(v.get('vstart', 0)), H(v['vl']), H(v['vtype']), H(v.get('vcsr', 0)), vlenb, regs)


def pick_base(regions, size, want=None, extra=()):
    """Find a VA hole for the restorer segment (+ replay trace) that overlaps no
    region and no range the replayed program maps (1 MiB margin), within one
    4 GiB-aligned window (for the seccomp IP check), preferring high addresses
    below the Sv39 limit but away from the top where the kernel puts the
    initial stack."""
    margin = 1 << 20
    busy = sorted([(H(r['start']) - margin, H(r['end']) + margin) for r in regions] +
                  [(s - margin, e + margin) for s, e in extra])

    def free(b):
        e = b + size
        return b >= 1 << 24 and (b >> 32) == ((e - 1) >> 32) and \
            all(e <= s or b >= t for s, t in busy)

    if want is not None:
        if not free(want):
            die('--base 0x%x overlaps a region' % want)
        return want
    step = 1 << 24
    # 128 GiB first, then scan downward, then upward to 0x3f00000000.
    cands = list(range(0x2000000000, 1 << 24, -step)) + \
        list(range(0x2000000000 + step, 0x3f00000000 - size, step))
    for b in cands:
        if free(b):
            return b
    die('no VA hole for the restorer')


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('ckpt', help='checkpoint directory (manifest.json, mem.bin)')
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('-r', '--restorer',
                    default=os.path.join(here, '..', 'restorer', 'build', 'restorer.bin'))
    ap.add_argument('--base', type=lambda s: int(s, 0), help='restorer VA (default: auto)')
    ap.add_argument('--eager', action='store_true',
                    help='copy memory with pread into anonymous mappings instead of mmapping the file')
    ap.add_argument('--no-reexec', action='store_true',
                    help='do not re-exec with ADDR_NO_RANDOMIZE when ASLR is on')
    ap.add_argument('--no-mm', action='store_true', help='skip prctl(PR_SET_MM_MAP)')
    ap.add_argument('--mode', choices=('replay', 'live'), default='replay',
                    help='replay: answer syscalls from syscalls.bin (seccomp+SIGSYS); '
                         'live: recreate fds/brk/signals and run against the real kernel')
    a = ap.parse_args()

    m = json.load(open(os.path.join(a.ckpt, 'manifest.json')))
    if m.get('version') not in (1, 2) or m.get('arch') != 'riscv64':
        die('unsupported manifest version/arch')
    vec = parse_vector(m)
    blob = open(a.restorer, 'rb').read()
    jump, bmagic, blob_size, stack_size = struct.unpack_from('<IIQQ', blob, 0)
    if bmagic != USP_BLOB_MAGIC:
        die('%s is not a restorer blob' % a.restorer)
    if len(blob) > blob_size:
        die('restorer blob larger than its declared size')
    blob = blob + b'\0' * (blob_size - len(blob))

    trace, trace_ranges, trace_count = b'', [], 0
    if a.mode == 'live' and m.get('live_unsupported'):
        die('live mode unsupported for this checkpoint: %s' % m['live_unsupported'])
    if a.mode == 'replay':
        tp = os.path.join(a.ckpt, 'syscalls.bin')
        if not os.path.exists(tp):
            die('replay mode needs %s (use --mode live)' % tp)
        trace = open(tp, 'rb').read()
        trace_count, trace_ranges = parse_trace(trace)

    mem_path = os.path.join(a.ckpt, 'mem.bin')
    mem_size = os.path.getsize(mem_path)

    # ---- regions / runs ----
    regions = sorted(m['regions'], key=lambda r: H(r['start']))
    prev_end = 0
    reg_recs, run_recs = [], []
    for r in regions:
        s, e = H(r['start']), H(r['end'])
        if s % PAGE or e % PAGE or e <= s or s < prev_end:
            die('bad/overlapping region %s-%s' % (r['start'], r['end']))
        prev_end = e
        first = len(run_recs)
        for u in sorted(r.get('runs', []), key=lambda u: H(u['vaddr'])):
            va, n, off = H(u['vaddr']), int(u['npages']), H(u['file_off'])
            if va % PAGE or off % PAGE or va < s or va + n * PAGE > e:
                die('bad run %s in region %s' % (u['vaddr'], r['start']))
            if off + n * PAGE > mem_size:
                die('run %s beyond mem.bin' % u['vaddr'])
            run_recs.append([va, n, off])
        flags = USP_R_STACK if r.get('name') == 'stack' else 0
        reg_recs.append((s, e, prot_bits(r['prot']), flags, first, len(run_recs) - first))

    # ---- fds ----
    strtab = bytearray()

    def addstr(s):
        off = len(strtab)
        strtab.extend(s.encode() + b'\0')
        return off

    fd_recs, contents = [], []
    for f in sorted(m.get('fds', []), key=lambda f: int(f['fd'])):
        fd, kind = int(f['fd']), f['kind']
        if kind in ('stdin', 'stdout', 'stderr'):
            fd_recs.append([fd, USP_FD_INHERIT, 0, 0, 0, addstr(''), NO_CONTENT, 0])
            continue
        if kind != 'file':
            die('fd %d: unsupported kind %r' % (fd, kind))
        mode = H(f['mode']) if 'mode' in f else 0o644
        rec = [fd, USP_FD_FILE, H(f.get('flags', '0x0')), mode, H(f.get('offset', '0x0')),
               addstr(f['path']), NO_CONTENT, 0]
        if f.get('content') and a.mode == 'live':
            data = open(os.path.join(a.ckpt, f['content']), 'rb').read()
            contents.append((len(fd_recs), data))
        fd_recs.append(rec)

    # ---- signals ----
    sig_recs = []
    for s in sorted(m.get('sigactions', []), key=lambda s: int(s['sig'])):
        sig_recs.append((int(s['sig']), H(s['handler']), H(s.get('flags', 0)), H(s.get('mask', 0))))

    # ---- descriptor ----
    desc_size = struct.calcsize(DESC_FMT)
    regions_off = align(desc_size, 16)
    runs_off = regions_off + len(reg_recs) * struct.calcsize(REGION_FMT)
    fds_off = align(runs_off + len(run_recs) * struct.calcsize(RUN_FMT), 16)
    sigs_off = fds_off + len(fd_recs) * struct.calcsize(FD_FMT)
    strtab_off = sigs_off + len(sig_recs) * struct.calcsize(SIG_FMT)
    vregs_off = align(strtab_off + len(strtab), 16)
    desc_total = vregs_off + (len(vec[5]) if vec else 0)

    filesz = blob_size + desc_total
    seg_size = align(filesz, 16) + stack_size
    seg_mem = align(seg_size, PAGE)
    trace_span = align(len(trace), PAGE)
    base = pick_base(regions, seg_mem + trace_span + KVDSO_SLOT, a.base, trace_ranges)
    trace_va = base + seg_mem
    kvdso_va = trace_va + trace_span

    # file layout
    seg_off = PAGE
    off = align(seg_off + filesz, PAGE)
    for idx, data in contents:
        fd_recs[idx][6] = off
        fd_recs[idx][7] = len(data)
        off = align(off + len(data), PAGE)
    trace_off = off
    off = align(off + len(trace), PAGE)
    mem_off = off
    for u in run_recs:
        u[2] += mem_off

    gpr = [H(x) for x in m['gpr']]
    fpr = [H(x) for x in m['fpr']]
    if len(gpr) != 32 or len(fpr) != 32:
        die('gpr/fpr must have 32 entries')
    flags = 0
    if a.eager:
        flags |= USP_F_EAGER
    if a.no_reexec:
        flags |= USP_F_NO_REEXEC
    mm = [0] * 11
    replay = [0] * 6
    if a.mode == 'replay':
        flags |= USP_F_REPLAY | USP_F_EAGER
        # seccomp allows the restorer and the relocated kernel vdso (sigreturn trampoline)
        replay = [trace_off, len(trace), trace_va, H(m['brk']['cur']), base,
                  kvdso_va + KVDSO_SLOT]
    elif not a.no_mm and 'mm' in m and 'brk' in m:
        mm_j, brk = m['mm'], m['brk']
        mm = [H(mm_j['start_code']), H(mm_j['end_code']), H(mm_j['start_data']),
              H(mm_j['end_data']), H(brk['start']), H(brk['cur']), H(mm_j['start_stack']),
              H(mm_j['arg_start']), H(mm_j['arg_end']), H(mm_j['env_start']), H(mm_j['env_end'])]
        flags |= USP_F_HAVE_MM
    vdesc = [0] * 6
    if vec:
        flags |= USP_F_VECTOR
        vdesc = list(vec[:5]) + [vregs_off]

    desc = bytearray(desc_total)
    struct.pack_into(DESC_FMT, desc, 0, USP_DESC_MAGIC, USP_DESC_VERSION, seg_size, base, flags,
                     len(reg_recs), len(run_recs), len(fd_recs), len(sig_recs),
                     regions_off, runs_off, fds_off, sigs_off, strtab_off,
                     *gpr, *fpr, H(m.get('fcsr', '0x0')), H(m.get('sigmask', '0x0')),
                     H(m.get('umask', '0x12')), H(m.get('tid_address', '0x0')), *mm, *replay, kvdso_va, KVDSO_SLOT,
                     *vdesc)
    for i, r in enumerate(reg_recs):
        struct.pack_into(REGION_FMT, desc, regions_off + i * struct.calcsize(REGION_FMT), *r)
    for i, r in enumerate(run_recs):
        struct.pack_into(RUN_FMT, desc, runs_off + i * struct.calcsize(RUN_FMT), *r)
    for i, r in enumerate(fd_recs):
        struct.pack_into(FD_FMT, desc, fds_off + i * struct.calcsize(FD_FMT), *r)
    for i, r in enumerate(sig_recs):
        struct.pack_into(SIG_FMT, desc, sigs_off + i * struct.calcsize(SIG_FMT), *r)
    desc[strtab_off:strtab_off + len(strtab)] = strtab
    if vec:
        desc[vregs_off:] = vec[5]

    # ---- ELF header + program headers ----
    phnum = 2
    ehdr = struct.pack('<4sBBBBB7sHHIQQQIHHHHHH', b'\x7fELF', 2, 1, 1, 0, 0, b'\0' * 7,
                       2, 243, 1, base, 64, 0, 0x5,  # ET_EXEC, EM_RISCV, RVC|double-float ABI
                       64, 56, phnum, 64, 0, 0)
    PT_LOAD, PT_GNU_STACK = 1, 0x6474e551
    ph_load = struct.pack('<IIQQQQQQ', PT_LOAD, 7, seg_off, base, base, filesz, seg_size, PAGE)
    ph_stack = struct.pack('<IIQQQQQQ', PT_GNU_STACK, 6, 0, 0, 0, 0, 0, 16)

    tmp = a.output + '.tmp'
    with open(tmp, 'wb') as o:
        o.write(ehdr + ph_load + ph_stack)
        o.seek(seg_off)
        o.write(blob)
        o.write(desc)
        for idx, data in contents:
            o.seek(fd_recs[idx][6])
            o.write(data)
        if trace:
            o.seek(trace_off)
            o.write(trace)
        o.seek(mem_off)
        with open(mem_path, 'rb') as mf:
            while True:
                chunk = mf.read(1 << 24)
                if not chunk:
                    break
                o.write(chunk)
        o.truncate(mem_off + mem_size)
    os.chmod(tmp, 0o755)
    os.replace(tmp, a.output)
    print('usp-mkelf: %s: %s mode, restorer at 0x%x (+0x%x), %d regions, %d runs, %d fds, '
          '%d trace records, mem %d MiB at file 0x%x%s'
          % (a.output, a.mode, base, seg_size, len(reg_recs), len(run_recs), len(fd_recs),
             trace_count, mem_size >> 20, mem_off,
             ', vector VLEN=%d' % (vec[4] * 8) if vec else ''))


if __name__ == '__main__':
    main()

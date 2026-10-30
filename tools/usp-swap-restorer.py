#!/usr/bin/env python3
"""Replace the restorer stub inside existing ELFies (no raw checkpoint needed).

  usp-swap-restorer.py [-r restorer.bin] ELF...

The descriptor and everything after it are kept; the descriptor moves with the
new blob size. Works only while the segment still fits the old page-aligned
file and memory footprint (true for small restorer changes); otherwise the
ELFie is left untouched and reported.
"""
import argparse
import os
import struct
import sys

PAGE = 4096
USP_BLOB_MAGIC = 0x52505355


def align(x, a):
    return (x + a - 1) // a * a


def swap(path, blob):
    jump, magic, nbs, stack = struct.unpack_from('<IIQQ', blob, 0)
    blob = blob + b'\0' * (nbs - len(blob))
    with open(path, 'r+b') as f:
        hdr = f.read(64 + 56)
        p_type, p_flags, seg_off, va, pa, filesz, memsz, al = struct.unpack_from('<IIQQQQQQ', hdr, 64)
        f.seek(seg_off)
        old = f.read(filesz)
        _, omagic, obs, ostack = struct.unpack_from('<IIQQ', old, 0)
        if omagic != USP_BLOB_MAGIC or ostack != stack:
            return 'not an ELFie with a compatible restorer'
        desc = bytearray(old[obs:])
        nfilesz = nbs + len(desc)
        # a smaller blob keeps the old seg_size (the restorer stack grows a
        # little) so the memory layout after the segment does not move
        nseg = max(align(nfilesz, 16) + stack, struct.unpack_from('<Q', desc, 8)[0])
        if align(seg_off + nfilesz, PAGE) > align(seg_off + filesz, PAGE) or \
                align(nseg, PAGE) != align(memsz, PAGE):
            return 'new restorer does not fit the old layout; rebuild with usp-mkelf.py'
        struct.pack_into('<Q', desc, 8, nseg)          # usp_desc.seg_size
        f.seek(seg_off)
        f.write(blob + desc)
        if nfilesz < filesz:
            f.write(b'\0' * (filesz - nfilesz))
        f.seek(64)
        f.write(struct.pack('<IIQQQQQQ', p_type, p_flags, seg_off, va, pa, nfilesz, nseg, al))
    return None


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument('-r', '--restorer', default=os.path.join(here, '..', 'restorer', 'build', 'restorer.bin'))
    ap.add_argument('elf', nargs='+')
    a = ap.parse_args()
    blob = open(a.restorer, 'rb').read()
    bad = 0
    for p in a.elf:
        err = swap(p, blob)
        if err:
            bad += 1
            print(f'{p}: {err}', file=sys.stderr)
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()

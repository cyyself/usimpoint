#!/usr/bin/env python3
"""Write a synthetic syscalls.bin for sysbench: N x getppid (ret 42), then exit_group(0)."""
import struct, sys
out, n = sys.argv[1], int(sys.argv[2])
recs = [struct.pack('<Qq6QqQ', 0, 173, 0, 0, 0, 0, 0, 0, 42, 0)] * n
recs.append(struct.pack('<Qq6QqQ', 0, 94, 0, 0, 0, 0, 0, 0, 0, 0))
with open(out, 'wb') as f:
    f.write(struct.pack('<8sQQQ', b'USPTRC01', len(recs), 0, 0))
    f.write(b''.join(recs))

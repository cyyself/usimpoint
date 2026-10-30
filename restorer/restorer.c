/*
 * usimpoint ELFie restorer (freestanding, no libc, position independent).
 *
 * Implements the "Restore contract" of docs/ckpt-format.md using the binary
 * descriptor of usp_desc.h that usp-mkelf appends right after this blob.
 *
 * Rules for this file: no initialized pointers in data (the blob is linked
 * at 0 and loaded anywhere), no libc, no vector instructions (the only
 * vector-unit access is reading the vlenb CSR, which also makes the kernel
 * enable V for this task; vector state is restored by the kernel from the
 * final rt_sigreturn frame).
 */
#include <stddef.h>
#include <stdint.h>
#include "usp_desc.h"

typedef unsigned long ul;

/* ---- riscv64 Linux (asm-generic) syscall numbers and constants ---- */
#define NR_dup3            24
#define NR_fcntl           25
#define NR_ftruncate       46
#define NR_openat          56
#define NR_close           57
#define NR_lseek           62
#define NR_write           64
#define NR_pread64         67
#define NR_exit_group      94
#define NR_set_tid_address 96
#define NR_rt_sigaction    134
#define NR_rt_sigprocmask  135
#define NR_umask           166
#define NR_prctl           167
#define NR_munmap          215
#define NR_execve          221
#define NR_mmap            222
#define NR_mprotect        226
#define NR_personality     92
#define NR_close_range     436
#define NR_sigaltstack     132
#define NR_seccomp         277
#define NR_mremap          216
#define NR_madvise         233
#define NR_exit            93
#define NR_brk             214
#define NR_getpid          172
#define NR_gettid          178
#define NR_tgkill          131

#define AT_FDCWD   (-100)
#define O_RDONLY   00
#define O_ACCMODE  03
#define O_WRONLY   01
#define O_CREAT    0100
#define O_EXCL     0200
#define O_TRUNC    01000
#define O_CLOEXEC  02000000
#define F_DUPFD    0
#define PROT_READ  1
#define PROT_WRITE 2
#define MADV_POPULATE_WRITE 23
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_GROWSDOWN 0x0100
#define SIG_SETMASK 2
#define SS_DISABLE  2
#define PR_SET_MM     35
#define PR_SET_MM_MAP 14
#define ADDR_NO_RANDOMIZE 0x0040000
#define PAGE_SIZE 4096UL

#define EXIT_FAIL 127

/* ---- kernel rt_sigframe layout for riscv64 (arch/riscv/kernel/signal.c) ----
 * struct rt_sigframe { struct siginfo info; struct ucontext uc; };
 * struct ucontext { uc_flags; uc_link; stack_t uc_stack; sigset_t uc_sigmask;
 *                   __u8 __unused[1024/8 - 8]; struct sigcontext uc_mcontext; }
 * struct sigcontext { user_regs_struct sc_regs; union { fp_state (q: 528 B,
 *                   aligned 16); __riscv_extra_ext_header sc_extdesc; }; }
 * The extension area (sc_extdesc.reserved = 0, then the first
 * struct __riscv_ctx_hdr) overlaps the tail of the q-ext fp state.  Headers
 * are chained: each {magic, size} is followed by size - 8 payload bytes, the
 * list ends with {END_MAGIC 0, size 0}.  Without vector state the first header
 * is END (all zero).  With it, the first header is RISCV_V_MAGIC, size
 * 8 + sizeof(struct __sc_riscv_v_state) + riscv_v_vsize (see vector_check),
 * and the payload
 * (struct __riscv_v_ext_state, then the register file that its datap points
 * at) lies right after the sigcontext, followed by the END header.
 */
#define RISCV_V_MAGIC 0x53465457u
struct k_sigcontext {
	uint64_t regs[32];          /* pc, ra, sp, ... */
	uint64_t f[32];             /* __riscv_d_ext_state.f */
	uint32_t fcsr;              /* __riscv_d_ext_state.fcsr */
	uint8_t rest[528 - 260 - 12]; /* q-ext tail / extdesc padding: zero */
	uint32_t ext_reserved;      /* sc_extdesc.reserved: must be 0 */
	uint32_t ext_magic;         /* sc_extdesc.hdr */
	uint32_t ext_size;
} __attribute__((aligned(16)));

struct k_ucontext {
	uint64_t uc_flags;
	uint64_t uc_link;
	uint64_t ss_sp;
	int32_t ss_flags;
	int32_t ss_pad;
	uint64_t ss_size;
	uint64_t uc_sigmask;
	uint8_t unused[1024 / 8 - 8];
	struct k_sigcontext uc_mcontext;
} __attribute__((aligned(16)));

struct k_rt_sigframe {
	uint8_t info[128];          /* siginfo_t */
	struct k_ucontext uc;
};

_Static_assert(offsetof(struct k_ucontext, uc_sigmask) == 40, "uc_sigmask");
_Static_assert(offsetof(struct k_ucontext, uc_mcontext) == 176, "uc_mcontext");
_Static_assert(sizeof(struct k_sigcontext) == 256 + 528, "sigcontext");
_Static_assert(offsetof(struct k_rt_sigframe, uc) == 128, "uc");
_Static_assert(sizeof(struct k_rt_sigframe) == 1088, "rt_sigframe");
_Static_assert(offsetof(struct k_sigcontext, ext_magic) == 256 + 520, "sc_extdesc.hdr");

/* struct __sc_riscv_v_state (= struct __riscv_v_ext_state) */
struct k_v_state {
	uint64_t vstart, vl, vtype, vcsr, vlenb;
	uint64_t datap;
};
#define USP_MAX_VLENB 256           /* VLEN 2048 */

/* The final rt_sigreturn frame: sigframe + room for the V extension. */
struct usp_frame {
	struct k_rt_sigframe f;
	struct k_v_state v;         /* right after uc_mcontext = end of sigframe */
	uint8_t vregs[32 * USP_MAX_VLENB];
	uint32_t end_hdr[2];        /* placed right after the used part of vregs */
} __attribute__((aligned(16)));
_Static_assert(offsetof(struct usp_frame, v) == sizeof(struct k_rt_sigframe), "v ext");

struct k_sigaction {            /* asm-generic, no SA_RESTORER on riscv */
	uint64_t handler, flags, mask;
};

struct prctl_mm_map {
	uint64_t start_code, end_code, start_data, end_data, start_brk, brk;
	uint64_t start_stack, arg_start, arg_end, env_start, env_end;
	uint64_t auxv;
	uint32_t auxv_size;
	uint32_t exe_fd;
};

/* ---- syscalls ---- */
static inline long sys6(long n, long a, long b, long c, long d, long e, long f)
{
	register long a0 __asm__("a0") = a;
	register long a1 __asm__("a1") = b;
	register long a2 __asm__("a2") = c;
	register long a3 __asm__("a3") = d;
	register long a4 __asm__("a4") = e;
	register long a5 __asm__("a5") = f;
	register long a7 __asm__("a7") = n;
	__asm__ volatile("ecall"
			 : "+r"(a0)
			 : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a7)
			 : "memory");
	return a0;
}
#define sys0(n) sys6(n, 0, 0, 0, 0, 0, 0)
#define sys1(n, a) sys6(n, (long)(a), 0, 0, 0, 0, 0)
#define sys2(n, a, b) sys6(n, (long)(a), (long)(b), 0, 0, 0, 0)
#define sys3(n, a, b, c) sys6(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define sys4(n, a, b, c, d) sys6(n, (long)(a), (long)(b), (long)(c), (long)(d), 0, 0)

extern void usp_sigreturn(void *frame) __attribute__((noreturn));

/* GCC may emit calls to these. */
void *memset(void *d, int c, size_t n)
{
	volatile unsigned char *p = d;
	while (n--)
		*p++ = (unsigned char)c;
	return d;
}
void *memcpy(void *d, const void *s, size_t n)
{
	volatile unsigned char *p = d;
	const unsigned char *q = s;
	if ((((ul)p | (ul)q) & 7) == 0) {
		while (n >= 8) {
			*(volatile uint64_t *)p = *(const uint64_t *)q;
			p += 8;
			q += 8;
			n -= 8;
		}
	}
	while (n--)
		*p++ = *q++;
	return d;
}

/* ---- tiny output helpers (stderr) ---- */
static size_t slen(const char *s)
{
	size_t n = 0;
	while (s[n])
		n++;
	return n;
}
static void puts2(const char *s) { sys3(NR_write, 2, s, slen(s)); }
static void puthex(uint64_t v)
{
	char b[19];
	int i;
	b[0] = '0';
	b[1] = 'x';
	for (i = 0; i < 16; i++) {
		unsigned d = (v >> (60 - 4 * i)) & 0xf;
		b[2 + i] = d < 10 ? '0' + d : 'a' + d - 10;
	}
	b[18] = 0;
	/* strip leading zeros */
	i = 2;
	while (i < 17 && b[i] == '0')
		i++;
	b[i - 1] = 'x';
	b[i - 2] = '0';
	puts2(b + i - 2);
}
static void putdec(long v)
{
	char b[24];
	int i = 23;
	int neg = v < 0;
	unsigned long u = neg ? -(unsigned long)v : (unsigned long)v;
	b[i] = 0;
	do {
		b[--i] = '0' + u % 10;
		u /= 10;
	} while (u);
	if (neg)
		b[--i] = '-';
	puts2(b + i);
}

static int verbose;
static int no_kvdso; /* debug: don't relocate the kernel vdso */

static void __attribute__((noreturn)) die(const char *what, long err, uint64_t arg)
{
	puts2("usp-restore: error: ");
	puts2(what);
	puts2(" (arg ");
	puthex(arg);
	puts2(", errno ");
	putdec(-err);
	puts2(")\n");
	sys1(NR_exit_group, EXIT_FAIL);
	for (;;)
		;
}

static void note(const char *what, uint64_t a, uint64_t b)
{
	if (!verbose)
		return;
	puts2("usp-restore: ");
	puts2(what);
	puts2(" ");
	puthex(a);
	puts2(" ");
	puthex(b);
	puts2("\n");
}

static int is_err(long r) { return (unsigned long)r >= (unsigned long)-4095; }

static int streq_prefix(const char *s, const char *pfx)
{
	while (*pfx)
		if (*s++ != *pfx++)
			return 0;
	return 1;
}

/* Read exactly len bytes at file offset off into dst (from the ELFie). */
static void pread_all(int fd, void *dst, uint64_t len, uint64_t off)
{
	char *p = dst;
	while (len) {
		long chunk = len > (1UL << 30) ? (1L << 30) : (long)len;
		long r = sys4(NR_pread64, fd, p, chunk, off);
		if (r == -4 /* EINTR */)
			continue;
		if (is_err(r) || r == 0)
			die("pread from ELFie", r, off);
		p += r;
		off += r;
		len -= r;
	}
}

static char copybuf[65536] __attribute__((aligned(16)));

static void write_all(int fd, const char *p, long n, uint64_t what)
{
	while (n > 0) {
		long r = sys3(NR_write, fd, p, n);
		if (r == -4)
			continue;
		if (is_err(r))
			die("write fd content", r, what);
		p += r;
		n -= r;
	}
}

static void restore_fds(struct usp_desc *d, int exefd)
{
	struct usp_fd *fds = (struct usp_fd *)((char *)d + d->fds_off);
	const char *strtab = (const char *)d + d->strtab_off;
	uint32_t i;

	for (i = 0; i < d->nfds; i++) {
		struct usp_fd *f = &fds[i];
		const char *path = strtab + f->path_off;
		uint32_t fl;
		int writable;
		long nfd, r;

		if (f->kind == USP_FD_INHERIT)
			continue;
		if (f->kind != USP_FD_FILE)
			die("unknown fd kind", -22, f->fd);
		writable = (f->flags & O_ACCMODE) != O_RDONLY;
		if (f->content_off != ~0ULL) {
			uint64_t left = f->content_len, off = f->content_off;
			long cfd = sys4(NR_openat, AT_FDCWD, path,
					O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
			if (is_err(cfd)) {
				puts2("usp-restore: cannot create ");
				puts2(path);
				puts2("\n");
				die("open for content restore", cfd, f->fd);
			}
			while (left) {
				uint64_t n = left > sizeof(copybuf) ? sizeof(copybuf) : left;
				pread_all(exefd, copybuf, n, off);
				write_all(cfd, copybuf, (long)n, f->fd);
				left -= n;
				off += n;
			}
			sys1(NR_close, cfd);
		}
		fl = f->flags & ~(O_CREAT | O_TRUNC | O_EXCL);
		if (writable)
			fl |= O_CREAT;
		nfd = sys4(NR_openat, AT_FDCWD, path, fl, f->mode ? f->mode : 0644);
		if (is_err(nfd)) {
			puts2("usp-restore: cannot open ");
			puts2(path);
			puts2("\n");
			die("open fd", nfd, f->fd);
		}
		if (nfd != f->fd) {
			r = sys3(NR_dup3, nfd, f->fd, f->flags & O_CLOEXEC);
			if (is_err(r))
				die("dup3", r, f->fd);
			sys1(NR_close, nfd);
		}
		/* No content but captured with O_TRUNC: file length was == offset
		 * unless it was written past and seeked back; best effort. */
		if (writable && f->content_off == ~0ULL && (f->flags & O_TRUNC)) {
			r = sys2(NR_ftruncate, f->fd, f->offset);
			if (is_err(r))
				die("ftruncate", r, f->fd);
		}
		r = sys3(NR_lseek, f->fd, f->offset, 0 /* SEEK_SET */);
		if (is_err(r) && r != -29 /* ESPIPE */)
			die("lseek", r, f->fd);
		note("fd", f->fd, f->offset);
	}
}

static void map_regions(struct usp_desc *d, int exefd)
{
	struct usp_region *rg = (struct usp_region *)((char *)d + d->regions_off);
	struct usp_run *runs = (struct usp_run *)((char *)d + d->runs_off);
	uint32_t i, j;

	for (i = 0; i < d->nregions; i++) {
		struct usp_region *r = &rg[i];
		uint64_t len = r->end - r->start;
		int eager = (d->flags & USP_F_EAGER) || (r->flags & USP_R_STACK);
		long flags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
		long p;

		if (r->flags & USP_R_STACK)
			flags |= MAP_GROWSDOWN;
		p = sys6(NR_mmap, r->start, len, PROT_READ | PROT_WRITE, flags, -1, 0);
		if (is_err(p) || (uint64_t)p != r->start)
			die("mmap region", p, r->start);
		/* Zero pages aren't in the image, but the original process had real
		 * pages there: back them now, or reads would all hit the shared zero
		 * page (always cached) and memory-bound code would run too fast. */
		if (eager && (r->prot & PROT_WRITE) && !(r->flags & USP_R_STACK))
			sys3(NR_madvise, r->start, len, MADV_POPULATE_WRITE);
		for (j = r->first_run; j < r->first_run + r->nruns; j++) {
			struct usp_run *u = &runs[j];
			uint64_t ulen = u->npages * PAGE_SIZE;
			if (u->vaddr < r->start || u->vaddr + ulen > r->end)
				die("run outside region", -22, u->vaddr);
			if (eager) {
				pread_all(exefd, (void *)u->vaddr, ulen, u->file_off);
			} else {
				p = sys6(NR_mmap, u->vaddr, ulen, PROT_READ | PROT_WRITE,
					 MAP_FIXED | MAP_PRIVATE, exefd, u->file_off);
				if (is_err(p) || (uint64_t)p != u->vaddr)
					die("mmap run", p, u->vaddr);
			}
		}
		if (r->prot != (PROT_READ | PROT_WRITE)) {
			p = sys3(NR_mprotect, r->start, len, r->prot);
			if (is_err(p))
				die("mprotect", p, r->start);
		}
		note("region", r->start, r->end);
	}
}

/* Move the kernel's own [vvar*]/[vdso] mappings into the reserved slot (the
 * vdso .mremap hook updates mm->context.vdso, which the kernel uses as the
 * signal-return trampoline).  Returns 0 on success, -1 if not possible (the
 * caller then just unmaps them with everything else). */
/* a few lines at restore time; sized so restorer changes still fit old ELFies */
static char mapsbuf[16384 - 64];

static uint64_t parse_hex(const char **pp)
{
	const char *p = *pp;
	uint64_t v = 0;
	for (;; p++) {
		char c = *p;
		if (c >= '0' && c <= '9')
			v = v * 16 + (c - '0');
		else if (c >= 'a' && c <= 'f')
			v = v * 16 + (c - 'a' + 10);
		else
			break;
	}
	*pp = p;
	return v;
}

static int relocate_kvdso(struct usp_desc *d)
{
	uint64_t st[8], en[8], lo = ~0ULL, hi = 0;
	int n = 0, i;
	long fd, len = 0, r;
	const char *p, *end;

	if (!d->kvdso_size)
		return -1;
	fd = sys4(NR_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
	if (is_err(fd))
		return -1;
	while (len < (long)sizeof(mapsbuf) - 1) {
		r = sys3(63 /* read */, fd, mapsbuf + len, sizeof(mapsbuf) - 1 - len);
		if (r <= 0)
			break;
		len += r;
	}
	sys1(NR_close, fd);
	mapsbuf[len] = 0;
	for (p = mapsbuf, end = mapsbuf + len; p < end;) {
		const char *eol = p, *q;
		uint64_t s0, e0;
		while (eol < end && *eol != '\n')
			eol++;
		q = p;
		s0 = parse_hex(&q);
		q++; /* '-' */
		e0 = parse_hex(&q);
		/* name = last field */
		for (q = eol; q > p && q[-1] != ' '; q--)
			;
		if (streq_prefix(q, "[vvar") || streq_prefix(q, "[vdso]")) {
			if (n == 8)
				return -1;
			st[n] = s0;
			en[n] = e0;
			n++;
			if (s0 < lo)
				lo = s0;
			if (e0 > hi)
				hi = e0;
		}
		p = eol + 1;
	}
	if (!n || hi - lo > d->kvdso_size)
		return -1;
	for (i = 0; i < n; i++) {
		uint64_t dst = d->kvdso_va + (st[i] - lo);
		r = sys6(NR_mremap, st[i], en[i] - st[i], en[i] - st[i],
			 1 /* MAYMOVE */ | 2 /* FIXED */, dst, 0);
		if ((uint64_t)r != dst) {
			puts2("usp-restore: warning: mremap of kernel vdso/vvar failed (");
			putdec(r);
			puts2("); signal handlers cannot return\n");
			return -1;
		}
	}
	note("kernel vdso/vvar moved to", d->kvdso_va, hi - lo);
	return 0;
}

static void unmap_others(uint64_t lo, uint64_t hi)
{
	static const unsigned char tops[] = {56, 47, 38};
	long r;
	unsigned i;

	if (lo) {
		r = sys2(NR_munmap, 0, lo);
		if (is_err(r))
			die("munmap below restorer", r, lo);
	}
	for (i = 0; i < sizeof(tops); i++) {
		uint64_t top = 1ULL << tops[i];
		if (top <= hi)
			continue;
		r = sys2(NR_munmap, hi, top - hi);
		if (!is_err(r)) {
			note("unmapped up to", top, 0);
			return;
		}
	}
	die("munmap above restorer (task size probe failed)", r, hi);
}

/* ======================= replay mode =======================
 * Every syscall issued outside the restorer mapping traps (seccomp
 * SECCOMP_RET_TRAP -> SIGSYS) into usp_sigsys(), which answers it from the
 * syscalls.bin trace (docs/ckpt-format.md, "syscalls.bin").  The handler runs
 * on an alternate stack inside the restorer mapping and returns with its own
 * rt_sigreturn (the kernel's vDSO trampoline is gone after the restore).
 */
#define TRACE_EXIT_CODE 126
#define AUDIT_ARCH_RISCV64 0xc00000f3u
#define SA_SIGINFO 4
#define SA_ONSTACK 0x08000000
#define SIGSYS 31
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define PR_SET_NO_NEW_PRIVS 38
#define SECCOMP_SET_MODE_FILTER 1

struct trace_hdr {
	char magic[8];
	uint64_t count, start_icount, window;
};
struct trace_rec {
	uint64_t icount_rel;
	int64_t num;
	uint64_t args[6];
	int64_t ret;
	uint64_t nwrites;
};

static struct {
	const uint8_t *cur;      /* next record */
	const uint8_t *end;
	uint64_t left;           /* records left */
	uint64_t done;           /* records replayed */
	uint64_t brk;            /* emulated program break */
	int verbose;
} rp;

static char altstack[32768] __attribute__((aligned(16)));

static void __attribute__((noreturn)) replay_fail(const char *what, uint64_t a, uint64_t b)
{
	puts2("usp-replay: ");
	puts2(what);
	puts2(" (syscall #");
	putdec((long)rp.done);
	puts2(": ");
	puthex(a);
	puts2(" ");
	puthex(b);
	puts2(")\n");
	sys1(NR_exit_group, TRACE_EXIT_CODE);
	for (;;)
		;
}

static uint64_t pgup(uint64_t v) { return (v + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1); }

/* Apply the record's writes; returns pointer past them. */
static const uint8_t *apply_writes(const uint8_t *p, uint64_t n)
{
	while (n--) {
		uint64_t addr = ((const uint64_t *)p)[0];
		uint64_t len = ((const uint64_t *)p)[1];
		p += 16;
		if (p + len > rp.end)
			replay_fail("trace truncated in writes", addr, len);
		memcpy((void *)addr, p, len);
		p += (len + 7) & ~7ULL;
	}
	return p;
}

void usp_sigsys(int sig, void *info, struct k_ucontext *uc)
{
	uint64_t *g = uc->uc_mcontext.regs; /* pc ra sp gp tp t0 t1 t2 s0 s1 a0.. */
	uint64_t *a = &g[10];
	const struct trace_rec *r;
	const uint8_t *w;
	uint64_t nr = g[17]; /* a7 */
	long ret;
	int i;

	/* seccomp RET_TRAP: epc was already advanced past the 4-byte ecall
	 * (do_trap_ecall_u does epc += 4 before seccomp) and a0 rolled back to
	 * the original argument.  Be defensive if pc still points at ecall. */
	if (*(const uint32_t *)(g[0] - 4) != 0x00000073 && *(const uint32_t *)g[0] == 0x00000073)
		g[0] += 4;

	/* riscv_flush_icache: handled by QEMU's cpu loop, never in the trace;
	 * cache maintenance, so execute it for real without consuming a record */
	if (nr == 259) {
		a[0] = (uint64_t)sys3(259, a[0], a[1], a[2]);
		usp_sigreturn((char *)uc - offsetof(struct k_rt_sigframe, uc));
	}

	if (!rp.left) {
		puts2("usp-replay: trace exhausted after ");
		putdec((long)rp.done);
		puts2(" syscalls; next syscall ");
		putdec((long)nr);
		puts2(" at pc ");
		puthex(g[0] - 4);
		puts2("\n");
		sys1(NR_exit_group, TRACE_EXIT_CODE);
	}
	r = (const struct trace_rec *)rp.cur;
	if ((const uint8_t *)(r + 1) > rp.end)
		replay_fail("trace truncated", 0, 0);
	if ((uint64_t)r->num != nr)
		replay_fail("divergence: syscall number (expected, got)", (uint64_t)r->num, nr);
	/* exit/exit_group only use a0; the other registers are leftovers */
	for (i = 0; i < (nr == NR_exit || nr == NR_exit_group ? 1 : 6); i++)
		if (r->args[i] != a[i]) {
			puts2("usp-replay: arg ");
			putdec(i);
			puts2(" of syscall ");
			putdec((long)nr);
			puts2("\n");
			replay_fail("divergence: argument (expected, got)", r->args[i], a[i]);
		}
	w = rp.cur + sizeof(*r);
	ret = r->ret;

	switch (nr) {
	case NR_exit:
	case NR_exit_group:
		if (rp.verbose) {
			puts2("usp-replay: program exits after ");
			putdec((long)rp.done);
			puts2(" replayed syscalls\n");
		}
		sys1(nr, a[0]);
		break;
	case NR_mmap:
		if (!is_err(ret)) {
			long p = sys6(NR_mmap, ret, a[1], PROT_READ | PROT_WRITE,
				      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (p != ret)
				replay_fail("replayed mmap failed", ret, p);
		}
		w = apply_writes(w, r->nwrites);
		if (!is_err(ret) && a[2] != (PROT_READ | PROT_WRITE)) {
			long p = sys3(NR_mprotect, ret, a[1], a[2]);
			if (is_err(p))
				replay_fail("replayed mmap mprotect failed", ret, p);
		}
		break;
	case NR_munmap:
	case NR_mprotect:
	case NR_madvise:
		if (!is_err(ret)) {
			long p = sys3(nr, a[0], a[1], a[2]);
			if (p != ret)
				replay_fail("replayed munmap/mprotect/madvise result differs", ret, p);
		}
		w = apply_writes(w, r->nwrites);
		break;
	case NR_mremap:
		if (!is_err(ret)) {
			long p;
			if ((uint64_t)ret == a[0])
				p = sys4(NR_mremap, a[0], a[1], a[2], 0);
			else
				p = sys6(NR_mremap, a[0], a[1], a[2],
					 MREMAP_MAYMOVE | MREMAP_FIXED, ret, 0);
			if (p != ret)
				replay_fail("replayed mremap failed", ret, p);
		}
		w = apply_writes(w, r->nwrites);
		break;
	case NR_brk: {
		uint64_t nb = (uint64_t)ret, ob = rp.brk;
		if (!ob) {
			/* checkpoint taken before the first brk(): adopt the break */
		} else if (pgup(nb) > pgup(ob)) {
			long p = sys6(NR_mmap, pgup(ob), pgup(nb) - pgup(ob), PROT_READ | PROT_WRITE,
				      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if ((uint64_t)p != pgup(ob))
				replay_fail("brk grow failed", nb, p);
		} else if (pgup(nb) < pgup(ob)) {
			long p = sys2(NR_munmap, pgup(nb), pgup(ob) - pgup(nb));
			if (is_err(p))
				replay_fail("brk shrink failed", nb, p);
		}
		rp.brk = nb;
		w = apply_writes(w, r->nwrites);
		break;
	}
	default:
		w = apply_writes(w, r->nwrites);
		break;
	}
	a[0] = (uint64_t)ret;
	rp.cur = w;
	rp.left--;
	rp.done++;
	usp_sigreturn((char *)uc - offsetof(struct k_rt_sigframe, uc));
}

struct sock_filter {
	uint16_t code;
	uint8_t jt, jf;
	uint32_t k;
};
struct sock_fprog {
	uint16_t len;
	struct sock_filter *filter;
};

static void replay_setup(struct usp_desc *d, int exefd, int verbose_flag)
{
	const struct trace_hdr *h;
	struct k_sigaction ka;
	long r;
	struct {
		uint64_t ss_sp;
		int32_t ss_flags, pad;
		uint64_t ss_size;
	} ss;
	struct sock_filter f[9];
	struct sock_fprog prog;
	uint32_t lo = (uint32_t)d->seccomp_lo, hi_lo = (uint32_t)d->seccomp_hi;
	uint32_t hiword = (uint32_t)(d->seccomp_lo >> 32);

	r = sys6(NR_mmap, d->trace_va, pgup(d->trace_size), PROT_READ, MAP_FIXED | MAP_PRIVATE,
		 exefd, d->trace_file_off);
	if ((uint64_t)r != d->trace_va)
		die("mmap trace", r, d->trace_va);
	h = (const struct trace_hdr *)d->trace_va;
	if (!streq_prefix(h->magic, "USPTRC01"))
		die("bad syscalls.bin magic", -22, 0);
	rp.cur = (const uint8_t *)(h + 1);
	rp.end = (const uint8_t *)d->trace_va + d->trace_size;
	rp.left = h->count;
	rp.done = 0;
	rp.brk = d->replay_brk;
	rp.verbose = verbose_flag;
	note("replay trace records", h->count, h->window);

	ss.ss_sp = (uint64_t)altstack;
	ss.ss_flags = 0;
	ss.pad = 0;
	ss.ss_size = sizeof(altstack);
	r = sys2(NR_sigaltstack, &ss, 0);
	if (is_err(r))
		die("sigaltstack", r, 0);
	ka.handler = (uint64_t)usp_sigsys;
	ka.flags = SA_SIGINFO | SA_ONSTACK;
	ka.mask = ~0ULL;
	r = sys4(NR_rt_sigaction, SIGSYS, &ka, 0, 8);
	if (is_err(r))
		die("rt_sigaction(SIGSYS)", r, 0);

	if ((d->seccomp_hi - 1) >> 32 != hiword || hi_lo == 0)
		die("seccomp range crosses a 4 GiB boundary", -22, d->seccomp_lo);
#define BPF_LD_W_ABS 0x20
#define BPF_JEQ_K 0x15
#define BPF_JGE_K 0x35
#define BPF_RET_K 0x06
	f[0] = (struct sock_filter){BPF_LD_W_ABS, 0, 0, 4};          /* arch */
	f[1] = (struct sock_filter){BPF_JEQ_K, 0, 6, AUDIT_ARCH_RISCV64};
	f[2] = (struct sock_filter){BPF_LD_W_ABS, 0, 0, 12};         /* ip >> 32 */
	f[3] = (struct sock_filter){BPF_JEQ_K, 0, 4, hiword};
	f[4] = (struct sock_filter){BPF_LD_W_ABS, 0, 0, 8};          /* ip & 0xffffffff */
	f[5] = (struct sock_filter){BPF_JGE_K, 0, 2, lo};
	f[6] = (struct sock_filter){BPF_JGE_K, 1, 0, hi_lo};
	f[7] = (struct sock_filter){BPF_RET_K, 0, 0, 0x7fff0000};    /* ALLOW */
	f[8] = (struct sock_filter){BPF_RET_K, 0, 0, 0x00030000};    /* TRAP */
	prog.len = 9;
	prog.filter = f;
	r = sys6(NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0);
	if (is_err(r))
		die("PR_SET_NO_NEW_PRIVS", r, 0);
	r = sys3(NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
	if (is_err(r))
		die("seccomp(SET_MODE_FILTER)", r, 0);
}

/* Vector unit: the image's VLEN must match the hardware's.  Reading vlenb is
 * the first vector-unit access of this task, so the kernel turns V on (first
 * use trap); rt_sigreturn only accepts a V frame for a task with V on.
 *
 * rt_sigreturn also insists that the V header size equals the kernel's
 * riscv_v_sc_size exactly, and that is not 8 + 48 + 32 * vlenb in general:
 * riscv_v_vsize is sized for the largest VLEN of all harts (on the K3 the
 * A100 AI cores, harts 8-15, have VLEN 1024: 4096 bytes although the X100 cores
 * have vlenb 32).  The kernel restores registers packed with the running
 * hart's vlenb from the start of that area.  Learn the size from a frame the
 * kernel builds: send ourselves one signal. */
#define AT_HWCAP 16
#define HWCAP_V (1UL << ('V' - 'A'))
#define SIGUSR1 10
static uint32_t v_ext_size;

void usp_vprobe(int sig, void *info, struct k_ucontext *uc)
{
	if (uc->uc_mcontext.ext_magic == RISCV_V_MAGIC)
		v_ext_size = uc->uc_mcontext.ext_size;
	usp_sigreturn((char *)uc - offsetof(struct k_rt_sigframe, uc));
}

static void vector_check(struct usp_desc *d, char **envp)
{
	ul *av, hwcap = 0, vlenb;
	struct k_sigaction ka;
	uint64_t mask, old;
	long r;

	if (!(d->flags & USP_F_VECTOR))
		return;
	for (av = (ul *)envp; *av; av++)
		;
	for (av++; av[0]; av += 2)
		if (av[0] == AT_HWCAP)
			hwcap = av[1];
	if (!(hwcap & HWCAP_V))
		die("image has vector state but the CPU/kernel has no V", -22, hwcap);
	asm volatile("csrr %0, 0xc22" : "=r"(vlenb)); /* vlenb */
	if (vlenb != d->vlenb)
		die("VLEN mismatch (image vlenb, cpu vlenb)", d->vlenb, vlenb);
	if (d->vlenb > USP_MAX_VLENB)
		die("vlenb too large", -22, d->vlenb);

	ka.handler = (uint64_t)usp_vprobe;
	ka.flags = SA_SIGINFO;
	ka.mask = ~0ULL;
	r = sys4(NR_rt_sigaction, SIGUSR1, &ka, 0, 8);
	if (is_err(r))
		die("rt_sigaction(probe)", r, 0);
	mask = ~(1ULL << (SIGUSR1 - 1));
	sys4(NR_rt_sigprocmask, SIG_SETMASK, &mask, &old, 8);
	sys3(NR_tgkill, sys0(NR_getpid), sys0(NR_gettid), SIGUSR1);
	sys4(NR_rt_sigprocmask, SIG_SETMASK, &old, 0, 8);
	ka.handler = 0; /* SIG_DFL */
	ka.flags = 0;
	ka.mask = 0;
	sys4(NR_rt_sigaction, SIGUSR1, &ka, 0, 8);
	if (v_ext_size < 8 + sizeof(struct k_v_state) + 32 * vlenb ||
	    v_ext_size > 8 + sizeof(struct k_v_state) + 32 * USP_MAX_VLENB)
		die("unexpected kernel V signal context size", v_ext_size, vlenb);
	note("vector: vlenb, kernel V context size", vlenb, v_ext_size);
}

/* Fill the final rt_sigreturn frame: gpr/fpr/fcsr and, if present, the
 * vector state as a RISCV_V_MAGIC extension (the kernel restores vl/vtype
 * with vsetvl, so vill and any vl <= VLMAX come back exactly). */
static struct k_rt_sigframe *build_frame(struct usp_desc *d)
{
	static struct usp_frame frame; /* bss: zero, so the ext area is END */
	struct k_rt_sigframe *fr = &frame.f;
	uint32_t i;

	for (i = 0; i < 32; i++) {
		fr->uc.uc_mcontext.regs[i] = d->gpr[i];
		fr->uc.uc_mcontext.f[i] = d->fpr[i];
	}
	fr->uc.uc_mcontext.fcsr = (uint32_t)d->fcsr;
	fr->uc.uc_sigmask = d->sigmask;
	if (d->flags & USP_F_VECTOR) {
		uint64_t n = 32 * d->vlenb;
		uint32_t *end = (uint32_t *)((char *)&frame.v + v_ext_size - 8);
		fr->uc.uc_mcontext.ext_magic = RISCV_V_MAGIC;
		fr->uc.uc_mcontext.ext_size = v_ext_size;
		frame.v.vstart = d->vstart;
		frame.v.vl = d->vl;
		frame.v.vtype = d->vtype;
		frame.v.vcsr = d->vcsr;
		frame.v.vlenb = d->vlenb;
		frame.v.datap = (uint64_t)frame.vregs;
		memcpy(frame.vregs, (char *)d + d->vregs_off, n);
		end[0] = 0; /* END_MAGIC */
		end[1] = 0;
	}
	return fr;
}

void usp_main(struct usp_desc *d, ul *isp, ul base)
{
	ul argc = isp[0];
	char **argv = (char **)&isp[1];
	char **envp = argv + argc + 1;
	char **e;
	uint64_t hi;
	long r, exefd;
	int scratch;
	uint32_t i;
	static uint64_t allsigs = ~0ULL;
	struct k_rt_sigframe *fr;

	for (e = envp; *e; e++)
		if (streq_prefix(*e, "USP_VERBOSE=1"))
			verbose = 1;
		else if (streq_prefix(*e, "USP_NO_KVDSO=1"))
			no_kvdso = 1;

	if (d->magic != USP_DESC_MAGIC || d->version != USP_DESC_VERSION)
		die("bad descriptor magic/version", -22, d->magic);
	if (d->base != base)
		die("loaded at unexpected base", -22, base);

	/* Captures assume a non-randomized layout (future mmap placement). */
	if (!(d->flags & USP_F_NO_REEXEC)) {
		long pers = sys1(NR_personality, 0xffffffffUL);
		if (!is_err(pers) && !(pers & ADDR_NO_RANDOMIZE)) {
			if (!is_err(sys1(NR_personality, pers | ADDR_NO_RANDOMIZE))) {
				r = sys3(NR_execve, "/proc/self/exe", argv, envp);
				puts2("usp-restore: warning: re-exec with ADDR_NO_RANDOMIZE failed (");
				putdec(r);
				puts2("), continuing\n");
			}
		}
	}

	vector_check(d, envp);

	r = sys4(NR_rt_sigprocmask, SIG_SETMASK, &allsigs, 0, 8);
	if (is_err(r))
		die("rt_sigprocmask", r, 0);

	/* Close inherited fds >= 3, then open ourselves at a scratch fd number
	 * that no restored fd uses. */
	r = sys3(NR_close_range, 3, ~0U, 0);
	if (is_err(r))
		die("close_range", r, 3);
	exefd = sys4(NR_openat, AT_FDCWD, "/proc/self/exe", O_RDONLY | O_CLOEXEC, 0);
	if (is_err(exefd))
		die("open /proc/self/exe", exefd, 0);
	{
		struct usp_fd *fds = (struct usp_fd *)((char *)d + d->fds_off);
		int used;
		scratch = 1000;
		do {
			used = 0;
			for (i = 0; i < d->nfds; i++)
				if (fds[i].fd == scratch)
					used = 1;
			if (used)
				scratch--;
		} while (used);
		r = sys3(NR_fcntl, exefd, F_DUPFD, scratch);
		if (is_err(r))
			die("fcntl F_DUPFD", r, scratch);
		sys1(NR_close, exefd);
		exefd = r;
		for (i = 0; i < d->nfds; i++)
			if (fds[i].fd == exefd)
				die("scratch fd collides with restored fd", -22, exefd);
	}

	/* Address space. */
	hi = (base + d->seg_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	if (d->kvdso_size) /* keep [base, end of kernel-vdso slot) */
		hi = d->kvdso_va + d->kvdso_size;
	if (!no_kvdso)
		relocate_kvdso(d);
	unmap_others(base, hi);
	map_regions(d, exefd);

	if (d->flags & USP_F_REPLAY) {
		replay_setup(d, exefd, verbose);
		sys1(NR_close, exefd);
		fr = build_frame(d);
		/* keep our SIGSYS altstack across the final rt_sigreturn */
		fr->uc.ss_sp = (uint64_t)altstack;
		fr->uc.ss_flags = 0;
		fr->uc.ss_size = sizeof(altstack);
		note("replay: jump to pc", d->gpr[0], d->gpr[2]);
		usp_sigreturn(fr);
	}

	if (d->flags & USP_F_HAVE_MM) {
		struct prctl_mm_map m;
		m.start_code = d->mm[0];
		m.end_code = d->mm[1];
		m.start_data = d->mm[2];
		m.end_data = d->mm[3];
		m.start_brk = d->mm[4];
		m.brk = d->mm[5];
		m.start_stack = d->mm[6];
		m.arg_start = d->mm[7];
		m.arg_end = d->mm[8];
		m.env_start = d->mm[9];
		m.env_end = d->mm[10];
		m.auxv = 0;
		m.auxv_size = 0;
		m.exe_fd = (uint32_t)-1;
		r = sys6(NR_prctl, PR_SET_MM, PR_SET_MM_MAP, (long)&m, sizeof(m), 0, 0);
		if (is_err(r)) {
			puts2("usp-restore: warning: prctl(PR_SET_MM_MAP) failed (errno ");
			putdec(-r);
			puts2("); brk() will misbehave (kernel break is not the image's)\n");
		} else {
			note("brk", m.start_brk, m.brk);
		}
	}

	restore_fds(d, exefd);

	sys1(NR_umask, d->umask);
	sys1(NR_set_tid_address, d->tid_address);
	{
		struct usp_sig *s = (struct usp_sig *)((char *)d + d->sigs_off);
		for (i = 0; i < d->nsigs; i++) {
			struct k_sigaction ka;
			ka.handler = s[i].handler;
			ka.flags = s[i].flags;
			ka.mask = s[i].mask;
			r = sys4(NR_rt_sigaction, s[i].sig, &ka, 0, 8);
			if (is_err(r))
				die("rt_sigaction", r, s[i].sig);
		}
	}
	sys1(NR_close, exefd);

	/* Final switch: rt_sigreturn on a crafted frame. */
	fr = build_frame(d);
	fr->uc.ss_flags = SS_DISABLE;
	note("jump to pc", d->gpr[0], d->gpr[2]);
	usp_sigreturn(fr);
}

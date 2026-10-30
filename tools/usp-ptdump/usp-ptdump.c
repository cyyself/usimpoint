/*
 * usp-ptdump: TEST-ONLY native checkpoint producer for riscv64 Linux (ptrace).
 *
 *   usp-ptdump -o CKPTDIR (-t SECONDS | -n INSNS) [-v] -- prog args...
 *
 * Runs prog (ASLR off, vector disabled for the exec'd image), stops it after
 * SECONDS of wall time (or after ~INSNS user instructions, via a perf
 * counter polled at 1 ms), and writes a checkpoint in the
 * docs/ckpt-format.md format with "source": "ptrace".  The child is killed
 * afterwards.  With neither -t nor -n, -t 1 is used.
 *
 * Kernel state that ptrace cannot read directly (exact brk, signal handlers)
 * is obtained by injecting brk(0) / rt_sigaction(sig, NULL, &old) syscalls
 * into the stopped tracee.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <asm/ptrace.h>

#ifndef PR_RISCV_V_SET_CONTROL
#define PR_RISCV_V_SET_CONTROL 69
#define PR_RISCV_V_VSTATE_CTRL_OFF 1
#endif

#define PAGE 4096UL

static int verbose;

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "usp-ptdump: error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ---------------- registers ---------------- */
struct fpregs {
	uint64_t f[32];
	uint32_t fcsr;
};

static void get_regs(pid_t pid, struct user_regs_struct *r)
{
	struct iovec iov = {r, sizeof(*r)};
	if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov))
		die("GETREGSET NT_PRSTATUS: %s", strerror(errno));
}
static void set_regs(pid_t pid, struct user_regs_struct *r)
{
	struct iovec iov = {r, sizeof(*r)};
	if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov))
		die("SETREGSET NT_PRSTATUS: %s", strerror(errno));
}
static void get_fpregs(pid_t pid, struct fpregs *f)
{
	struct iovec iov = {f, sizeof(*f)};
	memset(f, 0, sizeof(*f));
	if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRFPREG, &iov))
		die("GETREGSET NT_PRFPREG: %s", strerror(errno));
}

/* ---------------- syscall injection ---------------- */
static int mem_fd = -1;

static void mem_rw(int write, uint64_t addr, void *buf, size_t len)
{
	ssize_t r = write ? pwrite(mem_fd, buf, len, addr) : pread(mem_fd, buf, len, addr);
	if (r != (ssize_t)len)
		die("%s tracee memory at 0x%llx: %s", write ? "write" : "read",
		    (unsigned long long)addr, strerror(errno));
}

static void wait_stop(pid_t pid, int *status)
{
	if (waitpid(pid, status, __WALL) != pid)
		die("waitpid: %s", strerror(errno));
	if (!WIFSTOPPED(*status))
		die("tracee died (status 0x%x)", *status);
}

/* Execute one syscall in the stopped tracee; returns its a0. Registers and
 * the instruction word at pc are restored afterwards. */
static long inject(pid_t pid, long nr, long a0, long a1, long a2, long a3)
{
	struct user_regs_struct saved, r;
	uint32_t ins_saved, ecall = 0x00000073;
	int st;

	get_regs(pid, &saved);
	r = saved;
	mem_rw(0, saved.pc, &ins_saved, 4);
	mem_rw(1, saved.pc, &ecall, 4);
	r.a7 = nr;
	r.a0 = a0;
	r.a1 = a1;
	r.a2 = a2;
	r.a3 = a3;
	set_regs(pid, &r);
	for (int phase = 0; phase < 2; phase++) {
		if (ptrace(PTRACE_SYSCALL, pid, 0, 0))
			die("PTRACE_SYSCALL: %s", strerror(errno));
		for (;;) {
			wait_stop(pid, &st);
			if (WSTOPSIG(st) == (SIGTRAP | 0x80))
				break;
			/* some other signal: suppress and keep going */
			if (ptrace(PTRACE_SYSCALL, pid, 0, 0))
				die("PTRACE_SYSCALL: %s", strerror(errno));
		}
	}
	get_regs(pid, &r);
	mem_rw(1, saved.pc, &ins_saved, 4);
	set_regs(pid, &saved);
	return (long)r.a0;
}

/* ---------------- /proc helpers ---------------- */
static char *slurp(const char *path)
{
	FILE *f = fopen(path, "r");
	char *buf = NULL;
	size_t cap = 0, len = 0, n;
	if (!f)
		die("open %s: %s", path, strerror(errno));
	for (;;) {
		if (len + 4096 + 1 > cap) {
			cap = cap * 2 + 8192;
			buf = realloc(buf, cap);
		}
		n = fread(buf + len, 1, 4096, f);
		if (!n)
			break;
		len += n;
	}
	buf[len] = 0;
	fclose(f);
	return buf;
}

static uint64_t status_hex(const char *status, const char *key)
{
	const char *p = strstr(status, key);
	if (!p)
		die("no %s in /proc/pid/status", key);
	return strtoull(p + strlen(key), NULL, 16);
}

/* ---------------- memory ---------------- */
struct run {
	uint64_t vaddr, npages, file_off;
};
struct region {
	uint64_t start, end;
	char prot[4];
	char name[16];
	struct run *runs;
	int nruns;
};

static int all_zero(const unsigned char *p, size_t n)
{
	const uint64_t *q = (const uint64_t *)p;
	for (size_t i = 0; i < n / 8; i++)
		if (q[i])
			return 0;
	return 1;
}

static uint64_t mem_bin_off;

static void dump_region(struct region *rg, FILE *mem_bin, int readable)
{
	static unsigned char buf[1 << 20];
	uint64_t a = rg->start;
	int cap = 0;
	struct run *cur = NULL;

	while (a < rg->end) {
		size_t n = rg->end - a < sizeof(buf) ? rg->end - a : sizeof(buf);
		ssize_t got = readable ? pread(mem_fd, buf, n, a) : -1;
		if (got < 0)
			got = 0; /* unreadable: treat as zero */
		if ((size_t)got < n)
			memset(buf + got, 0, n - got);
		for (size_t o = 0; o < n; o += PAGE) {
			if (all_zero(buf + o, PAGE)) {
				cur = NULL;
				continue;
			}
			if (!cur || cur->vaddr + cur->npages * PAGE != a + o) {
				if (rg->nruns == cap) {
					cap = cap * 2 + 8;
					rg->runs = realloc(rg->runs, cap * sizeof(*rg->runs));
				}
				cur = &rg->runs[rg->nruns++];
				cur->vaddr = a + o;
				cur->npages = 0;
				cur->file_off = mem_bin_off;
			}
			if (fwrite(buf + o, PAGE, 1, mem_bin) != 1)
				die("write mem.bin: %s", strerror(errno));
			cur->npages++;
			mem_bin_off += PAGE;
		}
		a += n;
	}
}

/* ---------------- main ---------------- */
static void usage(void)
{
	fprintf(stderr, "usage: usp-ptdump -o CKPTDIR [-t SECONDS | -n INSNS] [-v] -- prog args...\n");
	exit(2);
}

static long perf_open(pid_t pid)
{
	struct perf_event_attr pa;
	memset(&pa, 0, sizeof(pa));
	pa.size = sizeof(pa);
	pa.type = PERF_TYPE_HARDWARE;
	pa.config = PERF_COUNT_HW_INSTRUCTIONS;
	pa.exclude_kernel = 1;
	pa.exclude_hv = 1;
	return syscall(SYS_perf_event_open, &pa, pid, -1, -1, 0);
}

int main(int argc, char **argv)
{
	const char *out = NULL;
	double secs = -1;
	uint64_t insns = 0;
	int opt, st;
	pid_t pid;
	char path[PATH_MAX], cwd[PATH_MAX];

	while ((opt = getopt(argc, argv, "+o:t:n:v")) != -1) {
		switch (opt) {
		case 'o': out = optarg; break;
		case 't': secs = atof(optarg); break;
		case 'n': insns = strtoull(optarg, NULL, 0); break;
		case 'v': verbose = 1; break;
		default: usage();
		}
	}
	if (!out || optind >= argc)
		usage();
	if (secs < 0 && !insns)
		secs = 1;
	if (!getcwd(cwd, sizeof(cwd)))
		die("getcwd");

	pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		if (personality(ADDR_NO_RANDOMIZE) < 0)
			perror("usp-ptdump: personality");
		/* next exec: vector OFF (cur unchanged) so glibc ifuncs avoid V */
		if (prctl(PR_RISCV_V_SET_CONTROL, PR_RISCV_V_VSTATE_CTRL_OFF << 2, 0, 0, 0))
			perror("usp-ptdump: PR_RISCV_V_SET_CONTROL");
		/* don't leak our fds (>= 3) into the benchmark */
		syscall(SYS_close_range, 3, ~0U, 0);
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execvp(argv[optind], argv + optind);
		perror("usp-ptdump: exec");
		_exit(127);
	}
	wait_stop(pid, &st); /* SIGTRAP after exec */
	if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL))
		die("PTRACE_SETOPTIONS: %s", strerror(errno));
	long pfd = perf_open(pid);
	if (pfd < 0 && insns)
		die("perf_event_open: %s", strerror(errno));
	if (ptrace(PTRACE_CONT, pid, 0, 0))
		die("PTRACE_CONT: %s", strerror(errno));

	/* run until deadline / instruction target, forwarding other signals */
	double deadline = now() + (secs >= 0 ? secs : 1e9);
	for (;;) {
		pid_t w = waitpid(pid, &st, WNOHANG | __WALL);
		if (w == pid) {
			if (WIFEXITED(st) || WIFSIGNALED(st))
				die("program ended before capture point (status 0x%x)", st);
			if (WIFSTOPPED(st)) {
				int sig = WSTOPSIG(st);
				ptrace(PTRACE_CONT, pid, 0, sig == SIGTRAP ? 0 : sig);
				continue;
			}
		}
		if (now() >= deadline)
			break;
		if (insns) {
			uint64_t c = 0;
			if (read(pfd, &c, 8) == 8 && c >= insns)
				break;
		}
		usleep(insns ? 1000 : 2000);
	}
	kill(pid, SIGSTOP);
	for (;;) {
		wait_stop(pid, &st);
		if (WSTOPSIG(st) == SIGSTOP)
			break;
		ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(st) == SIGTRAP ? 0 : WSTOPSIG(st));
	}
	uint64_t icount = 0;
	if (pfd >= 0 && read(pfd, &icount, 8) != 8)
		icount = 0;

	snprintf(path, sizeof(path), "/proc/%d/mem", pid);
	mem_fd = open(path, O_RDWR);
	if (mem_fd < 0)
		die("open %s: %s", path, strerror(errno));

	struct user_regs_struct regs;
	struct fpregs fp;
	get_regs(pid, &regs);
	get_fpregs(pid, &fp);

	/* /proc/pid/status: sigmask, umask, caught/ignored signals */
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	char *status = slurp(path);
	uint64_t sigblk = status_hex(status, "SigBlk:");
	uint64_t sigign = status_hex(status, "SigIgn:");
	uint64_t sigcgt = status_hex(status, "SigCgt:");
	unsigned umask_v = strtoul(strstr(status, "Umask:") + 6, NULL, 8);
	if (strstr(status, "Threads:") && atoi(strstr(status, "Threads:") + 8) != 1)
		die("multi-threaded tracee is not supported");

	/* /proc/pid/stat: mm fields (1-based field numbers) */
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	char *stat_s = slurp(path);
	uint64_t fld[64] = {0};
	{
		char *p = strrchr(stat_s, ')') + 2; /* field 3: state letter */
		while (*p && *p != ' ')
			p++;
		while (*p == ' ')
			p++;
		for (int i = 4; i < 64 && *p; i++) {
			fld[i] = strtoull(p, &p, 10);
			while (*p == ' ')
				p++;
		}
	}

	/* exact brk via injected brk(0) */
	uint64_t brk_cur = (uint64_t)inject(pid, SYS_brk, 0, 0, 0, 0);

	/* signal handlers via injected rt_sigaction(sig, NULL, &old) using a
	 * scratch area below sp (no red zone on riscv; content saved/restored) */
	struct sa { uint64_t handler, flags, mask; } sas[65];
	int sig_list[65], nsig = 0;
	{
		uint64_t scratch = (regs.sp - 256) & ~15UL;
		unsigned char save[32];
		mem_rw(0, scratch, save, sizeof(save));
		for (int s = 1; s <= 64; s++) {
			uint64_t bit = 1ULL << (s - 1);
			if (s == SIGKILL || s == SIGSTOP)
				continue;
			if (!(sigcgt & bit) && !(sigign & bit))
				continue;
			long r = inject(pid, SYS_rt_sigaction, s, 0, scratch, 8);
			if (r)
				die("injected rt_sigaction(%d) failed: %ld", s, r);
			mem_rw(0, scratch, &sas[nsig], sizeof(sas[0]));
			sig_list[nsig++] = s;
		}
		mem_rw(1, scratch, save, sizeof(save));
	}

	/* output dir */
	mkdir(out, 0755);
	snprintf(path, sizeof(path), "%s/files", out);
	mkdir(path, 0755);
	snprintf(path, sizeof(path), "%s/mem.bin", out);
	FILE *mem_bin = fopen(path, "w");
	if (!mem_bin)
		die("create %s: %s", path, strerror(errno));

	/* regions */
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	char *maps = slurp(path);
	struct region *rgs = NULL;
	int nrg = 0, caprg = 0;
	for (char *line = strtok(maps, "\n"); line; line = strtok(NULL, "\n")) {
		unsigned long s, e, off;
		char perms[8], dev[16], name[PATH_MAX] = "";
		unsigned long ino;
		if (sscanf(line, "%lx-%lx %7s %lx %15s %lu %4095[^\n]", &s, &e, perms, &off, dev,
			   &ino, name) < 6)
			die("cannot parse maps line: %s", line);
		char *nm = name;
		while (*nm == ' ')
			nm++;
		if (perms[3] == 's')
			die("MAP_SHARED mapping not supported: %s", line);
		if (nrg == caprg) {
			caprg = caprg * 2 + 16;
			rgs = realloc(rgs, caprg * sizeof(*rgs));
		}
		struct region *rg = &rgs[nrg++];
		memset(rg, 0, sizeof(*rg));
		rg->start = s;
		rg->end = e;
		memcpy(rg->prot, perms, 3);
		int readable = 1;
		if (!strcmp(nm, "[heap]"))
			strcpy(rg->name, "heap");
		else if (!strcmp(nm, "[stack]"))
			strcpy(rg->name, "stack");
		else if (!strcmp(nm, "[vdso]"))
			strcpy(rg->name, "vdso");
		else if (!strncmp(nm, "[vvar", 5)) {
			/* kernel data pages, unreadable: restore as zero pages. A zeroed
			 * vvar makes the vDSO fall back to real syscalls. */
			strcpy(rg->name, "anon");
			readable = 0;
		} else if (nm[0] == '/')
			strcpy(rg->name, "exe");
		else
			strcpy(rg->name, "anon");
		dump_region(rg, mem_bin, readable);
	}
	fclose(mem_bin);

	/* fds */
	snprintf(path, sizeof(path), "%s/manifest.json", out);
	FILE *m = fopen(path, "w");
	if (!m)
		die("create %s", path);
	fprintf(m, "{\n  \"version\": 1,\n  \"arch\": \"riscv64\",\n  \"source\": \"ptrace\",\n");
	fprintf(m, "  \"icount\": \"0x%llx\",\n", (unsigned long long)icount);
	fprintf(m, "  \"cpu\": \"native\",\n");
	fprintf(m, "  \"gpr\": [");
	uint64_t *g = (uint64_t *)&regs;
	for (int i = 0; i < 32; i++)
		fprintf(m, "%s\"0x%llx\"", i ? ", " : "", (unsigned long long)g[i]);
	fprintf(m, "],\n  \"fpr\": [");
	for (int i = 0; i < 32; i++)
		fprintf(m, "%s\"0x%llx\"", i ? ", " : "", (unsigned long long)fp.f[i]);
	fprintf(m, "],\n  \"fcsr\": \"0x%x\",\n  \"regions\": [\n", fp.fcsr);
	for (int i = 0; i < nrg; i++) {
		struct region *rg = &rgs[i];
		fprintf(m, "    {\"start\": \"0x%llx\", \"end\": \"0x%llx\", \"prot\": \"%s\", \"name\": \"%s\", \"runs\": [",
			(unsigned long long)rg->start, (unsigned long long)rg->end, rg->prot, rg->name);
		for (int j = 0; j < rg->nruns; j++)
			fprintf(m, "%s{\"vaddr\": \"0x%llx\", \"npages\": %llu, \"file_off\": \"0x%llx\"}",
				j ? ", " : "", (unsigned long long)rg->runs[j].vaddr,
				(unsigned long long)rg->runs[j].npages,
				(unsigned long long)rg->runs[j].file_off);
		fprintf(m, "]}%s\n", i + 1 < nrg ? "," : "");
	}
	fprintf(m, "  ],\n");
	/* stat fields: 26 startcode 27 endcode 28 startstack 45 start_data
	 * 46 end_data 47 start_brk 48 arg_start 49 arg_end 50 env_start 51 env_end */
	fprintf(m, "  \"brk\": {\"start\": \"0x%llx\", \"cur\": \"0x%llx\"},\n",
		(unsigned long long)fld[47], (unsigned long long)brk_cur);
	fprintf(m, "  \"mm\": {\"start_code\": \"0x%llx\", \"end_code\": \"0x%llx\", "
		   "\"start_data\": \"0x%llx\", \"end_data\": \"0x%llx\", \"start_stack\": \"0x%llx\", "
		   "\"arg_start\": \"0x%llx\", \"arg_end\": \"0x%llx\", \"env_start\": \"0x%llx\", "
		   "\"env_end\": \"0x%llx\"},\n",
		(unsigned long long)fld[26], (unsigned long long)fld[27], (unsigned long long)fld[45],
		(unsigned long long)fld[46], (unsigned long long)fld[28], (unsigned long long)fld[48],
		(unsigned long long)fld[49], (unsigned long long)fld[50], (unsigned long long)fld[51]);

	fprintf(m, "  \"fds\": [\n");
	{
		snprintf(path, sizeof(path), "/proc/%d/fd", pid);
		DIR *dd = opendir(path);
		int fdl[1024], nfd = 0;
		struct dirent *de;
		if (!dd)
			die("opendir %s", path);
		while ((de = readdir(dd)))
			if (isdigit((unsigned char)de->d_name[0]) && nfd < 1024)
				fdl[nfd++] = atoi(de->d_name);
		closedir(dd);
		for (int i = 0; i < nfd; i++) /* sort */
			for (int j = i + 1; j < nfd; j++)
				if (fdl[j] < fdl[i]) {
					int t = fdl[i]; fdl[i] = fdl[j]; fdl[j] = t;
				}
		for (int i = 0; i < nfd; i++) {
			int fd = fdl[i];
			const char *sep = i + 1 < nfd ? "," : "";
			if (fd <= 2) {
				static const char *k[] = {"stdin", "stdout", "stderr"};
				fprintf(m, "    {\"fd\": %d, \"kind\": \"%s\"}%s\n", fd, k[fd], sep);
				continue;
			}
			char lp[PATH_MAX], target[PATH_MAX];
			snprintf(lp, sizeof(lp), "/proc/%d/fd/%d", pid, fd);
			ssize_t tl = readlink(lp, target, sizeof(target) - 1);
			if (tl < 0)
				die("readlink %s", lp);
			target[tl] = 0;
			struct stat sb;
			if (stat(lp, &sb))
				die("stat %s", lp);
			if (!S_ISREG(sb.st_mode) && !S_ISCHR(sb.st_mode))
				die("fd %d (%s): only regular files / char devices supported", fd, target);
			snprintf(lp, sizeof(lp), "/proc/%d/fdinfo/%d", pid, fd);
			char *fi = slurp(lp);
			unsigned long long pos = strtoull(strstr(fi, "pos:") + 4, NULL, 10);
			unsigned long flags = strtoul(strstr(fi, "flags:") + 6, NULL, 8);
			free(fi);
			const char *rel = target;
			size_t cl = strlen(cwd);
			if (!strncmp(target, cwd, cl) && target[cl] == '/')
				rel = target + cl + 1;
			fprintf(m, "    {\"fd\": %d, \"kind\": \"file\", \"path\": \"%s\", \"flags\": \"0x%lx\", \"offset\": \"0x%llx\"",
				fd, rel, flags, pos);
			if ((flags & O_ACCMODE) != O_RDONLY && S_ISREG(sb.st_mode)) {
				/* snapshot contents of files open for writing */
				char cp[PATH_MAX];
				snprintf(lp, sizeof(lp), "/proc/%d/fd/%d", pid, fd);
				int in = open(lp, O_RDONLY);
				if (in < 0)
					die("reopen %s for content: %s", target, strerror(errno));
				snprintf(cp, sizeof(cp), "%s/files/%d.bin", out, fd);
				int o = open(cp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
				char b[65536];
				ssize_t n;
				while ((n = read(in, b, sizeof(b))) > 0)
					if (write(o, b, n) != n)
						die("write %s", cp);
				close(in);
				close(o);
				fprintf(m, ", \"content\": \"files/%d.bin\"", fd);
			}
			fprintf(m, "}%s\n", sep);
		}
	}
	fprintf(m, "  ],\n");
	fprintf(m, "  \"cwd\": \"%s\",\n  \"umask\": \"0x%x\",\n  \"tid_address\": \"0x0\",\n", cwd,
		umask_v);
	fprintf(m, "  \"sigmask\": \"0x%llx\",\n  \"sigactions\": [", (unsigned long long)sigblk);
	for (int i = 0; i < nsig; i++)
		fprintf(m, "%s\n    {\"sig\": %d, \"handler\": \"0x%llx\", \"flags\": \"0x%llx\", \"mask\": \"0x%llx\"}",
			i ? "," : "", sig_list[i], (unsigned long long)sas[i].handler,
			(unsigned long long)sas[i].flags, (unsigned long long)sas[i].mask);
	fprintf(m, "%s]\n}\n", nsig ? "\n  " : "");
	fclose(m);

	fprintf(stderr, "usp-ptdump: captured pid %d at pc 0x%llx, icount ~%llu, %d regions, mem.bin %llu MiB, brk 0x%llx\n",
		pid, (unsigned long long)regs.pc, (unsigned long long)icount, nrg,
		(unsigned long long)(mem_bin_off >> 20), (unsigned long long)brk_cur);
	kill(pid, SIGKILL);
	waitpid(pid, &st, __WALL);
	return 0;
}

/*
 * usp-run: run a program (typically a usimpoint ELFie checkpoint) and measure
 * exactly one window of user-mode instructions with perf_event:
 *
 *   [exec ... W user insts (warmup) ... | ... M user insts (measured) ... | kill]
 *
 * Counting starts at execve() of the child (enable_on_exec), user-only.
 *
 * Overflow mode (default): the leader (instructions:u) samples with period
 * P = gcd(W, M) and PERF_SAMPLE_READ|PERF_FORMAT_GROUP, so every overflow
 * record carries the whole group's counts captured by the kernel in the PMU
 * interrupt.  The kernel programs each overflow from the exact remaining
 * period, so records land at k*P + (a few insts of skid): A = record at W,
 * B = record at W+M.  Neither boundary depends on parent wake-up latency.
 * The child is SIGKILLed after B.  If gcd(W, M) is tiny, the period is W and
 * is re-armed after A with PERF_EVENT_IOC_PERIOD (end boundary then has
 * ~parent-latency error, but B-A is still exact).
 *
 * Polling mode (no overflow interrupt support, or --poll-us): the parent reads
 * the group periodically (adaptive sleep, at least --poll-us near a boundary)
 * and takes snapshots at the first reads that cross W and A+M.
 *
 * Pure C, no dependencies.  Build: see Makefile.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/perf_event.h>

#define MAXEV 16
#define SAMPLE_TYPE (PERF_SAMPLE_IP | PERF_SAMPLE_READ)
#define RB_PAGES 8 /* data pages of the sample ring buffer (power of 2) */

struct evdef {
	const char *name;
	uint32_t type;
	uint64_t config;
};

#define HW(n, c) { n, PERF_TYPE_HARDWARE, PERF_COUNT_HW_##c }
#define HC(n, id, op, res)                                                   \
	{ n, PERF_TYPE_HW_CACHE,                                             \
	  PERF_COUNT_HW_CACHE_##id | (PERF_COUNT_HW_CACHE_OP_##op << 8) |    \
		  (PERF_COUNT_HW_CACHE_RESULT_##res << 16) }

static const struct evdef evtab[] = {
	HW("instructions", INSTRUCTIONS),
	HW("cycles", CPU_CYCLES),
	HW("cpu-cycles", CPU_CYCLES),
	HW("branches", BRANCH_INSTRUCTIONS),
	HW("branch-instructions", BRANCH_INSTRUCTIONS),
	HW("branch-misses", BRANCH_MISSES),
	HW("cache-references", CACHE_REFERENCES),
	HW("cache-misses", CACHE_MISSES),
	HW("bus-cycles", BUS_CYCLES),
	HW("stalled-cycles-frontend", STALLED_CYCLES_FRONTEND),
	HW("stalled-cycles-backend", STALLED_CYCLES_BACKEND),
	HW("ref-cycles", REF_CPU_CYCLES),
	HC("L1-dcache-loads", L1D, READ, ACCESS),
	HC("L1-dcache-load-misses", L1D, READ, MISS),
	HC("L1-dcache-stores", L1D, WRITE, ACCESS),
	HC("L1-dcache-store-misses", L1D, WRITE, MISS),
	HC("L1-dcache-prefetches", L1D, PREFETCH, ACCESS),
	HC("L1-dcache-prefetch-misses", L1D, PREFETCH, MISS),
	HC("L1-icache-loads", L1I, READ, ACCESS),
	HC("L1-icache-load-misses", L1I, READ, MISS),
	HC("LLC-loads", LL, READ, ACCESS),
	HC("LLC-load-misses", LL, READ, MISS),
	HC("LLC-stores", LL, WRITE, ACCESS),
	HC("LLC-store-misses", LL, WRITE, MISS),
	HC("dTLB-loads", DTLB, READ, ACCESS),
	HC("dTLB-load-misses", DTLB, READ, MISS),
	HC("dTLB-stores", DTLB, WRITE, ACCESS),
	HC("dTLB-store-misses", DTLB, WRITE, MISS),
	HC("iTLB-loads", ITLB, READ, ACCESS),
	HC("iTLB-load-misses", ITLB, READ, MISS),
	HC("branch-loads", BPU, READ, ACCESS),
	HC("branch-load-misses", BPU, READ, MISS),
};

struct snap {
	int valid;
	uint64_t te, tr;  /* time enabled / running (ns) */
	uint64_t ip;      /* user pc at overflow (overflow mode only) */
	uint64_t v[MAXEV];
};

#define GCD_MAX_INTERIOR 64

static uint64_t gcd64(uint64_t a, uint64_t b)
{
	while (b) {
		uint64_t t = a % b;
		a = b;
		b = t;
	}
	return a;
}

static int nev;
static struct evdef ev[MAXEV];
static int fds[MAXEV];
static pid_t child = -1;

static double now_s(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("usp-run: ", stderr);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	if (child > 0) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
	}
	exit(2);
}

static uint64_t parse_num(const char *s)
{
	char *end;
	double d;
	errno = 0;
	uint64_t v = strtoull(s, &end, 0);
	if (!errno && *end == 0 && end != s)
		return v;
	d = strtod(s, &end); /* accept 2e7, 1e9 */
	if (*end || end == s || d < 0)
		die("bad number '%s'", s);
	return (uint64_t)(d + 0.5);
}

static void add_event(const char *name)
{
	char buf[128];
	size_t n;
	if (nev >= MAXEV)
		die("too many events (max %d)", MAXEV);
	snprintf(buf, sizeof buf, "%s", name);
	n = strlen(buf);
	if (n > 2 && !strcmp(buf + n - 2, ":u"))
		buf[n - 2] = 0;
	if (buf[0] == 'r' && buf[1] && strspn(buf + 1, "0123456789abcdefABCDEF") == strlen(buf + 1)) {
		ev[nev].type = PERF_TYPE_RAW;
		ev[nev].config = strtoull(buf + 1, NULL, 16);
		ev[nev].name = strdup(buf);
		nev++;
		return;
	}
	for (size_t i = 0; i < sizeof evtab / sizeof evtab[0]; i++)
		if (!strcmp(evtab[i].name, buf)) {
			ev[nev] = evtab[i];
			nev++;
			return;
		}
	die("unknown event '%s' (generic hw/cache names or rHEX raw)", name);
}

static int perf_open(struct perf_event_attr *a, pid_t pid, int group)
{
	return syscall(SYS_perf_event_open, a, pid, -1, group, PERF_FLAG_FD_CLOEXEC);
}

/* Parse a read_format GROUP|TE|TR buffer into s. */
static void parse_group(const uint64_t *p, struct snap *s)
{
	uint64_t nr = p[0];
	s->te = p[1];
	s->tr = p[2];
	for (uint64_t i = 0; i < nr && i < MAXEV; i++)
		s->v[i] = p[3 + i];
	s->valid = 1;
}

static int read_group(struct snap *s)
{
	uint64_t buf[3 + MAXEV];
	ssize_t r = read(fds[0], buf, sizeof buf);
	if (r < (ssize_t)(3 * sizeof(uint64_t)))
		return -1;
	s->ip = 0;
	parse_group(buf, s);
	return 0;
}

/* ---- overflow ring buffer ---- */
static struct perf_event_mmap_page *rb;
static size_t rb_data_size;

/* Copy next record into out (handles wrap).  Returns 1 if a record was read. */
static int rb_next(char *out, size_t outsz)
{
	uint64_t head = __atomic_load_n(&rb->data_head, __ATOMIC_ACQUIRE);
	uint64_t tail = rb->data_tail;
	const char *data = (const char *)rb + rb->data_offset;
	struct perf_event_header h;
	size_t off, sz;

	if (tail >= head)
		return 0;
	off = tail % rb_data_size;
	for (size_t i = 0; i < sizeof h; i++)
		((char *)&h)[i] = data[(off + i) % rb_data_size];
	sz = h.size;
	if (sz < sizeof h)
		sz = sizeof h; /* corrupt; skip header */
	for (size_t i = 0; i < sz && i < outsz; i++)
		out[i] = data[(off + i) % rb_data_size];
	__atomic_store_n(&rb->data_tail, tail + sz, __ATOMIC_RELEASE);
	return 1;
}

static const char *signame(int sig)
{
	const char *s = sigabbrev_np(sig);
	return s ? s : "?";
}

static void usage(void)
{
	fprintf(stderr,
		"usage: usp-run [-w WARMUP] [-m MEASURE] [-e ev,...] [-o result.json]\n"
		"               [--cpu N] [--poll-us N] [-q] -- prog args...\n"
		"  -w N        warmup user instructions counted from exec (default 20000000, may be 0)\n"
		"  -m N        measured user instructions (default 20000000)\n"
		"  -e LIST     extra events: generic names (branch-misses, cache-misses,\n"
		"              L1-dcache-load-misses, ...) or raw rHEX\n"
		"  -o FILE     write JSON result\n"
		"  --cpu N     pin child to CPU N\n"
		"  --poll-us N force polling mode, minimum poll interval N us\n"
		"  --max-rate N polling: upper bound on insts/s for adaptive sleep (default 1e10)\n"
		"  --rearm     overflow mode: always end the window by re-arming the period\n"
		"              after A (default only when gcd(W,M) is too small)\n"
		"  --exact-w   keep W as given even if gcd(W,M) is tiny (default: round W\n"
		"              to the nearest multiple of M, which keeps both boundaries\n"
		"              in the PMU interrupt; checkpoint warmups are ~M anyway)\n"
		"  -q          no human summary\n");
	exit(2);
}

int main(int argc, char **argv)
{
	uint64_t W = 20000000, M = 20000000;
	const char *outpath = NULL;
	int cpu = -1, quiet = 0;
	long poll_us = 0;
	int force_poll = 0, force_rearm = 0, exact_w = 0;
	int debug = getenv("USP_DEBUG") != NULL;
	double max_rate = 1e10; /* polling: upper bound on user insts/s */
	static const struct option lopts[] = {
		{ "cpu", required_argument, 0, 'c' },
		{ "poll-us", required_argument, 0, 'p' },
		{ "rearm", no_argument, 0, 'r' },
		{ "exact-w", no_argument, 0, 'x' },
		{ "max-rate", required_argument, 0, 'R' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 } };
	char *extras[MAXEV];
	int nextras = 0;
	int opt;

	while ((opt = getopt_long(argc, argv, "+w:m:e:o:qh", lopts, NULL)) != -1) {
		switch (opt) {
		case 'w': W = parse_num(optarg); break;
		case 'm': M = parse_num(optarg); break;
		case 'e': {
			char *s = strdup(optarg), *tok, *save;
			for (tok = strtok_r(s, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
				if (nextras >= MAXEV - 2)
					die("too many extra events");
				extras[nextras++] = tok;
			}
			break;
		}
		case 'o': outpath = optarg; break;
		case 'c': cpu = (int)parse_num(optarg); break;
		case 'p': poll_us = (long)parse_num(optarg); force_poll = 1; break;
		case 'q': quiet = 1; break;
		case 'r': force_rearm = 1; break;
		case 'x': exact_w = 1; break;
		case 'R': max_rate = (double)parse_num(optarg); break;
		default: usage();
		}
	}
	if (optind >= argc || M == 0)
		usage();
	char **cargv = argv + optind;

	add_event("instructions");
	add_event("cycles");
	for (int i = 0; i < nextras; i++)
		add_event(extras[i]);

	double t0 = now_s();

	/* ---- fork the child, blocked on a pipe until counters exist ---- */
	int pp[2];
	if (pipe2(pp, O_CLOEXEC))
		die("pipe: %s", strerror(errno));
	child = fork();
	if (child < 0)
		die("fork: %s", strerror(errno));
	if (child == 0) {
		char c;
		close(pp[1]);
		if (cpu >= 0) {
			cpu_set_t set;
			CPU_ZERO(&set);
			CPU_SET(cpu, &set);
			if (sched_setaffinity(0, sizeof set, &set))
				fprintf(stderr, "usp-run: sched_setaffinity(%d): %s\n", cpu, strerror(errno));
		}
		if (read(pp[0], &c, 1) != 1)
			_exit(127); /* parent gave up */
		execv(cargv[0], cargv);
		fprintf(stderr, "usp-run: execv %s: %s\n", cargv[0], strerror(errno));
		_exit(127);
	}
	close(pp[0]);
	if (cpu >= 0) {
		/* keep the launcher off the measured CPU */
		cpu_set_t set;
		if (!sched_getaffinity(0, sizeof set, &set) && CPU_ISSET(cpu, &set) && CPU_COUNT(&set) > 1) {
			CPU_CLR(cpu, &set);
			sched_setaffinity(0, sizeof set, &set);
		}
	}

	/* ---- open the counter group on the child ---- */
	int mode_overflow = !force_poll;
	/* Overflow scheme.  The kernel programs every overflow from the exact
	 * remaining period (skid does not accumulate), so with leader period
	 * P = gcd(W, M) the records at counts W and W+M are both taken in the PMU
	 * interrupt with only a few instructions of skid and no parent latency.
	 * Only one sampling counter is needed (on K3 a second instructions
	 * counter in the group does not raise overflow interrupts).  If P is so
	 * small that more than GCD_MAX_INTERIOR interrupts would land inside the
	 * window, fall back to "re-arm": period W, then PERF_EVENT_IOC_PERIOD so
	 * the next overflow is ~A+M (end boundary then has parent-latency error,
	 * still measured exactly). */
	if (W && !exact_w && !force_rearm && !force_poll &&
	    M / gcd64(W, M) > GCD_MAX_INTERIOR) {
		uint64_t r = (W + M / 2) / M * M;
		if (!r)
			r = M;
		if (!quiet)
			fprintf(stderr, "usp-run: warmup %llu rounded to %llu "
				"(multiple of measure length)\n",
				(unsigned long long)W, (unsigned long long)r);
		W = r;
	}
	uint64_t period = W ? gcd64(W, M) : M;
	int rearm = force_rearm || M / period > GCD_MAX_INTERIOR;
	if (rearm && W)
		period = W;
	struct perf_event_attr a;
	for (int i = 0; i < nev; i++) {
		memset(&a, 0, sizeof a);
		a.size = sizeof a;
		a.type = ev[i].type;
		a.config = ev[i].config;
		a.exclude_kernel = 1;
		a.exclude_hv = 1;
		a.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED |
				PERF_FORMAT_TOTAL_TIME_RUNNING;
		if (i == 0) {
			a.disabled = 1;
			a.enable_on_exec = 1;
			if (mode_overflow) {
				a.sample_period = period;
				a.sample_type = SAMPLE_TYPE;
				a.wakeup_events = 1;
			}
		}
		fds[i] = perf_open(&a, child, i ? fds[0] : -1);
		if (fds[i] < 0 && i == 0 && mode_overflow) {
			int e = errno;
			fprintf(stderr, "usp-run: sampling leader not supported (%s); falling back to polling\n",
				strerror(e));
			mode_overflow = 0;
			i--;
			continue;
		}
		if (fds[i] < 0)
			die("perf_event_open(%s): %s%s", ev[i].name, strerror(errno),
			    errno == ENOENT || errno == EOPNOTSUPP ? " (event not supported by this PMU)" : "");
	}
	if (!mode_overflow && poll_us <= 0)
		poll_us = 100;

	int nfds = 1;
	struct pollfd pfd[2];
	if (mode_overflow) {
		long pg = sysconf(_SC_PAGESIZE);
		rb_data_size = (size_t)RB_PAGES * pg;
		rb = mmap(NULL, (1 + RB_PAGES) * pg, PROT_READ | PROT_WRITE, MAP_SHARED, fds[0], 0);
		if (rb == MAP_FAILED)
			die("mmap perf ring: %s", strerror(errno));
		pfd[0].fd = fds[0];
		pfd[0].events = POLLIN;
	}
	int pidfd = syscall(SYS_pidfd_open, child, 0);
	if (pidfd >= 0) {
		pfd[nfds].fd = pidfd;
		pfd[nfds].events = POLLIN;
		nfds++;
	}

	/* ---- release the child ---- */
	if (write(pp[1], "g", 1) != 1)
		die("pipe write: %s", strerror(errno));
	close(pp[1]);

	struct snap A = { 0 }, B = { 0 }, Ar = { 0 }, fin = { 0 };
	int status = 0, exited = 0, late = 0, ovf_dead = 0;
	uint64_t nsamples = 0, nlost = 0, nthrottle = 0, nreads = 0;
	if (W == 0)
		A.valid = 1; /* counters are zero at exec */

	if (mode_overflow) {
		char rec[4096];
		while (!B.valid) {
			int r = poll(pfd + 0, nfds, 20);
			if (r < 0 && errno != EINTR)
				die("poll: %s", strerror(errno));
			/* check exit before draining so no record is left behind */
			if (waitpid(child, &status, WNOHANG) == child)
				exited = 1;
			while (!B.valid && rb_next(rec, sizeof rec)) {
				struct perf_event_header *h = (void *)rec;
				if (h->type == PERF_RECORD_LOST) {
					nlost++;
					continue;
				}
				if (h->type == PERF_RECORD_THROTTLE) {
					nthrottle++;
					continue;
				}
				if (h->type != PERF_RECORD_SAMPLE)
					continue;
				nsamples++;
				uint64_t *p = (uint64_t *)(h + 1);
				struct snap s = { 0 };
				parse_group(p + 1, &s);
				s.ip = p[0];
				if (debug)
					fprintf(stderr, "usp-run: sample insts=%" PRIu64 " ip=0x%" PRIx64 "\n", s.v[0], s.ip);
				if (!rearm) {
					/* records at k*P; skid << P */
					if (!A.valid && s.v[0] >= W) {
						A = s;
						read_group(&Ar);
					} else if (A.valid && s.v[0] >= W + M) {
						B = s;
					}
					continue;
				}
				if (!A.valid) {
					A = s;
					/* Re-arm so the next overflow lands at A+M.  The ioctl
					 * restarts the period from "now", so subtract what was
					 * already counted since A. */
					read_group(&Ar);
					if (Ar.v[0] >= A.v[0] + M) {
						late = 1;
						continue; /* wait for a later sample / exit */
					}
					uint64_t per = A.v[0] + M - Ar.v[0];
					if (ioctl(fds[0], PERF_EVENT_IOC_PERIOD, &per))
						die("PERF_EVENT_IOC_PERIOD: %s", strerror(errno));
				} else if (s.v[0] >= A.v[0] + M) {
					B = s;
				}
			}
			if (B.valid || exited)
				break;
			/* Watchdog: sampling accepted but no overflow interrupt ever
			 * delivered (seen on K3 for a 2nd instructions counter) -> poll. */
			if (nsamples == 0) {
				struct snap c;
				if (!read_group(&c) && c.v[0] > period + period / 2 + 10000000ULL) {
					fprintf(stderr, "usp-run: WARNING: no overflow records after %" PRIu64
						" insts; switching to polling (use --poll-us to poll from the start)\n", c.v[0]);
					mode_overflow = 0;
					ovf_dead = 1;
					if (poll_us <= 0)
						poll_us = 100;
					break;
				}
			}
		}
	}
	if (!mode_overflow && !exited && !B.valid) {
		/* Adaptive sleep: never sleep longer than the remaining distance
		 * could take at max_rate insts/s, so a boundary is never overshot by
		 * more than one poll_us interval; far from it, read rarely (every
		 * read IPIs the child's CPU). */
		struct snap prev = { 0 };
		for (;;) {
			uint64_t target = A.valid ? A.v[0] + M : W;
			uint64_t rem = target > prev.v[0] ? target - prev.v[0] : 0;
			double sl_d = rem / max_rate * 1e6;
			long sl = sl_d > 50000 ? 50000 : (long)sl_d;
			if (sl < poll_us)
				sl = poll_us;
			struct timespec ts = { sl / 1000000, (sl % 1000000) * 1000 };
			nanosleep(&ts, NULL);
			struct snap s;
			if (read_group(&s))
				die("read: %s", strerror(errno));
			nreads++;
			prev = s;
			if (!A.valid && s.v[0] >= W)
				A = s;
			if (A.valid && s.v[0] >= A.v[0] + M) {
				B = s;
				break;
			}
			if (waitpid(child, &status, WNOHANG) == child) {
				exited = 1;
				break;
			}
		}
	}

	if (!exited) {
		kill(child, SIGKILL);
		while (waitpid(child, &status, 0) < 0 && errno == EINTR)
			;
	}
	read_group(&fin); /* final counts (at exit, or at kill) */
	double t1 = now_s();

	int complete = A.valid && B.valid;
	const char *modestr = ovf_dead ? "poll-after-dead-overflow" : !mode_overflow ? "poll" : rearm && W ? "overflow-rearm" : "overflow";
	char cstat[64];
	if (exited) {
		if (WIFEXITED(status))
			snprintf(cstat, sizeof cstat, "exited(%d)", WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			snprintf(cstat, sizeof cstat, "signal(%s)", signame(WTERMSIG(status)));
		else
			snprintf(cstat, sizeof cstat, "unknown(0x%x)", status);
	} else {
		snprintf(cstat, sizeof cstat, "killed_by_launcher");
	}
	/* Partial: use what we have. */
	struct snap a_ = A.valid ? A : (struct snap){ 0 };
	struct snap b_ = B.valid ? B : fin;
	if (!A.valid)
		a_ = (struct snap){ 0 }; /* never reached warmup: report whole run */

	uint64_t dv[MAXEV];
	for (int i = 0; i < nev; i++)
		dv[i] = b_.v[i] - a_.v[i];
	double ipc = dv[1] ? (double)dv[0] / dv[1] : 0;
	double cpi = dv[0] ? (double)dv[1] / dv[0] : 0;
	int64_t skid = (int64_t)dv[0] - (int64_t)M;
	int64_t wskid = A.valid ? (int64_t)A.v[0] - (int64_t)W : 0;
	uint64_t dte = b_.te - a_.te, dtr = b_.tr - a_.tr;
	int mux = dte != dtr;
	int unsched = b_.te && !b_.tr;

	if (unsched)
		fprintf(stderr, "usp-run: WARNING: group never scheduled (too many events for the PMU?)\n");
	else if (mux)
		fprintf(stderr, "usp-run: WARNING: multiplexing: window time_enabled=%" PRIu64
			" time_running=%" PRIu64 " (counts NOT scaled)\n", dte, dtr);
	if (nlost || nthrottle)
		fprintf(stderr, "usp-run: WARNING: lost=%" PRIu64 " throttle=%" PRIu64 "\n", nlost, nthrottle);
	if (late)
		fprintf(stderr, "usp-run: WARNING: parent woke up after A+M had passed\n");
	if (!complete)
		fprintf(stderr, "usp-run: WARNING: window incomplete: child %s before %s\n", cstat,
			A.valid ? "end of measurement" : "end of warmup");

	if (!quiet) {
		fprintf(stderr, "usp-run: mode=%s warmup=%" PRIu64 " measure=%" PRIu64 " child=%s%s\n",
			modestr, W, M, cstat, complete ? "" : " [PARTIAL]");
		fprintf(stderr, "  window: A=%" PRIu64 " (warmup skid %+" PRId64 ") B=%" PRIu64
			" (measure skid %+" PRId64 ")\n", a_.v[0], wskid, b_.v[0], skid);
		if (mode_overflow && A.valid && Ar.valid)
			fprintf(stderr, "  parent wakeup lag at A: %" PRIu64 " insts\n", Ar.v[0] - A.v[0]);
		if (mode_overflow)
			fprintf(stderr, "  pc: A=0x%" PRIx64 " B=0x%" PRIx64 "\n", a_.ip, b_.ip);
		fprintf(stderr, "  %-24s %16" PRIu64 "\n", "instructions:u", dv[0]);
		fprintf(stderr, "  %-24s %16" PRIu64 "\n", "cycles:u", dv[1]);
		for (int i = 2; i < nev; i++)
			fprintf(stderr, "  %-24s %16" PRIu64 "\n", ev[i].name, dv[i]);
		fprintf(stderr, "  IPC %.4f  CPI %.4f  window %.3f ms  wall %.3f s\n", ipc, cpi,
			dte * 1e-6, t1 - t0);
		if (!mode_overflow)
			fprintf(stderr, "  polling reads: %" PRIu64 "\n", nreads);
	}

	if (outpath) {
		FILE *f = fopen(outpath, "w");
		if (!f)
			die("open %s: %s", outpath, strerror(errno));
		fprintf(f, "{\n  \"mode\": \"%s\",\n", modestr);
		fprintf(f, "  \"warmup_target\": %" PRIu64 ",\n  \"measure_target\": %" PRIu64 ",\n", W, M);
		fprintf(f, "  \"complete\": %s,\n", complete ? "true" : "false");
		fprintf(f, "  \"child_status\": \"%s\",\n", cstat);
		fprintf(f, "  \"insts\": %" PRIu64 ",\n  \"cycles\": %" PRIu64 ",\n", dv[0], dv[1]);
		fprintf(f, "  \"ipc\": %.6f,\n  \"cpi\": %.6f,\n", ipc, cpi);
		fprintf(f, "  \"skid\": %" PRId64 ",\n  \"warmup_skid\": %" PRId64 ",\n", skid, wskid);
		fprintf(f, "  \"start_insts\": %" PRIu64 ",\n  \"end_insts\": %" PRIu64 ",\n", a_.v[0], b_.v[0]);
		fprintf(f, "  \"start_pc\": %" PRIu64 ",\n  \"end_pc\": %" PRIu64 ",\n", a_.ip, b_.ip);
		if (mode_overflow && A.valid && Ar.valid)
			fprintf(f, "  \"wakeup_lag_insts\": %" PRIu64 ",\n", Ar.v[0] - A.v[0]);
		fprintf(f, "  \"events\": {");
		for (int i = 2; i < nev; i++)
			fprintf(f, "%s\"%s\": %" PRIu64, i > 2 ? ", " : "", ev[i].name, dv[i]);
		fprintf(f, "},\n");
		fprintf(f, "  \"time_enabled_ns\": %" PRIu64 ",\n  \"time_running_ns\": %" PRIu64 ",\n", dte, dtr);
		fprintf(f, "  \"multiplexed\": %s,\n", mux ? "true" : "false");
		fprintf(f, "  \"total_insts\": %" PRIu64 ",\n", fin.v[0]);
		fprintf(f, "  \"overflow_records\": %" PRIu64 ",\n  \"poll_reads\": %" PRIu64 ",\n", nsamples, nreads);
		fprintf(f, "  \"wall_s\": %.6f\n}\n", t1 - t0);
		fclose(f);
	}
	return complete ? 0 : 1;
}

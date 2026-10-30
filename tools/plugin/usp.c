/*
 * usp — usimpoint QEMU linux-user plugin.
 *
 * Guests are single-threaded, or multi-threaded with the threads serialized:
 * the plugin lets only one guest thread run at a time (a "baton" handed over
 * only when the holder blocks in a syscall, see "Thread serialization"), so
 * all threads form one deterministic instruction stream.  Intervals, BBVs and
 * checkpoints refer to that global stream; a checkpoint is the thread running
 * at that point.
 *
 * mode=profile  : SimPoint BBV (interval insts) + syscall log for replay
 * mode=capture  : replay nondeterministic syscalls from the log, and at the
 *                 start of each selected interval dump a checkpoint
 *                 (docs/ckpt-format.md).
 *
 * Options (comma separated, key=value):
 *   mode=profile|capture   out=DIR   interval=N (default 20000000)
 *   syslog=FILE            (profile: written, capture: replayed)
 *   points=FILE            (capture: SimPoint "simpoints" file, "<interval> <id>")
 *   weights=FILE           (capture: optional SimPoint weights file)
 *   cpu=STRING             (informational, stored in manifest)
 *   stop=1                 (capture: exit after the last checkpoint window)
 *   warmup=K               (capture: checkpoint K intervals before each
 *                           SimPoint interval; default 1)
 *   window=N               (capture: record a syscall trace for N insts after
 *                           each checkpoint; default 3*interval, 0 = off)
 *
 * Requires the qemu_plugin_walk_guest_regions() API added in third_party/qemu.
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define PAGE 4096ULL
/* cond callback fires when ctr >= BIAS, i.e. icount >= next boundary */
#define BIAS (1ULL << 62)

/*
 * Callback udata: TB vaddr << 16 | insn count. The TB vaddr is the PC: with
 * PC-relative translation QEMU does not sync env->pc at TB entry, so reading
 * the "pc" register in a TB callback can return a stale value.
 */
#define TB_UDATA(vaddr, n) ((void *)(uintptr_t)(((vaddr) << 16) | (n)))
#define TB_VADDR(udata) ((uint64_t)(uintptr_t)(udata) >> 16)
#define TB_NINSNS(udata) ((uint64_t)(uintptr_t)(udata) & 0xffff)

/* riscv64 (asm-generic) syscall numbers */
enum {
    NR_getcwd = 17, NR_dup = 23, NR_dup3 = 24, NR_fcntl = 25, NR_chdir = 49,
    NR_fchdir = 50, NR_openat = 56, NR_close = 57, NR_pipe2 = 59,
    NR_set_tid_address = 96, NR_setitimer = 103, NR_timer_create = 107,
    NR_clock_gettime = 113, NR_clock_getres = 114, NR_sched_getaffinity = 123,
    NR_rt_sigaction = 134, NR_rt_sigprocmask = 135, NR_times = 153,
    NR_uname = 160, NR_getrusage = 165, NR_umask = 166, NR_getcpu = 168,
    NR_gettimeofday = 169, NR_getpid = 172, NR_getppid = 173, NR_gettid = 178,
    NR_sysinfo = 179, NR_socket = 198, NR_brk = 214, NR_clone = 220,
    NR_mmap = 222, NR_exit = 93, NR_exit_group = 94, NR_waitid = 95,
    NR_futex = 98, NR_nanosleep = 101, NR_clock_nanosleep = 115,
    NR_sched_yield = 124, NR_rt_sigsuspend = 133, NR_rt_sigtimedwait = 137,
    NR_pselect6 = 72, NR_ppoll = 73, NR_epoll_pwait = 22, NR_wait4 = 260,
    NR_futex_waitv = 449,
    NR_execve = 221, NR_getrandom = 278, NR_execveat = 281, NR_clone3 = 435,
};

/* ---------------------------------------------------------------- state */

typedef struct Bb {
    uint64_t vaddr;
    struct qemu_plugin_scoreboard *count;
    unsigned int index;
} Bb;

typedef struct {
    uint64_t icount;   /* insts of all TBs entered, incl. the current one */
    uint64_t ctr;      /* icount - next_boundary + BIAS */
} VcpuCounters;

typedef struct {
    char *path;
    uint64_t flags;
} FdEnt;

typedef struct {
    uint64_t handler, flags, mask;
} SigAct;

enum { MODE_PROFILE, MODE_CAPTURE };

static int mode = MODE_PROFILE;
static uint64_t interval = 20000000;
static char *outdir;
static char *syslog_path;
static char *points_path;
static char *weights_path;
static char *cpu_name;
static bool stop_after_last;
static uint64_t window = UINT64_MAX;    /* UINT64_MAX: 3 * interval */
static uint64_t warmup_intervals = 1;   /* checkpoint this many intervals early */

/*
 * Per-checkpoint syscall trace (docs/ckpt-format.md, "syscalls.bin"):
 * everything the guest gets from the kernel during the replay window.
 */
typedef struct {
    FILE *f;
    uint64_t start;     /* icount of the checkpoint */
    uint64_t end;       /* stop recording at this icount */
    uint64_t count;
    unsigned int vcpu;  /* the checkpointed thread */
    char *dir;
} Trace;
static GPtrArray *traces;     /* active traces */

typedef struct {
    uint64_t addr, len;
} Range;
/* guest memory written by this thread's current syscall */
static __thread GArray *sc_writes;

static struct qemu_plugin_scoreboard *counters;
static GHashTable *bbs;
static FILE *bbv_file;
static uint64_t next_boundary;
static uint64_t interval_index;   /* index of the interval being executed */

/* registers */
static struct qemu_plugin_register *gpr_handle[32]; /* [0] = pc */
static struct qemu_plugin_register *fpr_handle[32];
static struct qemu_plugin_register *fcsr_handle;
static struct qemu_plugin_register *fflags_handle, *frm_handle;
/* vector state (only if the CPU model has V) */
static struct qemu_plugin_register *vreg_handle[32];
enum { VCSR_VSTART, VCSR_VL, VCSR_VTYPE, VCSR_VCSR, VCSR_VXRM, VCSR_VXSAT,
       VCSR_VLENB, VCSR_N };
static const char *vcsr_names[VCSR_N] = {
    "vstart", "vl", "vtype", "vcsr", "vxrm", "vxsat", "vlenb",
};
static struct qemu_plugin_register *vcsr_handle[VCSR_N];
static bool have_vector;     /* V registers exposed by QEMU */
static bool dump_vec;        /* ... and AT_HWCAP advertises V to the guest */

/* process state tracked from syscalls */
#define MAX_FD 1024
static FdEnt fds[MAX_FD];
static char *init_cwd;
static char *cur_cwd;     /* guest-relative changes via chdir, absolute */
static uint64_t brk_start, brk_cur;
static SigAct sigacts[65];
static uint64_t umask_val = 022;
static bool unsupported;
static char unsupported_why[256];
/* fd-table state live mode can't rebuild; replay mode doesn't need it */
static bool live_unsupported;
static char live_why[256];

/* initial stack layout for PR_SET_MM_MAP */
static bool seen_first_tb;
static uint64_t entry_pc, start_stack, arg_start, arg_end, env_start, env_end;

/* pending syscall entry of this guest thread (callbacks run on its thread) */
static __thread int64_t sc_num;
static __thread uint64_t sc_args[8];

/*
 * Threads.  QEMU linux-user runs each guest thread on its own host thread
 * (one vCPU each), and plugin callbacks run on that thread.  Per-thread
 * kernel state that a checkpoint needs is kept per vCPU index; "ord" is the
 * thread's creation ordinal, stable between runs (vCPU indexes are too, but
 * the ordinal does not depend on QEMU's index reuse).
 */
#define MAX_VCPUS 1024
typedef struct {
    bool live;
    bool in_sys;            /* between syscall entry and return */
    int ord;
    uint64_t tid_address;   /* set_tid_address / CLONE_CHILD_CLEARTID */
    uint64_t sigmask;       /* blocked signals (per thread) */
    uint64_t sys_since;     /* g_get_monotonic_time() at syscall entry */
    int64_t sys_num;
} Thr;
static Thr thr[MAX_VCPUS];
static int nthreads;              /* ordinals handed out */
static int nlive;
static uint64_t clone_sigmask, clone_ctid;   /* for the child of a pending clone */

/*
 * Thread serialization ("baton").  A guest thread executes guest code only
 * while it holds the baton.  It is taken at vCPU start and at every syscall
 * return, and given up at the entry of syscalls that may block (futex wait,
 * sleeps, waits, thread exit, sched_yield).  Waiters are served FIFO.  So
 * only the holder runs, and the order is decided by the program's own
 * blocking pattern, not by host timing; the global instruction stream is
 * the concatenation of the threads' slices.  A thread blocked in a syscall
 * we did not classify as blocking while another waits for the baton is
 * detected after a few seconds and the baton is taken from it (with a
 * warning; the stream may then be nondeterministic).
 * All plugin state is protected by mtx (callbacks of different threads may
 * run concurrently: a thread returning from a blocking syscall runs its
 * callbacks while the holder executes).
 */
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t baton_cv = PTHREAD_COND_INITIALIZER;
static int baton = -1;            /* vCPU index of the holder */
static uint64_t ticket_next, ticket_serving;
static int last_runner = -1;      /* vCPU that held the baton last */
static uint64_t nswitches;
static FILE *switch_out;          /* profile: switches.txt */
static bool serial_broken;

/* syscall log */
typedef struct __attribute__((packed)) {
    uint32_t magic;     /* 'USPS' */
    uint32_t buflen;
    int64_t num;
    int64_t ret;
    uint64_t icount;
    uint64_t bufaddr;
    uint32_t thread;    /* thread ordinal */
    uint32_t pad;
} SysRec;
#define SYSREC_MAGIC 0x53505355u

static FILE *syslog_out;
static uint8_t *syslog_buf;       /* capture: whole log in memory */
static size_t syslog_len;
/* capture: per thread ordinal, offsets of its records and the next one */
static GPtrArray *rp_off;         /* GArray<size_t> per ordinal */
static GArray *rp_pos;            /* guint per ordinal */
static uint64_t sys_seq;
static bool replay_ok = true;

/* capture targets */
typedef struct {
    uint64_t interval;      /* SimPoint interval to be measured */
    uint64_t at;            /* interval at whose start the checkpoint is taken */
    int id;
    double weight;
} Point;
static GArray *points;      /* sorted by interval */
static guint next_point;

/* ------------------------------------------------------------- helpers */

static void die(const char *fmt, ...) G_GNUC_PRINTF(1, 2);
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "usp: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    _exit(125);
}

static void mark_live_unsupported(const char *why)
{
    if (!live_unsupported) {
        live_unsupported = true;
        g_strlcpy(live_why, why, sizeof(live_why));
        fprintf(stderr, "usp: live mode unsupported (replay only): %s\n", why);
    }
}

static void mark_unsupported(const char *why)
{
    if (!unsupported) {
        unsupported = true;
        g_strlcpy(unsupported_why, why, sizeof(unsupported_why));
        fprintf(stderr, "usp: unsupported guest behaviour: %s\n", why);
    }
}

static qemu_plugin_u64 icount_u64(void)
{
    return qemu_plugin_scoreboard_u64_in_struct(counters, VcpuCounters, icount);
}

static qemu_plugin_u64 ctr_u64(void)
{
    return qemu_plugin_scoreboard_u64_in_struct(counters, VcpuCounters, ctr);
}

/* instructions executed by all threads (the global stream) */
static uint64_t global_icount(void)
{
    return qemu_plugin_u64_sum(icount_u64());
}

/*
 * Point vcpu's boundary counter at the next boundary of the global stream:
 * its cond callback fires once it has executed (next_boundary - global)
 * more instructions.  Called when a thread takes the baton; with one thread
 * this is a no-op (ctr == icount - next_boundary + BIAS already).
 */
static void resync_ctr(unsigned int vcpu)
{
    qemu_plugin_u64_set(ctr_u64(), vcpu,
                        global_icount() - next_boundary + BIAS);
}

static void traces_switch(unsigned int vcpu, uint64_t icount);

static void baton_acquire(unsigned int vcpu)
{
    uint64_t t;

    if (baton == (int)vcpu) {
        return;
    }
    t = ticket_next++;
    while (baton >= 0 || ticket_serving != t) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 2;
        if (pthread_cond_timedwait(&baton_cv, &mtx, &ts) == ETIMEDOUT &&
            ticket_serving == t && baton >= 0 && thr[baton].in_sys &&
            g_get_monotonic_time() - (int64_t)thr[baton].sys_since > 5000000) {
            fprintf(stderr, "usp: warning: thread %d blocked in syscall %"
                    PRId64 " for >5s holding the run baton; thread %d takes "
                    "it (execution no longer deterministically serialized)\n",
                    thr[baton].ord, thr[baton].sys_num, thr[vcpu].ord);
            serial_broken = true;
            baton = -1;
        }
    }
    ticket_serving++;
    baton = vcpu;
    pthread_cond_broadcast(&baton_cv);
    if (last_runner >= 0 && last_runner != (int)vcpu) {
        uint64_t icount = global_icount();
        nswitches++;
        if (switch_out) {
            fprintf(switch_out, "%" PRIu64 " %d %d\n", icount,
                    thr[last_runner].ord, thr[vcpu].ord);
        }
        traces_switch(vcpu, icount);
    }
    last_runner = vcpu;
    resync_ctr(vcpu);
}

static void baton_release(unsigned int vcpu)
{
    if (baton == (int)vcpu) {
        baton = -1;
        pthread_cond_broadcast(&baton_cv);
    }
}

/* syscalls that may block until another guest thread does something */
static bool may_block(int64_t num, const uint64_t *a)
{
    switch (num) {
    case NR_futex:
        switch (a[1] & 127) {
        case 0:  /* FUTEX_WAIT */
        case 6:  /* FUTEX_LOCK_PI */
        case 9:  /* FUTEX_WAIT_BITSET */
        case 11: /* FUTEX_WAIT_REQUEUE_PI */
        case 12: /* FUTEX_LOCK_PI2 */
            return true;
        }
        return false;
    case NR_futex_waitv: case NR_exit: case NR_sched_yield:
    case NR_nanosleep: case NR_clock_nanosleep: case NR_wait4: case NR_waitid:
    case NR_ppoll: case NR_pselect6: case NR_epoll_pwait:
    case NR_rt_sigsuspend: case NR_rt_sigtimedwait:
        return true;
    }
    return false;
}

/* syscalls whose number of calls may legitimately differ between runs */
static bool sync_syscall(int64_t num)
{
    return num == NR_futex || num == NR_sched_yield;
}

static uint64_t read_reg(struct qemu_plugin_register *h)
{
    g_autoptr(GByteArray) buf = g_byte_array_new();
    uint64_t v = 0;
    if (!qemu_plugin_read_register(h, buf) || !buf->len) {
        die("cannot read register");
    }
    memcpy(&v, buf->data, MIN((size_t)buf->len, sizeof(v)));
    return v;
}

static bool read_guest(uint64_t addr, void *dst, size_t len)
{
    g_autoptr(GByteArray) buf = g_byte_array_new();
    if (!qemu_plugin_read_memory_vaddr(addr, buf, len)) {
        return false;
    }
    memcpy(dst, buf->data, len);
    return true;
}

static char *read_guest_str(uint64_t addr)
{
    GString *s = g_string_new(NULL);
    char c;
    while (s->len < 4096 && read_guest(addr + s->len, &c, 1) && c) {
        g_string_append_c(s, c);
    }
    return g_string_free(s, false);
}

static char *rel_path(const char *path)
{
    /* resolve against the guest cwd, then make relative to the initial cwd */
    g_autofree char *abs = g_path_is_absolute(path) ?
        g_strdup(path) : g_build_filename(cur_cwd, path, NULL);
    g_autofree char *canon = g_canonicalize_filename(abs, NULL);
    size_t n = strlen(init_cwd);
    if (strncmp(canon, init_cwd, n) == 0 && canon[n] == '/') {
        return g_strdup(canon + n + 1);
    }
    return g_steal_pointer(&canon);
}

static void find_registers(void)
{
    g_autoptr(GArray) regs = qemu_plugin_get_registers();
    static const char *gnames[32] = {
        "pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "fp", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
        "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
        "t3", "t4", "t5", "t6",
    };
    static const char *fnames[32] = {
        "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1",
        "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7",
        "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11",
        "ft8", "ft9", "ft10", "ft11",
    };

    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *d =
            &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        for (int r = 0; r < 32; r++) {
            if (!gpr_handle[r] && !strcmp(d->name, gnames[r])) {
                gpr_handle[r] = d->handle;
            }
            if (!fpr_handle[r] && !strcmp(d->name, fnames[r])) {
                fpr_handle[r] = d->handle;
            }
        }
        for (int r = 0; r < 32; r++) {
            char vn[8];
            snprintf(vn, sizeof(vn), "v%d", r);
            if (!vreg_handle[r] && !strcmp(d->name, vn)) {
                vreg_handle[r] = d->handle;
            }
        }
        for (int r = 0; r < VCSR_N; r++) {
            if (!vcsr_handle[r] && !strcmp(d->name, vcsr_names[r])) {
                vcsr_handle[r] = d->handle;
            }
        }
        if (!strcmp(d->name, "fcsr")) {
            fcsr_handle = d->handle;
        } else if (!strcmp(d->name, "fflags")) {
            fflags_handle = d->handle;
        } else if (!strcmp(d->name, "frm")) {
            frm_handle = d->handle;
        }
    }
    for (int r = 0; r < 32; r++) {
        if (!gpr_handle[r] || !fpr_handle[r]) {
            die("register %s/%s not exposed by QEMU", gnames[r], fnames[r]);
        }
    }
    if (!fcsr_handle && !(fflags_handle && frm_handle)) {
        die("fcsr not exposed by QEMU");
    }
    have_vector = vreg_handle[0] != NULL;
    if (have_vector) {
        for (int r = 0; r < 32; r++) {
            if (!vreg_handle[r]) {
                die("vector register v%d not exposed by QEMU", r);
            }
        }
        for (int r = 0; r < VCSR_N; r++) {
            if (!vcsr_handle[r]) {
                die("vector CSR %s not exposed by QEMU", vcsr_names[r]);
            }
        }
    }
}

/* "vector" manifest object: CSRs and v0..v31 as little-endian hex numbers
 * of vlenb bytes (byte 0 = lowest-addressed byte, as vs1r.v stores it). */
static void dump_vector(GString *j)
{
    uint64_t c[VCSR_N];
    for (int r = 0; r < VCSR_N; r++) {
        c[r] = read_reg(vcsr_handle[r]);
    }
    if (c[VCSR_VSTART]) {
        fprintf(stderr, "usp: warning: vstart=%" PRIu64 " at checkpoint\n",
                c[VCSR_VSTART]);
    }
    g_string_append_printf(j, ",\n  \"vector\": {\"vlenb\": %" PRIu64,
                           c[VCSR_VLENB]);
    for (int r = 0; r < VCSR_VLENB; r++) {
        g_string_append_printf(j, ", \"%s\": \"0x%" PRIx64 "\"",
                               vcsr_names[r], c[r]);
    }
    g_string_append(j, ",\n    \"v\": [");
    for (int r = 0; r < 32; r++) {
        g_autoptr(GByteArray) buf = g_byte_array_new();
        if (!qemu_plugin_read_register(vreg_handle[r], buf) ||
            buf->len != c[VCSR_VLENB]) {
            die("cannot read v%d (%u bytes, vlenb %" PRIu64 ")", r, buf->len,
                c[VCSR_VLENB]);
        }
        g_string_append(j, r ? ",\n      \"0x" : "\n      \"0x");
        for (int b = buf->len - 1; b >= 0; b--) {
            g_string_append_printf(j, "%02x", buf->data[b]);
        }
        g_string_append_c(j, '"');
    }
    g_string_append(j, "]}");
}

/* ----------------------------------------------------- syscall handling */

/* nondeterministic syscalls: which arg is the output buffer and its size */
static bool nondet_buffer(int64_t num, const uint64_t *a, int64_t ret,
                          uint64_t *addr, uint32_t *len)
{
    *addr = 0;
    *len = 0;
    switch (num) {
    case NR_getrandom:
        if (ret > 0) {
            *addr = a[0];
            *len = ret;
        }
        return true;
    case NR_clock_gettime:
    case NR_clock_getres:
        if (a[1]) {
            *addr = a[1];
            *len = 16;
        }
        return true;
    case NR_gettimeofday:
        if (a[0]) {
            *addr = a[0];
            *len = 16;
        }
        return true;
    case NR_times:
        if (a[0]) {
            *addr = a[0];
            *len = 32;
        }
        return true;
    case NR_getrusage:
        *addr = a[1];
        *len = 144;
        return true;
    case NR_uname:
        *addr = a[0];
        *len = 390;
        return true;
    case NR_sysinfo:
        *addr = a[0];
        *len = 112;
        return true;
    case NR_sched_getaffinity:
        if (ret > 0) {
            *addr = a[2];
            *len = ret;
        }
        return true;
    case NR_getcpu:
        if (a[0]) {
            *addr = a[0];
            *len = 4;
        }
        return true;
    case NR_getpid:
    case NR_getppid:
    case NR_gettid:
        return true;
    default:
        return false;
    }
}

/* runs on the thread doing the syscall (QEMU's unlock_user) */
static void guest_write(uint64_t addr, uint64_t len)
{
    Range r = { addr, len };
    if (sc_writes) {
        g_array_append_val(sc_writes, r);
    }
}

#define TRACE_MAGIC "USPTRC01"

static void trace_close(Trace *t)
{
    /* header: magic[8], count, start icount, window */
    fseek(t->f, 8, SEEK_SET);
    fwrite(&t->count, 8, 1, t->f);
    fclose(t->f);
    g_free(t->dir);
    g_free(t);
}

static void trace_open(const char *dir, uint64_t icount, unsigned int vcpu)
{
    g_autofree char *path = g_build_filename(dir, "syscalls.bin", NULL);
    Trace *t = g_new0(Trace, 1);
    uint64_t hdr[3] = { 0, icount, window };

    t->f = fopen(path, "wb");
    if (!t->f) {
        die("open %s: %s", path, strerror(errno));
    }
    t->start = icount;
    t->end = icount + window;
    t->vcpu = vcpu;
    t->dir = g_strdup(dir);
    fwrite(TRACE_MAGIC, 8, 1, t->f);
    fwrite(hdr, sizeof(hdr), 1, t->f);
    g_ptr_array_add(traces, t);
}

/*
 * Another thread starts running: the checkpointed thread's trace ends here
 * (the restored program is that thread alone; nothing it could do after
 * this point is in the trace).  The truncation point is left in the
 * checkpoint as "switch" (instructions after the checkpoint), so a window
 * that needs more than that can be rejected.
 */
static void traces_switch(unsigned int vcpu, uint64_t icount)
{
    if (!traces) {
        return;
    }
    for (guint i = 0; i < traces->len;) {
        Trace *t = g_ptr_array_index(traces, i);
        if (t->vcpu != vcpu && icount < t->end) {
            g_autofree char *p = g_build_filename(t->dir, "switch", NULL);
            g_autofree char *s = g_strdup_printf("%" PRIu64 "\n",
                                                 icount - t->start);
            g_file_set_contents(p, s, -1, NULL);
            fprintf(stderr, "usp: thread switch %" PRIu64 " insts after "
                    "checkpoint %s, its trace ends there\n",
                    icount - t->start, t->dir);
            trace_close(t);
            g_ptr_array_remove_index(traces, i);
        } else {
            i++;
        }
    }
}

static void traces_expire(uint64_t icount)
{
    for (guint i = 0; i < traces->len;) {
        Trace *t = g_ptr_array_index(traces, i);
        if (icount >= t->end) {
            trace_close(t);
            g_ptr_array_remove_index(traces, i);
        } else {
            i++;
        }
    }
}

/*
 * Record: icount_rel, num, args[6], ret, nwrites, then per write
 * {addr, len, data padded to 8 bytes}.
 */
static void trace_syscall(unsigned int vcpu, int64_t num, int64_t ret)
{
    uint64_t icount = global_icount();
    g_autoptr(GByteArray) rec = g_byte_array_new();
    uint64_t hdr[10];

    if (num == NR_mmap && ret >= 0 && !(sc_args[3] & 0x20 /* MAP_ANONYMOUS */)) {
        /* file contents arrive by page faults, not syscall writes */
        struct stat st;
        int64_t len = sc_args[1];
        if (fstat(sc_args[4], &st) == 0) {
            len = MIN(len, (int64_t)st.st_size - (int64_t)sc_args[5]);
        }
        if (len > 0) {
            guest_write(ret, len);
        }
    }

    hdr[1] = num;
    memcpy(&hdr[2], sc_args, 6 * 8);
    hdr[8] = ret;
    hdr[9] = sc_writes->len;
    for (guint i = 0; i < traces->len; i++) {
        Trace *t = g_ptr_array_index(traces, i);
        if (icount >= t->end || t->vcpu != vcpu) {
            continue;
        }
        hdr[0] = icount - t->start;
        g_byte_array_set_size(rec, 0);
        g_byte_array_append(rec, (guint8 *)hdr, sizeof(hdr));
        for (guint w = 0; w < sc_writes->len; w++) {
            Range *r = &g_array_index(sc_writes, Range, w);
            uint64_t wh[2] = { r->addr, r->len };
            g_autoptr(GByteArray) data = g_byte_array_new();
            static const uint8_t pad[8];
            if (!qemu_plugin_read_memory_vaddr(r->addr, data, r->len)) {
                die("cannot read syscall output at 0x%" PRIx64, r->addr);
            }
            g_byte_array_append(rec, (guint8 *)wh, sizeof(wh));
            g_byte_array_append(rec, data->data, r->len);
            g_byte_array_append(rec, pad, (8 - r->len % 8) % 8);
        }
        fwrite(rec->data, rec->len, 1, t->f);
        t->count++;
    }
}

static void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu, int64_t num,
                         uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                         uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8)
{
    pthread_mutex_lock(&mtx);
    if (!sc_writes) {
        sc_writes = g_array_new(false, false, sizeof(Range));
    }
    g_array_set_size(sc_writes, 0);
    if (traces && traces->len && (num == NR_exit || num == NR_exit_group)) {
        sc_num = num;
        sc_args[0] = a1;
        trace_syscall(vcpu, num, 0);
    }
    sc_num = num;
    sc_args[0] = a1; sc_args[1] = a2; sc_args[2] = a3; sc_args[3] = a4;
    sc_args[4] = a5; sc_args[5] = a6; sc_args[6] = a7; sc_args[7] = a8;
    thr[vcpu].in_sys = true;
    thr[vcpu].sys_num = num;
    thr[vcpu].sys_since = g_get_monotonic_time();

    switch (num) {
    case NR_clone: case NR_clone3: {
        /* threads (CLONE_VM|CLONE_THREAD) are fine, processes are not */
        uint64_t ca[3] = { a1, 0, 0 };   /* flags, pidfd, child_tid */
        if (num == NR_clone3 && !read_guest(a1, ca, sizeof(ca))) {
            ca[0] = 0;
        }
        if ((ca[0] & 0x10100) != 0x10100) {
            mark_unsupported("fork/vfork (clone without CLONE_VM|CLONE_THREAD)");
            break;
        }
        clone_sigmask = thr[vcpu].sigmask;
        clone_ctid = !(ca[0] & 0x200000 /* CLONE_CHILD_CLEARTID */) ? 0 :
            num == NR_clone ? a5 : ca[2];
        break;
    }
    case NR_execve: case NR_execveat:
        mark_unsupported("exec");
        break;
    case NR_socket:
        mark_live_unsupported("socket");
        break;
    case NR_setitimer: case NR_timer_create:
        mark_unsupported("timers");
        break;
    }
    if (may_block(num, sc_args)) {
        baton_release(vcpu);
    }
    pthread_mutex_unlock(&mtx);
}

/* next log record of this thread, or NULL */
static const SysRec *replay_next(int ord, guint **pos)
{
    GArray *offs;

    if (ord >= (int)rp_off->len) {
        return NULL;
    }
    offs = g_ptr_array_index(rp_off, ord);
    *pos = &g_array_index(rp_pos, guint, ord);
    if (**pos >= offs->len) {
        return NULL;
    }
    return (const SysRec *)(syslog_buf + g_array_index(offs, size_t, **pos));
}

static bool syscall_filter(unsigned int vcpu, int64_t num, const uint64_t *a,
                           uint64_t *sysret)
{
    const SysRec *r;
    guint *pos = NULL;
    uint64_t addr;
    uint32_t len;

    if (!replay_ok) {
        return false;
    }
    /*
     * Each thread's syscalls are matched against its own records.  futex and
     * sched_yield may come and go between runs (lock contention depends on
     * the exact handoff points), so they are skipped on either side.
     */
    r = replay_next(thr[vcpu].ord, &pos);
    while (r && r->num != num && sync_syscall(r->num)) {
        (*pos)++;
        r = replay_next(thr[vcpu].ord, &pos);
    }
    if ((!r || r->num != num) && sync_syscall(num)) {
        return false;
    }
    if (!r && (num == NR_exit || num == NR_exit_group)) {
        return false;   /* exit/exit_group never return, so are not logged */
    }
    if (!r || r->num != num) {
        fprintf(stderr, "usp: replay diverged at syscall #%" PRIu64
                " of thread %d (log: %" PRId64 ", now: %" PRId64
                "), replay disabled\n",
                sys_seq, thr[vcpu].ord, r ? r->num : -1, num);
        replay_ok = false;
        return false;
    }
    (*pos)++;
    sys_seq++;
    if (!nondet_buffer(num, a, r->ret, &addr, &len)) {
        return false;
    }
    if (r->buflen) {
        GByteArray data = { .data = (guint8 *)(r + 1), .len = r->buflen };
        if (!qemu_plugin_write_memory_vaddr(r->bufaddr, &data)) {
            die("replay: cannot write guest memory at 0x%" PRIx64, r->bufaddr);
        }
        guest_write(r->bufaddr, r->buflen);
    }
    *sysret = r->ret;
    return true;
}

static bool vcpu_syscall_filter(qemu_plugin_id_t id, unsigned int vcpu,
                                int64_t num, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5,
                                uint64_t a6, uint64_t a7, uint64_t a8,
                                uint64_t *sysret)
{
    uint64_t a[8] = { a1, a2, a3, a4, a5, a6, a7, a8 };
    bool r;

    pthread_mutex_lock(&mtx);
    r = syscall_filter(vcpu, num, a, sysret);
    pthread_mutex_unlock(&mtx);
    return r;
}

static void log_syscall(unsigned int vcpu, int64_t num, int64_t ret)
{
    SysRec r = { .magic = SYSREC_MAGIC, .num = num, .ret = ret,
                 .thread = thr[vcpu].ord };
    g_autofree uint8_t *buf = NULL;
    uint64_t addr;
    uint32_t len;

    r.icount = global_icount();
    if (nondet_buffer(num, sc_args, ret, &addr, &len) && len && ret >= 0) {
        buf = g_malloc(len);
        if (read_guest(addr, buf, len)) {
            r.buflen = len;
            r.bufaddr = addr;
        }
    }
    fwrite(&r, sizeof(r), 1, syslog_out);
    if (r.buflen) {
        fwrite(buf, r.buflen, 1, syslog_out);
    }
    sys_seq++;
}

static void fd_set_ent(int fd, const char *path, uint64_t flags)
{
    if (fd < 0 || fd >= MAX_FD) {
        mark_live_unsupported("fd number too large");
        return;
    }
    g_free(fds[fd].path);
    fds[fd].path = g_strdup(path);
    fds[fd].flags = flags;
}

static void fd_clear(int fd)
{
    if (fd >= 0 && fd < MAX_FD) {
        g_free(fds[fd].path);
        fds[fd].path = NULL;
    }
}

static void syscall_ret(unsigned int vcpu, int64_t num, int64_t ret)
{
    const uint64_t *a = sc_args;

    if (num != sc_num) {
        die("syscall entry/return mismatch");
    }
    if (syslog_out) {
        log_syscall(vcpu, num, ret);
    }
    if (traces && traces->len) {
        trace_syscall(vcpu, num, ret);
    }

    switch (num) {
    case NR_openat:
        if (ret >= 0) {
            g_autofree char *p = read_guest_str(a[1]);
            g_autofree char *rp = NULL;
            if ((int)a[0] != -100 /* AT_FDCWD */ && !g_path_is_absolute(p)) {
                mark_live_unsupported("openat relative to a directory fd");
            }
            rp = rel_path(p);
            fd_set_ent(ret, rp, a[2]);
        }
        break;
    case NR_close:
        if (ret == 0) {
            fd_clear(a[0]);
        }
        break;
    case NR_dup:
    case NR_dup3:
    case NR_fcntl:
        if (num == NR_fcntl && a[1] != 0 /* F_DUPFD */ &&
            a[1] != 1030 /* F_DUPFD_CLOEXEC */) {
            break;
        }
        if (ret >= 0 && (int)a[0] < MAX_FD) {
            if (fds[a[0]].path) {
                fd_set_ent(ret, fds[a[0]].path, fds[a[0]].flags);
            } else if (a[0] > 2) {
                mark_live_unsupported("dup of unknown fd");
            } else if ((int)ret > 2) {
                mark_live_unsupported("dup of stdio to a new fd");
            }
        }
        break;
    case NR_pipe2:
        if (ret == 0) {
            mark_live_unsupported("pipe");
        }
        break;
    case NR_chdir:
        if (ret == 0) {
            g_autofree char *p = read_guest_str(a[0]);
            g_autofree char *abs = g_path_is_absolute(p) ?
                g_strdup(p) : g_build_filename(cur_cwd, p, NULL);
            g_free(cur_cwd);
            cur_cwd = g_canonicalize_filename(abs, NULL);
        }
        break;
    case NR_fchdir:
        if (ret == 0) {
            mark_live_unsupported("fchdir");
        }
        break;
    case NR_brk:
        if (!brk_start) {
            brk_start = ret;
        }
        brk_cur = ret;
        break;
    case NR_set_tid_address:
        thr[vcpu].tid_address = a[0];
        break;
    case NR_rt_sigaction:
        if (ret == 0 && a[1] && a[0] < 65) {
            SigAct sa;
            if (read_guest(a[1], &sa, sizeof(sa))) {
                sigacts[a[0]] = sa;
            }
        }
        break;
    case NR_rt_sigprocmask:
        if (ret == 0 && a[1]) {
            uint64_t set;
            if (read_guest(a[1], &set, sizeof(set))) {
                switch (a[0]) {
                case 0: thr[vcpu].sigmask |= set; break;          /* SIG_BLOCK */
                case 1: thr[vcpu].sigmask &= ~set; break;         /* SIG_UNBLOCK */
                case 2: thr[vcpu].sigmask = set; break;           /* SIG_SETMASK */
                }
            }
        }
        break;
    case NR_umask:
        umask_val = a[0] & 0777;
        break;
    }
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu,
                             int64_t num, int64_t ret)
{
    pthread_mutex_lock(&mtx);
    /* back to guest code: wait for our turn (no-op if we kept the baton) */
    baton_acquire(vcpu);
    thr[vcpu].in_sys = false;
    syscall_ret(vcpu, num, ret);
    pthread_mutex_unlock(&mtx);
}

/* ------------------------------------------------------- checkpointing */

typedef struct {
    uint64_t start, end;
    int prot;
} Region;

static int collect_region(void *opaque, uint64_t start, uint64_t end, int prot)
{
    GArray *a = opaque;
    Region r = { start, end, prot };
    g_array_append_val(a, r);
    return 0;
}

static const char *prot_str(int prot)
{
    static char s[4];
    s[0] = prot & QEMU_PLUGIN_PROT_READ ? 'r' : '-';
    s[1] = prot & QEMU_PLUGIN_PROT_WRITE ? 'w' : '-';
    s[2] = prot & QEMU_PLUGIN_PROT_EXEC ? 'x' : '-';
    s[3] = 0;
    return s;
}

static bool page_is_zero(const uint8_t *p)
{
    const uint64_t *q = (const uint64_t *)p;
    for (size_t i = 0; i < PAGE / 8; i++) {
        if (q[i]) {
            return false;
        }
    }
    return true;
}

static const char *region_name(const Region *r, uint64_t sp)
{
    if (r->start <= entry_pc && entry_pc < r->end) {
        return "exe";
    }
    if (brk_start && r->start >= brk_start && r->end <= brk_cur + PAGE) {
        return "heap";
    }
    if (r->start <= sp && sp < r->end) {
        return "stack";
    }
    if (r->start <= start_stack && start_stack < r->end) {
        return "stack";
    }
    return "anon";
}

static void hex(GString *j, const char *key, uint64_t v, bool comma)
{
    g_string_append_printf(j, "\"%s\": \"0x%" PRIx64 "\"%s", key, v,
                           comma ? ", " : "");
}

static void json_str(GString *j, const char *s)
{
    g_string_append_c(j, '"');
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') {
            g_string_append_c(j, '\\');
        }
        g_string_append_c(j, *s);
    }
    g_string_append_c(j, '"');
}

static void take_checkpoint(const Point *pt, uint64_t icount, uint64_t pc,
                            unsigned int vcpu)
{
    g_autofree char *dir = g_strdup_printf("%s/ckpt_%" PRIu64, outdir,
                                           pt->interval);
    g_autofree char *mem_path = g_build_filename(dir, "mem.bin", NULL);
    g_autofree char *man_path = g_build_filename(dir, "manifest.json", NULL);
    g_autofree char *files_dir = g_build_filename(dir, "files", NULL);
    g_autoptr(GArray) regions = g_array_new(false, false, sizeof(Region));
    GString *j = g_string_new("{\n");
    uint64_t gpr[32], fpr[32], fcsr, file_off = 0;
    uint64_t start_code = 0, end_code = 0, start_data = 0, end_data = 0;
    FILE *mem;

    if (unsupported) {
        fprintf(stderr, "usp: skip checkpoint %" PRIu64 ": %s\n",
                pt->interval, unsupported_why);
        return;
    }
    if (g_mkdir_with_parents(files_dir, 0755)) {
        die("mkdir %s: %s", files_dir, strerror(errno));
    }
    mem = fopen(mem_path, "wb");
    if (!mem) {
        die("open %s: %s", mem_path, strerror(errno));
    }

    for (int r = 0; r < 32; r++) {
        gpr[r] = read_reg(gpr_handle[r]);
        fpr[r] = read_reg(fpr_handle[r]);
    }
    gpr[0] = pc;
    fcsr = fcsr_handle ? read_reg(fcsr_handle) :
        (read_reg(fflags_handle) | (read_reg(frm_handle) << 5));

    g_string_append(j, "  \"version\": 2, \"arch\": \"riscv64\", "
                    "\"source\": \"qemu-plugin\",\n  ");
    if (live_unsupported) {
        g_string_append_printf(j, "\"live_unsupported\": \"%s\",\n  ", live_why);
    }
    hex(j, "icount", icount, true);
    g_string_append_printf(j, "\"interval\": %" PRIu64 ", \"id\": %d, "
                           "\"weight\": %.9g, \"interval_size\": %" PRIu64
                           ", \"warmup\": %" PRIu64 ",\n  \"cpu\": ",
                           pt->interval, pt->id, pt->weight, interval,
                           pt->interval * interval > icount ?
                           pt->interval * interval - icount : 0);
    json_str(j, cpu_name ? cpu_name : "");
    g_string_append(j, ",\n  \"gpr\": [");
    for (int r = 0; r < 32; r++) {
        g_string_append_printf(j, "\"0x%" PRIx64 "\"%s", gpr[r],
                               r < 31 ? ", " : "");
    }
    g_string_append(j, "],\n  \"fpr\": [");
    for (int r = 0; r < 32; r++) {
        g_string_append_printf(j, "\"0x%" PRIx64 "\"%s", fpr[r],
                               r < 31 ? ", " : "");
    }
    g_string_append(j, "],\n  ");
    hex(j, "fcsr", fcsr, false);
    if (dump_vec) {
        dump_vector(j);
    }
    if (nthreads > 1) {
        /* multi-threaded guest: the image restores this thread only */
        g_string_append_printf(j, ",\n  \"thread\": {\"ordinal\": %d, "
                               "\"live_threads\": %d, \"threads_created\": %d, "
                               "\"switches_before\": %" PRIu64 "}",
                               thr[vcpu].ord, nlive, nthreads, nswitches);
    }

    /* memory */
    if (qemu_plugin_walk_guest_regions(collect_region, regions) < 0) {
        die("guest region walk not supported");
    }
    g_string_append(j, ",\n  \"regions\": [");
    for (guint i = 0; i < regions->len; i++) {
        Region *r = &g_array_index(regions, Region, i);
        const char *name = region_name(r, thr[vcpu].ord ? 0 : gpr[2]);
        bool first_run = true;

        if (!strcmp(name, "exe")) {
            start_code = r->start;
            end_code = r->end;
        } else if (r->start >= end_code && end_code &&
                   (r->prot & QEMU_PLUGIN_PROT_WRITE) && !start_data &&
                   (!brk_start || r->end <= brk_start)) {
            start_data = r->start;
            end_data = r->end;
        }

        g_string_append_printf(j, "%s\n    {", i ? "," : "");
        hex(j, "start", r->start, true);
        hex(j, "end", r->end, true);
        g_string_append_printf(j, "\"prot\": \"%s\", \"name\": \"%s\", "
                               "\"runs\": [", prot_str(r->prot), name);

        if (r->prot & QEMU_PLUGIN_PROT_READ) {
            const uint64_t chunk = 256 * PAGE;
            g_autoptr(GByteArray) buf = g_byte_array_new();
            uint64_t run_start = 0, run_pages = 0;

            for (uint64_t a = r->start; a < r->end; a += chunk) {
                uint64_t n = MIN(chunk, r->end - a);
                g_byte_array_set_size(buf, 0);
                if (!qemu_plugin_read_memory_vaddr(a, buf, n)) {
                    die("cannot read guest memory 0x%" PRIx64, a);
                }
                for (uint64_t off = 0; off < n; off += PAGE) {
                    const uint8_t *pg = buf->data + off;
                    if (page_is_zero(pg)) {
                        if (run_pages) {
                            g_string_append_printf(j, "%s{", first_run ? "" : ", ");
                            hex(j, "vaddr", run_start, true);
                            g_string_append_printf(j, "\"npages\": %" PRIu64 ", ",
                                                   run_pages);
                            hex(j, "file_off", file_off - run_pages * PAGE, false);
                            g_string_append_c(j, '}');
                            first_run = false;
                            run_pages = 0;
                        }
                        continue;
                    }
                    if (!run_pages) {
                        run_start = a + off;
                    }
                    run_pages++;
                    fwrite(pg, PAGE, 1, mem);
                    file_off += PAGE;
                }
            }
            if (run_pages) {
                g_string_append_printf(j, "%s{", first_run ? "" : ", ");
                hex(j, "vaddr", run_start, true);
                g_string_append_printf(j, "\"npages\": %" PRIu64 ", ", run_pages);
                hex(j, "file_off", file_off - run_pages * PAGE, false);
                g_string_append_c(j, '}');
            }
        }
        g_string_append(j, "]}");
    }
    fclose(mem);
    g_string_append(j, "\n  ],\n  \"brk\": {");
    hex(j, "start", brk_start, true);
    hex(j, "cur", brk_cur, false);
    g_string_append(j, "},\n  \"mm\": {");
    hex(j, "start_code", start_code, true);
    hex(j, "end_code", end_code, true);
    hex(j, "start_data", start_data, true);
    hex(j, "end_data", end_data, true);
    hex(j, "start_stack", start_stack, true);
    hex(j, "arg_start", arg_start, true);
    hex(j, "arg_end", arg_end, true);
    hex(j, "env_start", env_start, true);
    hex(j, "env_end", env_end, false);

    /* file descriptors: guest fds are host fds in linux-user */
    g_string_append(j, "},\n  \"fds\": [\n    {\"fd\": 0, \"kind\": \"stdin\"},"
                    " {\"fd\": 1, \"kind\": \"stdout\"},"
                    " {\"fd\": 2, \"kind\": \"stderr\"}");
    for (int fd = 3; fd < MAX_FD; fd++) {
        off_t pos;
        if (!fds[fd].path) {
            continue;
        }
        pos = lseek(fd, 0, SEEK_CUR);
        g_string_append_printf(j, ",\n    {\"fd\": %d, \"kind\": \"file\", "
                               "\"path\": ", fd);
        json_str(j, fds[fd].path);
        g_string_append(j, ", ");
        hex(j, "flags", fds[fd].flags, true);
        hex(j, "offset", pos < 0 ? 0 : pos, false);
        if ((fds[fd].flags & 3) != 0 /* O_RDONLY */) {
            /* written file: store its current contents */
            g_autofree char *rel = g_strdup_printf("files/%d.bin", fd);
            g_autofree char *dst = g_build_filename(dir, rel, NULL);
            g_autofree char *src = g_strdup_printf("/proc/self/fd/%d", fd);
            g_autofree gchar *contents = NULL;
            gsize len = 0;
            if (g_file_get_contents(src, &contents, &len, NULL) &&
                g_file_set_contents(dst, contents, len, NULL)) {
                g_string_append(j, ", \"content\": ");
                json_str(j, rel);
            } else {
                fprintf(stderr, "usp: cannot snapshot fd %d (%s)\n", fd,
                        fds[fd].path);
            }
        }
        g_string_append_c(j, '}');
    }
    g_string_append(j, "\n  ],\n  \"cwd\": ");
    json_str(j, cur_cwd);
    g_string_append(j, ",\n  ");
    hex(j, "umask", umask_val, true);
    hex(j, "tid_address", thr[vcpu].tid_address, true);
    hex(j, "sigmask", thr[vcpu].sigmask, false);
    g_string_append(j, ",\n  \"sigactions\": [");
    {
        bool first = true;
        for (int s = 1; s < 65; s++) {
            if (!sigacts[s].handler) {    /* SIG_DFL */
                continue;
            }
            g_string_append_printf(j, "%s{\"sig\": %d, ", first ? "" : ", ", s);
            hex(j, "handler", sigacts[s].handler, true);
            hex(j, "flags", sigacts[s].flags, true);
            hex(j, "mask", sigacts[s].mask, false);
            g_string_append_c(j, '}');
            first = false;
        }
    }
    g_string_append(j, "]\n}\n");

    if (!g_file_set_contents(man_path, j->str, j->len, NULL)) {
        die("cannot write %s", man_path);
    }
    g_string_free(j, true);
    if (traces) {
        trace_open(dir, icount, vcpu);
    }
    fprintf(stderr, "usp: checkpoint interval %" PRIu64 " at icount %" PRIu64
            " pc 0x%" PRIx64 " (%" PRIu64 " MiB non-zero)\n",
            pt->interval, icount, gpr[0], file_off >> 20);
}

/* ------------------------------------------------- execution callbacks */

static void dump_bbv_interval(void)
{
    GHashTableIter iter;
    void *value;

    fputc('T', bbv_file);
    g_hash_table_iter_init(&iter, bbs);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        Bb *bb = value;
        qemu_plugin_u64 c = qemu_plugin_scoreboard_u64(bb->count);
        uint64_t n = qemu_plugin_u64_sum(c);    /* all threads */
        if (n) {
            fprintf(bbv_file, ":%u:%" PRIu64 " ", bb->index, n);
            for (int v = 0; v < qemu_plugin_num_vcpus(); v++) {
                qemu_plugin_u64_set(c, v, 0);
            }
        }
    }
    fputc('\n', bbv_file);
}

static uint64_t guest_str_end(uint64_t addr)
{
    g_autofree char *s = read_guest_str(addr);
    return addr + strlen(s) + 1;
}

/* record the initial stack layout: argc, argv[], NULL, envp[], NULL, auxv */
static void vcpu_first_tb(unsigned int vcpu, void *udata)
{
    uint64_t sp, argc = 0, p = 0, envp;

    if (seen_first_tb) {
        return;
    }
    seen_first_tb = true;
    sp = read_reg(gpr_handle[2]);
    entry_pc = TB_VADDR(udata);
    start_stack = sp;
    read_guest(sp, &argc, 8);
    if (argc) {
        read_guest(sp + 8, &arg_start, 8);
        read_guest(sp + 8 * argc, &p, 8);
        arg_end = guest_str_end(p);
    }
    envp = sp + 8 * (argc + 2);
    if (read_guest(envp, &env_start, 8) && env_start) {
        uint64_t last = env_start;
        for (uint64_t q = envp; read_guest(q, &p, 8) && p; q += 8) {
            last = p;
        }
        env_end = guest_str_end(last);
    } else {
        env_start = env_end = arg_end;
    }
    /* Vector state is part of the image iff the guest is told it has V
     * (AT_HWCAP).  "xiangshan-kunminghu,v=false" still has a Zve* unit, so
     * QEMU exposes v0-v31, but such captures are meant for V-less builds and
     * must stay restorable on any VLEN. */
    {
        uint64_t q = envp, kv[2];
        while (read_guest(q, &p, 8) && p) {
            q += 8;
        }
        for (q += 8; read_guest(q, kv, 16) && kv[0]; q += 16) {
            if (kv[0] == 16 /* AT_HWCAP */) {
                dump_vec = have_vector && (kv[1] & (1u << ('V' - 'A')));
            }
        }
    }
    while (mode == MODE_CAPTURE && next_point < points->len &&
           g_array_index(points, Point, next_point).at == 0) {
        take_checkpoint(&g_array_index(points, Point, next_point), 0,
                        entry_pc, vcpu);
        next_point++;
    }
}

/* boundary callback: fires at the start of a TB once icount >= boundary */
static void boundary(unsigned int vcpu, void *udata)
{
    uint64_t n_insns = TB_NINSNS(udata);
    uint64_t icount = global_icount();
    uint64_t executed = icount - n_insns;   /* before this TB */

    if (executed < next_boundary) {
        return;      /* boundary falls inside this TB: take it at the next one */
    }
    while (executed >= next_boundary) {
        if (bbv_file) {
            dump_bbv_interval();
        }
        interval_index++;
        next_boundary += interval;
    }
    if (mode == MODE_CAPTURE && next_point < points->len) {
        Point *pt = &g_array_index(points, Point, next_point);
        if (pt->at < interval_index) {
            fprintf(stderr, "usp: missed point %" PRIu64 "\n", pt->interval);
            next_point++;
        } else if (pt->at == interval_index) {
            take_checkpoint(pt, executed, TB_VADDR(udata), vcpu);
            next_point++;
        }
    }
    if (traces) {
        traces_expire(executed);
    }
    if (mode == MODE_CAPTURE && stop_after_last && next_point == points->len) {
        if (!traces || !traces->len) {
            fprintf(stderr, "usp: all checkpoints and windows done\n");
            _exit(0);
        }
    }
    qemu_plugin_u64_set(ctr_u64(), vcpu, icount - next_boundary + BIAS);
}

static void vcpu_boundary(unsigned int vcpu, void *udata)
{
    pthread_mutex_lock(&mtx);
    boundary(vcpu, udata);
    pthread_mutex_unlock(&mtx);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t n = qemu_plugin_tb_n_insns(tb);
    uint64_t vaddr = qemu_plugin_tb_vaddr(tb);

    if (!seen_first_tb) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_first_tb,
                                             QEMU_PLUGIN_CB_R_REGS,
                                             TB_UDATA(vaddr, n));
    }
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, icount_u64(), n);
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, ctr_u64(), n);

    if (bbv_file) {
        Bb *bb = g_hash_table_lookup(bbs, &vaddr);
        if (!bb) {
            bb = g_new(Bb, 1);
            bb->vaddr = vaddr;
            bb->count = qemu_plugin_scoreboard_new(sizeof(uint64_t));
            bb->index = g_hash_table_size(bbs) + 1;
            g_hash_table_insert(bbs, &bb->vaddr, bb);
        }
        qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
            tb, QEMU_PLUGIN_INLINE_ADD_U64,
            qemu_plugin_scoreboard_u64(bb->count), n);
    }

    qemu_plugin_register_vcpu_tb_exec_cond_cb(
        tb, vcpu_boundary,
        mode == MODE_CAPTURE ? QEMU_PLUGIN_CB_R_REGS : QEMU_PLUGIN_CB_NO_REGS,
        QEMU_PLUGIN_COND_GE, ctr_u64(), BIAS, TB_UDATA(vaddr, n));
}

/* ------------------------------------------------------------ lifecycle */

/*
 * Runs on the new thread before it executes guest code (QEMU queues it as
 * vCPU work at creation).  A new thread waits here for its turn.
 */
static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu)
{
    if (vcpu >= MAX_VCPUS) {
        die("too many threads");
    }
    pthread_mutex_lock(&mtx);
    if (nthreads == 0) {
        find_registers();
    } else {
        /* child of the pending clone (thread creation is serialized) */
        thr[vcpu].sigmask = clone_sigmask;
        thr[vcpu].tid_address = clone_ctid;
        if (nthreads == 1) {
            fprintf(stderr, "usp: guest is multi-threaded; threads are "
                    "serialized\n");
        }
    }
    thr[vcpu].live = true;
    thr[vcpu].in_sys = false;
    thr[vcpu].ord = nthreads++;
    nlive++;
    baton_acquire(vcpu);
    pthread_mutex_unlock(&mtx);
}

static void vcpu_exit(qemu_plugin_id_t id, unsigned int vcpu)
{
    pthread_mutex_lock(&mtx);
    thr[vcpu].live = false;
    nlive--;
    baton_release(vcpu);
    pthread_mutex_unlock(&mtx);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    uint64_t icount = global_icount();

    if (traces) {
        traces_expire(UINT64_MAX);
    }

    if (bbv_file) {
        /* trailing partial interval */
        dump_bbv_interval();
        fclose(bbv_file);
    }
    if (syslog_out) {
        fclose(syslog_out);
    }
    if (mode == MODE_PROFILE) {
        g_autofree char *path = g_build_filename(outdir, "profile.json", NULL);
        g_autofree char *s = g_strdup_printf(
            "{\"icount\": %" PRIu64 ", \"interval\": %" PRIu64
            ", \"intervals\": %" PRIu64 ", \"syscalls\": %" PRIu64
            ", \"unsupported\": %s, \"threads\": %d, \"switches\": %" PRIu64
            ", \"serialization_broken\": %s}\n",
            icount, interval, interval_index + 1, sys_seq,
            unsupported ? "true" : "false", nthreads, nswitches,
            serial_broken ? "true" : "false");
        g_file_set_contents(path, s, -1, NULL);
        if (switch_out) {
            fclose(switch_out);
        }
    } else if (next_point < points->len) {
        fprintf(stderr, "usp: guest exited before %u checkpoint(s)\n",
                points->len - next_point);
    }
    fprintf(stderr, "usp: done, %" PRIu64 " instructions\n", icount);
}

static gint cmp_point(gconstpointer a, gconstpointer b)
{
    const Point *x = a, *y = b;
    return x->at < y->at ? -1 : x->at > y->at;
}

static void load_points(void)
{
    g_autofree gchar *s = NULL, *w = NULL;
    g_auto(GStrv) lines = NULL, wlines = NULL;

    points = g_array_new(false, false, sizeof(Point));
    if (!g_file_get_contents(points_path, &s, NULL, NULL)) {
        die("cannot read %s", points_path);
    }
    if (weights_path && !g_file_get_contents(weights_path, &w, NULL, NULL)) {
        die("cannot read %s", weights_path);
    }
    lines = g_strsplit(s, "\n", -1);
    wlines = w ? g_strsplit(w, "\n", -1) : NULL;
    for (int i = 0; lines[i]; i++) {
        Point p = { 0 };
        if (sscanf(lines[i], "%" SCNu64 " %d", &p.interval, &p.id) != 2) {
            continue;
        }
        p.weight = -1;
        p.at = p.interval > warmup_intervals ? p.interval - warmup_intervals : 0;
        for (int k = 0; wlines && wlines[k]; k++) {
            double wt;
            int id;
            if (sscanf(wlines[k], "%lf %d", &wt, &id) == 2 && id == p.id) {
                p.weight = wt;
            }
        }
        g_array_append_val(points, p);
    }
    g_array_sort(points, cmp_point);
    if (!points->len) {
        die("no points in %s", points_path);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        g_auto(GStrv) kv = g_strsplit(argv[i], "=", 2);
        if (!kv[1]) {
            die("bad option %s", argv[i]);
        }
        if (!strcmp(kv[0], "mode")) {
            if (!strcmp(kv[1], "profile")) {
                mode = MODE_PROFILE;
            } else if (!strcmp(kv[1], "capture")) {
                mode = MODE_CAPTURE;
            } else {
                die("bad mode %s", kv[1]);
            }
        } else if (!strcmp(kv[0], "out")) {
            outdir = g_strdup(kv[1]);
        } else if (!strcmp(kv[0], "interval")) {
            interval = g_ascii_strtoull(kv[1], NULL, 0);
        } else if (!strcmp(kv[0], "syslog")) {
            syslog_path = g_strdup(kv[1]);
        } else if (!strcmp(kv[0], "points")) {
            points_path = g_strdup(kv[1]);
        } else if (!strcmp(kv[0], "weights")) {
            weights_path = g_strdup(kv[1]);
        } else if (!strcmp(kv[0], "cpu")) {
            cpu_name = g_strdup(kv[1]);
        } else if (!strcmp(kv[0], "stop")) {
            stop_after_last = atoi(kv[1]);
        } else if (!strcmp(kv[0], "warmup")) {
            warmup_intervals = g_ascii_strtoull(kv[1], NULL, 0);
        } else if (!strcmp(kv[0], "window")) {
            window = g_ascii_strtoull(kv[1], NULL, 0);
        } else {
            die("unknown option %s", kv[0]);
        }
    }
    if (!outdir) {
        die("out=DIR is required");
    }
    if (g_mkdir_with_parents(outdir, 0755)) {
        die("mkdir %s: %s", outdir, strerror(errno));
    }
    init_cwd = g_get_current_dir();
    cur_cwd = g_strdup(init_cwd);
    next_boundary = interval;

    counters = qemu_plugin_scoreboard_new(sizeof(VcpuCounters));

    if (mode == MODE_PROFILE) {
        g_autofree char *p = g_build_filename(outdir, "bbv.bb", NULL);
        bbv_file = fopen(p, "w");
        if (!bbv_file) {
            die("open %s: %s", p, strerror(errno));
        }
        bbs = g_hash_table_new(g_int64_hash, g_int64_equal);
        if (!syslog_path) {
            syslog_path = g_build_filename(outdir, "syscalls.log", NULL);
        }
        syslog_out = fopen(syslog_path, "wb");
        if (!syslog_out) {
            die("open %s: %s", syslog_path, strerror(errno));
        }
        {
            /* global icount, from ordinal, to ordinal of each thread switch */
            g_autofree char *sp = g_build_filename(outdir, "switches.txt", NULL);
            switch_out = fopen(sp, "w");
            if (!switch_out) {
                die("open %s: %s", sp, strerror(errno));
            }
        }
    } else {
        if (!points_path) {
            die("capture needs points=FILE");
        }
        load_points();
        if (window == UINT64_MAX) {
            window = 3 * interval;
        }
        if (window) {
            traces = g_ptr_array_new();
            qemu_plugin_register_guest_write_cb(guest_write);
        }
        if (syslog_path) {
            gsize len;
            if (!g_file_get_contents(syslog_path, (gchar **)&syslog_buf, &len,
                                     NULL)) {
                die("cannot read %s", syslog_path);
            }
            syslog_len = len;
            /* index the records by thread */
            rp_off = g_ptr_array_new();
            rp_pos = g_array_new(false, true, sizeof(guint));
            for (size_t off = 0; off + sizeof(SysRec) <= syslog_len;) {
                const SysRec *r = (const SysRec *)(syslog_buf + off);
                if (r->magic != SYSREC_MAGIC) {
                    die("corrupt syscall log at offset %zu", off);
                }
                while (rp_off->len <= r->thread) {
                    g_ptr_array_add(rp_off,
                                    g_array_new(false, false, sizeof(size_t)));
                }
                g_array_append_val(g_ptr_array_index(rp_off, r->thread), off);
                off += sizeof(SysRec) + r->buflen;
            }
            g_array_set_size(rp_pos, rp_off->len);
            qemu_plugin_register_vcpu_syscall_filter_cb(id, vcpu_syscall_filter);
        } else {
            fprintf(stderr, "usp: no syslog=, nondeterministic syscalls are "
                    "not replayed\n");
        }
    }

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_exit_cb(id, vcpu_exit);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}

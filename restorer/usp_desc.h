/*
 * usimpoint ELFie restorer: binary descriptor layout.
 *
 * Shared contract between tools/usp-mkelf.py (writer) and the restorer stub
 * (reader).  All fields little-endian, naturally aligned.  Offsets marked
 * "desc-relative" are relative to the start of struct usp_desc.  File offsets
 * are offsets in the ELFie file itself (the restorer reads /proc/self/exe).
 *
 * Restorer PT_LOAD segment layout (one RWX segment at VA `base`):
 *
 *   base + 0              restorer blob (text, rodata, data, zeroed bss);
 *                         starts with struct usp_blob_hdr
 *   base + blob_size      struct usp_desc, then regions[], runs[], fds[],
 *                         sigs[], strtab (all inside p_filesz)
 *   ...                   zero fill (p_memsz > p_filesz): restorer stack
 *   base + seg_size       initial restorer stack top (16-byte aligned)
 */
#ifndef USP_DESC_H
#define USP_DESC_H

#include <stdint.h>

#define USP_BLOB_MAGIC 0x52505355u /* "USPR" */
#define USP_DESC_MAGIC 0x44505355u /* "USPD" */
#define USP_DESC_VERSION 3

/* At blob offset 0 (= ELF entry point). */
struct usp_blob_hdr {
	uint32_t jump;       /* "j _start" instruction */
	uint32_t magic;      /* USP_BLOB_MAGIC */
	uint64_t blob_size;  /* bytes, incl. bss, 16-aligned; desc goes here */
	uint64_t stack_size; /* stack bytes the restorer wants after the desc */
};

/* usp_desc.flags */
#define USP_F_HAVE_MM   (1u << 0) /* mm[]/brk valid: call PR_SET_MM_MAP */
#define USP_F_NO_REEXEC (1u << 1) /* don't re-exec with ADDR_NO_RANDOMIZE */
#define USP_F_EAGER     (1u << 2) /* anon mmap + pread for all runs (no file mapping) */
#define USP_F_REPLAY    (1u << 3) /* replay mode: syscalls answered from the trace */
#define USP_F_VECTOR    (1u << 4) /* v0-v31, vl, vtype, vcsr valid: restore V */

struct usp_desc {
	uint32_t magic;        /* USP_DESC_MAGIC */
	uint32_t version;      /* USP_DESC_VERSION */
	uint64_t seg_size;     /* restorer segment memsz; stack top = base+seg_size */
	uint64_t base;         /* segment load VA (as chosen by mkelf) */
	uint64_t flags;        /* USP_F_* */
	uint32_t nregions, nruns, nfds, nsigs;
	uint64_t regions_off;  /* desc-relative */
	uint64_t runs_off;     /* desc-relative */
	uint64_t fds_off;      /* desc-relative */
	uint64_t sigs_off;     /* desc-relative */
	uint64_t strtab_off;   /* desc-relative */
	uint64_t gpr[32];      /* user_regs_struct order: pc, ra, sp, gp, tp, ... */
	uint64_t fpr[32];
	uint64_t fcsr;
	uint64_t sigmask;
	uint64_t umask;
	uint64_t tid_address;
	/* prctl_mm_map order: start_code, end_code, start_data, end_data,
	 * start_brk, brk, start_stack, arg_start, arg_end, env_start, env_end */
	uint64_t mm[11];
	/* replay mode (USP_F_REPLAY) */
	uint64_t trace_file_off; /* syscalls.bin copy in the ELFie (page aligned) */
	uint64_t trace_size;     /* bytes */
	uint64_t trace_va;       /* where the restorer maps it read-only */
	uint64_t replay_brk;     /* initial program break for brk emulation */
	uint64_t seccomp_lo;     /* syscalls with lo <= ip < hi are allowed (restorer) */
	uint64_t seccomp_hi;     /* lo/hi share the same upper 32 bits */
	/* hole where the kernel's own [vvar*]+[vdso] are mremap'ed (both modes),
	 * so mm->context.vdso (signal-return trampoline) stays valid */
	uint64_t kvdso_va;
	uint64_t kvdso_size;
	/* vector state (USP_F_VECTOR); restored through the final rt_sigreturn
	 * frame's RISCV_V_MAGIC extension (struct __riscv_v_ext_state order) */
	uint64_t vstart, vl, vtype, vcsr, vlenb;
	uint64_t vregs_off;    /* desc-relative: v0..v31, vlenb bytes each, memory order */
};

/* usp_region.flags */
#define USP_R_STACK (1u << 0) /* map MAP_GROWSDOWN, fill eagerly (pread) */

struct usp_region {
	uint64_t start, end;  /* page aligned */
	uint32_t prot;        /* PROT_READ=1 | PROT_WRITE=2 | PROT_EXEC=4 */
	uint32_t flags;       /* USP_R_* */
	uint32_t first_run;   /* index into runs[] */
	uint32_t nruns;
};

struct usp_run {
	uint64_t vaddr;       /* page aligned */
	uint64_t npages;
	uint64_t file_off;    /* page-aligned offset in the ELFie file */
};

/* usp_fd.kind */
#define USP_FD_INHERIT 0  /* 0/1/2: keep what the launcher gave us */
#define USP_FD_FILE    1

struct usp_fd {
	int32_t fd;
	uint32_t kind;
	uint32_t flags;       /* open(2) flags as captured (O_TRUNC/O_EXCL ignored) */
	uint32_t mode;        /* creation mode for writable files */
	uint64_t offset;      /* lseek(SEEK_SET) target */
	uint64_t path_off;    /* strtab-relative, NUL terminated */
	uint64_t content_off; /* ELFie file offset of content, ~0 = none */
	uint64_t content_len;
};

struct usp_sig {
	uint64_t sig, handler, flags, mask;
};

#endif

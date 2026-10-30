/* usimpoint restorer entry.  Position independent: only pc-relative refs. */
	.section .text.head, "ax"
	.option norvc
	.globl _blob_start
_blob_start:
	j	_start                      /* usp_blob_hdr.jump */
	.word	0x52505355                  /* usp_blob_hdr.magic "USPR" */
	.quad	_blob_end - _blob_start     /* usp_blob_hdr.blob_size */
	.quad	RESTORER_STACK_SIZE         /* usp_blob_hdr.stack_size */

	.text
	.globl _start
_start:
	mv	a1, sp                      /* initial kernel sp: argc, argv, envp, auxv */
	lla	a0, _blob_end               /* struct usp_desc */
	lla	a2, _blob_start             /* load base */
	ld	t1, 8(a0)                   /* desc->seg_size */
	add	sp, a2, t1
	andi	sp, sp, -16
	li	ra, 0
	li	s0, 0
	call	usp_main
1:	j	1b

/* void usp_sigreturn(void *frame) -- never returns */
	.globl usp_sigreturn
usp_sigreturn:
	mv	sp, a0
	li	a7, 139                     /* __NR_rt_sigreturn */
	ecall
2:	j	2b

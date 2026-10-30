/* Flat, position-independent blob linked at 0 (or any base). */
OUTPUT_ARCH(riscv)
ENTRY(_blob_start)
SECTIONS
{
	. = BLOB_BASE;
	_blob_start_sym = .;
	.text : {
		KEEP(*(.text.head))
		*(.text .text.*)
	}
	.rodata : { *(.rodata .rodata.* .srodata .srodata.*) }
	.data : { *(.data .data.* .sdata .sdata.*) }
	.bss : {
		*(.bss .bss.* .sbss .sbss.* COMMON)
		. = ALIGN(16);
	}
	. = ALIGN(16);
	_blob_end = .;
	/DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.riscv.attributes) }
}

# usimpoint restorer stub: freestanding riscv64 blob, position independent.
# Output: build/restorer.bin (flat, linked at 0) consumed by tools/usp-mkelf.py.
CROSS ?= riscv64-linux-gnu-
CC := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy
READELF := $(CROSS)readelf
STACK_SIZE ?= 0x10000

CFLAGS := -march=rv64gc -mabi=lp64d -mcmodel=medany -fno-pic -fno-pie \
	-ffreestanding -fno-builtin -nostdlib -fno-stack-protector \
	-fno-jump-tables -fno-tree-loop-distribute-patterns \
	-fno-asynchronous-unwind-tables -fno-unwind-tables \
	-mno-relax -Os -Wall -Wextra -Werror -Wno-unused-parameter \
	-DRESTORER_STACK_SIZE=$(STACK_SIZE)
LDFLAGS := -nostdlib -static -no-pie -Wl,--no-relax -Wl,--build-id=none -Wl,--no-warn-rwx-segments

B := build
SRCS := start.S restorer.c

all: $(B)/restorer.bin

$(B)/restorer-%.elf: $(SRCS) usp_desc.h restorer.ld | $(B)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--defsym=BLOB_BASE=$* -T restorer.ld -o $@ $(SRCS)

# Build at two different bases; identical flat images prove there are no
# absolute addresses baked into the blob (position independence).
$(B)/restorer.bin: $(B)/restorer-0x0.elf $(B)/restorer-0x12345000.elf
	$(OBJCOPY) -O binary $(B)/restorer-0x0.elf $@
	$(OBJCOPY) -O binary $(B)/restorer-0x12345000.elf $(B)/check.bin
	cmp $@ $(B)/check.bin
	@if $(READELF) -S $(B)/restorer-0x0.elf | grep -Eq '\.(got|rela|dynamic|interp)'; then \
		echo "restorer: unexpected GOT/relocation sections"; exit 1; fi
	@if $(READELF) -r $(B)/restorer-0x0.elf | grep -q 'Relocation section'; then \
		echo "restorer: unexpected relocations"; exit 1; fi
	@echo "restorer.bin: $$(stat -c %s $@) bytes, position independent OK"

$(B):
	mkdir -p $@

clean:
	rm -rf $(B)

.PHONY: all clean

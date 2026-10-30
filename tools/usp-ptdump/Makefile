# Build natively on riscv64 (K3), or cross: make CC=riscv64-linux-gnu-gcc
CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
usp-ptdump: usp-ptdump.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f usp-ptdump
.PHONY: clean

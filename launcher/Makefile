# Cross:  make CC=riscv64-linux-gnu-gcc     (static riscv64 binary)
# Native: make                               (e.g. on the K3)
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?= -static

usp-run: usp-run.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f usp-run

.PHONY: clean

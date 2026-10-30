QEMU_SRC ?= ../../third_party/qemu
CFLAGS ?= -O2 -g -Wall
CFLAGS += -fPIC -I$(QEMU_SRC)/include/plugins $(shell pkg-config --cflags glib-2.0)
LDLIBS += $(shell pkg-config --libs glib-2.0)

libusp.so: usp.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDLIBS)

clean:
	rm -f libusp.so

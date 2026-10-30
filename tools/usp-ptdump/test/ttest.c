/* Restore smoke test: deterministic output that depends on heap (brk growth),
 * FP state, file reads at an offset, an output file written while running,
 * a signal handler and stdio buffers.  Build: gcc -O2 -static -o ttest ttest.c -lm */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int got_usr1;
static void on_usr1(int s) { got_usr1++; }

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 40;
	FILE *in = fopen(argc > 2 ? argv[2] : "ttest.c", "r");
	FILE *out = fopen("ttest.out", "w");
	unsigned long h = 1469598103934665603UL;
	double acc = 0.5;
	char line[256];
	if (!in || !out) {
		perror("open");
		return 1;
	}
	signal(SIGUSR1, on_usr1);
	for (long it = 0; it < iters; it++) {
		/* brk growth: allocate and keep chunks of increasing size */
		size_t sz = 4096 * (it % 97 + 1);
		unsigned char *p = malloc(sz);
		for (size_t i = 0; i < sz; i++)
			p[i] = (unsigned char)(i * it + h);
		for (long r = 0; r < 2000000; r++) { /* compute */
			h = (h ^ p[r % sz]) * 1099511628211UL;
			acc = acc * 1.0000001 + (double)(h & 0xff) * 1e-9;
		}
		if (it % 3 == 0)
			free(p);
		/* file read: one line per iteration, wrap around */
		if (!fgets(line, sizeof(line), in)) {
			rewind(in);
			fgets(line, sizeof(line), in);
		}
		for (char *c = line; *c; c++)
			h = (h ^ (unsigned char)*c) * 1099511628211UL;
		fprintf(out, "it %ld h %016lx acc %.17g pos %ld\n", it, h, acc, ftell(in));
		if (it % 8 == 0)
			fflush(out);
		printf("it %ld\n", it);
		fflush(stdout);
	}
	raise(SIGUSR1);
	fprintf(out, "done h %016lx acc %.17g usr1 %d brk %p\n", h, acc, got_usr1, (void *)0);
	fclose(out);
	printf("ok %016lx\n", h);
	return 0;
}

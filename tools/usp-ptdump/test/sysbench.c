/* Replay overhead micro-benchmark: spin ~0.5 s, then N raw getppid ecalls with
 * fixed a0..a5 = 0, then raw exit_group(0).  Pair with mksystrace.py. */
#include <stdlib.h>
static long raw(long n, long a0)
{
	register long r0 __asm__("a0") = a0;
	register long r1 __asm__("a1") = 0, r2 __asm__("a2") = 0, r3 __asm__("a3") = 0;
	register long r4 __asm__("a4") = 0, r5 __asm__("a5") = 0, r7 __asm__("a7") = n;
	__asm__ volatile("ecall" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r7) : "memory");
	return r0;
}
int main(int argc, char **argv)
{
	long n = atol(argv[1]);
	volatile unsigned long x = 0;
	for (unsigned long i = 0; i < 400000000UL; i++)
		x += i;
	long s = 0;
	for (long i = 0; i < n; i++)
		s += raw(173 /* getppid */, 0);
	raw(94 /* exit_group */, s == 42 * n ? 0 : 1);
	return 2;
}

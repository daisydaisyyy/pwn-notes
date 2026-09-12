#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(int a, int b, int c) {
	if (
		a != 0xdeadbeef ||
		b != 0xcafebabe ||
		c != 0x0badf00d
	) {
		return;
	}

	char* binsh = "/bin/sh";
	char* args[] = {binsh, NULL};
	char* env[] = {NULL};
	asm("syscall" : : "a"(0x3b), "D"(binsh), "S"(args), "d"(env));
}

void __attribute__((unused)) __attribute__((naked)) gadget() {
	asm("pop rax; ret;");
}

void (*why_am_i_here)(int, int, int) = win;

int main () {
	char buf[64];
	read(0, buf, 512);
	return 0;
}

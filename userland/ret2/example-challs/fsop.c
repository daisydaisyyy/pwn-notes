#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

void print(const char* s) {
	write(STDOUT_FILENO, s, strlen(s));
}

char* buf;
int main ()
{
	buf = malloc(0x10);
	if (buf == NULL) err(1, "malloc");
	FILE* fp = fopen("./foo", "r+");
	if (fp == NULL) err(1, "fopen");

	while (1) {
		print("1. read\n");
		print("2. write\n");
		print("3. overflow\n");
		print("4. exit\n");

		print("> ");
		char choice_buf[0x10] = "";
		if (read(STDIN_FILENO, choice_buf, 0xf) <= 0) err(-1, "read");
		int choice = atoi(choice_buf);
		switch (choice) {
			case 1:
				char rbuf[0x100] = "";
				fread(rbuf, 1, 0x10, fp);
				write(STDOUT_FILENO, rbuf, 0x10);
				break;
			case 2:
				char wbuf[0x100] = "";
				print("buf: ");
				read(STDIN_FILENO, wbuf, 0x10);
				fwrite(wbuf, 1, 0x10, fp);
				break;
			case 3:
				print("buf: ");
				read(STDIN_FILENO, buf, 0x200);
				break;
			case 4:
				return 0;
			default:
				err(-1, "invalid choice");
		}
	}
}

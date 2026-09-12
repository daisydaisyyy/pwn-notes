#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "mymalloc.h"

#define MAX_INDEX	1000
#define MAX_SIZE	1024

#define MALLOC		'm'
#define REALLOC		'r'
#define FREE		'f'
#define OVERFLOW	'o'


int main(void)
{
	void *allocated[MAX_INDEX] = {NULL};
	char action;
	unsigned int index, size;
	int one_shot = 0;

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	printf("Welcome to mymalloc, the hardened allocator.\n" /* *cough* */
	       "Format: action:index:size\n"
		   "Actions:\n"
		   "    m - malloc\n"
		   "    r - realloc\n"
		   "    f - free\n"
		   "    o - overflow\n\n");

	while (1)
	{
		printf(COLOR_GREEN "> " COLOR_RESET);

		if (scanf("%c:%u:%u", &action, &index, &size) != 3) {
			printf("invalid format, expected "
				   COLOR_RED "[mrfo]:index:size\n" COLOR_RESET);
			exit(EXIT_FAILURE);
		}
		getc(stdin); /* eat newline */

		if (index >= MAX_INDEX || size >= MAX_SIZE) {
			printf("Bad arguments\n");
			exit(EXIT_FAILURE);
		}

		switch (action) {
			case MALLOC :
				if (allocated[index]) {
					printf("Memory leak :(\n");
					exit(EXIT_FAILURE);
				} else {
					allocated[index] = mymalloc(size);
					printf("%04u : malloc(%u) = %p\n", index, size, allocated[index]);;
				}
				break;

			case REALLOC :
				printf("%04u : realloc(%p, %u) = ", index, allocated[index], size);
				allocated[index] = myrealloc(allocated[index], size);
				printf("%p\n", allocated[index]);
				break;

			case FREE :
				printf("%04u : free(%p)\n", index, allocated[index]);
				myfree(allocated[index]);
				allocated[index] = NULL;
				break;

			case OVERFLOW :
				if (one_shot) {
					printf("Sorry, you only have one shot ;)\n");
					exit(EXIT_FAILURE);
				} else {
					one_shot = 1;
					printf("%04u : overflow (%p)\n", index, allocated[index]);
					gets(allocated[index]);
				}
				break;

			default :
				printf("Unknow action %c\n", action);
				exit(EXIT_FAILURE);
		}
	}

	return EXIT_SUCCESS;
}

/*
 *  Dummy (and buggy :s) first-fit malloc implementation
 * 	Largely copied from this link :
 * 		http://wiki-prog.kh405.net/images/0/04/Malloc_tutorial.pdf
 */

/* -- Includes ------------------------------------------------------ */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "mymalloc.h"

/* -- Private variables --------------------------------------------- */

static heap_t heap = {NULL, NULL, 0, 0};

/* Private functions ------------------------------------------------ */

static segment_p create_new_segment(size_t size, segment_p last);

static __inline__ unsigned int rdtsc()
{
	unsigned int lo, hi;
	__asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));

	return lo ^ hi;
}

static void heap_kill(char * err_msg)
{
	fprintf(stderr, COLOR_RED "************ Heap Corruption detected ************\n" COLOR_RESET);
	fprintf(stderr, COLOR_RED "* %s\n" COLOR_RESET, err_msg);
	fprintf(stderr, COLOR_RED "**************************************************\n" COLOR_RESET);

	exit(EXIT_FAILURE);
}

static void generate_hash(segment_p seg)
{
	seg->index = heap.count++;
	seg->hash = rand();
	heap.hash_table[seg->index] = seg->hash;
}

static void extend_hash_table()
{
	int * tmp = NULL;
	segment_p hash_seg;

	srand(rdtsc());
	heap.max += HASH_TABLE_DELTA;

	if (!heap.hash_table) {
		hash_seg = create_new_segment(heap.max * sizeof(int), heap.segments);
		heap.segments = hash_seg;
		tmp = (int *)DATA(hash_seg);

		if (tmp) {
			heap.hash_table = tmp;
			generate_hash(hash_seg);
		} else {
			heap_kill("Somebody calls the police, hashtable is pretty much f*cked up !");
		}
	} else {
		tmp = myrealloc(heap.hash_table, heap.max * sizeof(int));

		if (tmp) {
			heap.hash_table = tmp;
		} else {
			heap_kill("Somebody calls the police, hashtable is pretty much f*cked up !");
		}
	}
}

static bool check_dat_hash_baby(segment_p seg)
{
	if (seg->index >= heap.max) {
		return false;
	}

	if (heap.hash_table[seg->index] != seg->hash) {
		return false;
	}

	return true;
}

static void validate_address_or_die(void *ptr)
{
	char *err_msg = NULL;

	if (!heap.segments || !heap.hash_table) {
		err_msg = "Malloc internals not even initialized mofo !";
	} else if (ptr < (void *)heap.segments || ptr > sbrk(0)) {
		err_msg = "Out of bounds monkey-ball-licker !";
	} else if (INDEX(ptr) >= heap.count) {
		err_msg = "i'll break ya neck";
	} else if (!check_dat_hash_baby(SEGMENT(ptr))) {
		err_msg = "Hide that big fat hash from me :@";
	} else if (PREVIOUS(ptr) && PREVIOUS(ptr)->next != SEGMENT(ptr)) {
		err_msg = "The backward link is broken sir !";
	} else if (PREVIOUS(ptr) && (segment_p)((char *)DATA(PREVIOUS(ptr)) + PREVIOUS(ptr)->size) != SEGMENT(ptr)) {
		err_msg = "Black hole in the space-time-memory continuum";
	} else if (NEXT(ptr) && NEXT(ptr)->previous != SEGMENT(ptr)) {
		err_msg = "Can I haz forward link pliz ?";
	} else if (NEXT(ptr) && (segment_p)((char *)ptr + SIZE(ptr)) != NEXT(ptr)) {
		err_msg = "Size : yes it does matters...";
	}

	if (err_msg) {
		heap_kill(err_msg);
	}
}

static segment_p create_new_segment(size_t size, segment_p last)
{
	segment_p new = sbrk(0);

	if (sbrk(SEGMENT_SIZE + size) == (void *) - 1) {
		return NULL;
	} else {
		new->hash = 0;
		new->index = 0;
		new->flags = INIT_FLAGS;
		SET_INUSE(new);

		new->size = size;
		new->next = NULL;
		new->previous = last;

		if (last) {
			last->next = new;
		}

		return new;
	}
}

static segment_p find_segment(size_t size, segment_p *position)
{
	segment_p cursor = heap.segments;
	*position = NULL;

	while (cursor && (IS_INUSE(cursor) || cursor->size < size)) {
		*position = cursor;
		cursor = cursor->next;
	}

	return cursor;
}

static void split_segment(segment_p seg, size_t size)
{
	segment_p new;

	if (seg && seg->size > size + MIN_ALLOC) {
		new = (segment_p)(DATA(seg) + size);

		generate_hash(new);

		new->flags = INIT_FLAGS;
		SET_FREE(new);

		new->size = seg->size - SEGMENT_SIZE - size;
		seg->size = size;

		new->next = seg->next;
		if (new->next) {
			new->next->previous = new;
		}

		new->previous = seg;
		seg->next = new;
	}
}

static segment_p merge_segment_with_next(segment_p seg)
{
	if (seg && seg->next && IS_FREE(seg->next) && NOT_OVERFLOW(seg->size, SEGMENT_SIZE+seg->next->size)) {
		seg->size += SEGMENT_SIZE + seg->next->size;
		seg->next = seg->next->next;

		if (seg->next) {
			seg->next->previous = seg;
		}
	}

	return seg;
}

/* -- Public functions ---------------------------------------------- */

void *mymalloc(size_t size)
{
	segment_p seg, position;
	size = ALIGN(size);
	size = MAX(size, MIN_SIZE);

	if (heap.count >= heap.max) {
		extend_hash_table();
	}

	if (heap.segments) {
		seg = find_segment(size, &position);

		if (seg) {
			SET_INUSE(seg);
			if (seg->size >= size + MIN_ALLOC)
				split_segment(seg, size);
		} else {
			seg = create_new_segment(size, position);
			generate_hash(seg);
		}
	} else {
		seg = create_new_segment(size, heap.segments);
		generate_hash(seg);
	}

	return seg ? (void *)DATA(seg) : NULL;
}

void myfree(void *ptr)
{
	segment_p seg;

	if (ptr) {
		validate_address_or_die(ptr);

		seg = SEGMENT(ptr);
		SET_FREE(seg);

		if (seg->previous && IS_FREE(seg->previous)) {
			seg = merge_segment_with_next(seg->previous);
		}

		if (seg->next && IS_FREE(seg->next)) {
			seg = merge_segment_with_next(seg);
		}

		if (!seg->next) {
			if (seg->previous) {
				seg->previous->next = NULL;
			} else {
				heap.segments = NULL;
			}
			brk(seg);
		}
	}
}

void *mycalloc(size_t nmemb, size_t size)
{
	char * new = NULL;
	size_t i, total = nmemb * size;

	if (nmemb > 0 && size > 0 && total / nmemb == size) {
		new = (char *)mymalloc(total);

		if (new) {
			for (i = 0; i < total; i++) {
				new[i] = 0;
			}
		}
	}

	return new;
}

void *myrealloc(void *ptr, size_t size)
{
	segment_p seg = NULL;
	void * ret = NULL;

	if (ptr) {
		validate_address_or_die(ptr);
		seg = SEGMENT(ptr);

		if (size == 0) {
			/* if size is equal to zero, the call is equivalent to free(ptr). */
			/* [and] either NULL or a pointer suitable to be passed to free() is returned. */
			myfree(ptr);
			ret = NULL;
		} else {
			size = ALIGN(size);

			if (size > seg->size)
			{
				if (seg->next && IS_FREE(seg->next) && seg->size + seg->next->size >= size) {
					seg = merge_segment_with_next(seg);
					if (seg->size >= size + MIN_ALLOC) {
						split_segment(seg, size);
					}
					ret = DATA(seg);
				} else {
					ret = mymalloc(size);
					if (ret) {
						memcpy(ret, DATA(seg), seg->size);
						myfree(ptr);
					}
				}
			} else {
				if (seg->size >= size + MIN_ALLOC) {
					split_segment(seg, size);
				}
				ret = DATA(seg);
			}
		}
	} else {
		/* If ptr is NULL, the call is equivalent to malloc(size); */
		ret = mymalloc(size);
	}

	return ret;
}


/* -- Debug Functions ------------------------------------------------*/

void print_segment(segment_p seg)
{
	printf("\t-> segment : %p\n", (void *)seg);

	if (DATA(seg) == (void *)heap.hash_table) {
		printf("\t\t- Hash Table\n");
	}

	printf("\t\t- hash : %x (hash_table[%d] = %x)\n",
		   seg->hash, seg->index,
		   (seg->index <= heap.count ? (unsigned int)heap.hash_table[seg->index] : 0xcafebabe));
	printf("\t\t- index : %u (%#x)\n", seg->index, seg->index);
	printf("\t\t- flags : %#x (IN_USE = %d)\n", seg->flags, IS_INUSE(seg));
	printf("\t\t- previous : %p\n", (void *)seg->previous);
	printf("\t\t- next : %p\n", (void *)seg->next);
	printf("\t\t- size : %u (%#x)\n", seg->size, seg->size);
	printf("\t\t- data : from %p to %p\n", DATA(seg), (DATA(seg) + seg->size));
}

void print_heap()
{
	segment_p cursor = heap.segments;

	printf("> Heap start : %p\n", (void *)cursor);
	printf("> Heap limit : %p\n", (void *)sbrk(0));
	printf("> Heap print : \n");

	while (cursor) {
		print_segment(cursor);
		cursor = cursor->next;
	}

	printf("> Done\n");
}

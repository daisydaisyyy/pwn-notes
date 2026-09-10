/* -- Includes ------------------------------------------------------ */
#include <stddef.h>


/* -- Types --------------------------------------------------------- */
typedef unsigned int size_t;

typedef enum { false = 0, true = 1 } bool;

typedef struct segment_s {
	int hash;
	size_t index;
	int flags;
	struct segment_s *previous, *next;
	size_t size;
} segment_t, *segment_p;


typedef struct heap_s {
	segment_p segments;
	int *hash_table;
	size_t max, count;
} heap_t, *heap_p;


/* -- Macros -------------------------------------------------------- */
#ifdef MAKELIB
	#define mymalloc	malloc
	#define myfree		free
	#define myrealloc	realloc
	#define mycalloc	calloc
#endif

#define INIT_FLAGS         0

#define INUSE_FLAG         0
#define SOME_FLAG          1
#define OTHER_FLAG         2
#define CAPTURE_THE_FLAG   4

#define TEST_FLAG(f,i)     ((f) & (1 << i))
#define SET_FLAG(f,i)      f |= (1 << i)
#define CLEAR_FLAG(f,i)	   f &= ~(1 << i)

#define MAX(a,b)           (((a) > (b)) ? (a) : (b))
#define NOT_OVERFLOW(a,b)  (((a) + (b)) > MAX(a, b))
#define ALIGN(x)           (((((x) - 1) / 4) * 4) + 4)

#define SEGMENT_SIZE       sizeof(segment_t)
#define MIN_SIZE           4
#define MAX_ALLOC          (1024 * 1024 * 100)
#define MIN_ALLOC          (SEGMENT_SIZE + MIN_SIZE)
#define HASH_TABLE_DELTA   100

#define SEGMENT(p)         ((segment_p)(((char *)(p)) - SEGMENT_SIZE))
#define DATA(p)            ((char *)(p) + SEGMENT_SIZE)

#define PREVIOUS(p)        (((segment_p)(SEGMENT(p)))->previous)
#define NEXT(p)            (((segment_p)(SEGMENT(p)))->next)
#define SIZE(p)            (((segment_p)(SEGMENT(p)))->size)
#define INDEX(p)           (((segment_p)(SEGMENT(p)))->index)

#define IS_INUSE(p)        TEST_FLAG(((segment_p)(p))->flags, INUSE_FLAG)
#define IS_FREE(p)         !IS_INUSE(p)
#define SET_INUSE(p)       SET_FLAG(((segment_p)(p))->flags, INUSE_FLAG)
#define SET_FREE(p)        CLEAR_FLAG(((segment_p)(p))->flags, INUSE_FLAG)

#define COLOR_RED     "[0;31m"
#define COLOR_GREEN   "[0;32m"
#define COLOR_RESET   "[0;00m"

/* -- Protoypes ----------------------------------------------------- */
void *mymalloc(size_t size);
void *mycalloc(size_t nmemb, size_t size);
void *myrealloc(void *ptr, size_t size);
void myfree(void *ptr);

void print_segment(segment_p seg);
void print_heap();

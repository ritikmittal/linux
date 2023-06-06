/*
 * mm.c
 *
 * Name: [FILL IN]
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 * Also, read malloclab.pdf carefully and in its entirety before beginning.
 *
 */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include "mm.h"
#include "memlib.h"

/*
 * If you want to enable your debugging output and heap checker code,
 * uncomment the following line. Be sure not to have debugging enabled
 * in your final submission.
 */
// #define DEBUG

#ifdef DEBUG
// When debugging is enabled, the underlying functions get called
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#else
// When debugging is disabled, no code gets generated
#define dbg_printf(...)
#define dbg_assert(...)
#endif // DEBUG

// do not change the following!
#ifdef DRIVER
// create aliases for driver tests
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#define memset mm_memset
#define memcpy mm_memcpy
#endif // DRIVER

#define ALIGNMENT 16

// rounds up to the nearest multiple of ALIGNMENT
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}

/*
 * mm_init: returns false on error, true on success.
 */
int cur_sz;
int filled_upto;
int int_ptr_sz;
void * base;
bool mm_init(void)
{
    // IMPLEMENT THIS
    cur_sz = 10;
    filled_upto = 0;
    base = mm_sbrk(cur_sz);
    int_ptr_sz = sizeof(int *);
    return true;
}

/*
 * malloc
 */
void * put_size(void * ptr, int sz) {
    int * vp = (int *)ptr;
    *vp = sz;
    return ptr + int_ptr_sz;
}

int get_size(void * ptr) {
    int * vp = (int *)ptr;
    vp--;
    return *vp;
}

void* malloc(size_t size)
{
    // IMPLEMENT THIS
    size += int_ptr_sz;
    if(size + filled_upto > cur_sz) {
        cur_sz *= 2;
        base = mm_sbrk(cur_sz);
    }
    filled_upto += size;
    return put_size(base + filled_upto - size, size - int_ptr_sz);
}

/*
 * free
 */
void free(void* ptr)
{
    // IMPLEMENT THIS
    return;
}


/*
 * realloc
 */
void* realloc(void* oldptr, size_t size)
{
    // IMPLEMENT THIS
    size += int_ptr_sz;
    if(size + filled_upto > cur_sz) {
        cur_sz *= 2;
        base = mm_sbrk(cur_sz);
    }
    filled_upto += size;
    void * ret =  put_size(base + filled_upto - size, size - int_ptr_sz);
    memcpy(ret, oldptr, get_size(oldptr));    
    return ret;
}

/*
 * calloc
 * This function is not tested by mdriver, and has been implemented for you.
 */
void* calloc(size_t nmemb, size_t size)
{
    void* ptr;
    size *= nmemb;
    ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

/*
 * Returns whether the pointer is in the heap.
 * May be useful for debugging.
 */
static bool in_heap(const void* p)
{
    return p <= mm_heap_hi() && p >= mm_heap_lo();
}

/*
 * Returns whether the pointer is aligned.
 * May be useful for debugging.
 */
static bool aligned(const void* p)
{
    size_t ip = (size_t) p;
    return align(ip) == ip;
}

/*
 * mm_checkheap
 * You call the function via mm_checkheap(__LINE__)
 * The line number can be used to print the line number of the calling
 * function where there was an invalid heap.
 */
bool mm_checkheap(int line_number)
{
#ifdef DEBUG
    // Write code to check heap invariants here
    // IMPLEMENT THIS
#endif // DEBUG
    return true;
}
/*
 * mm.c
 *
 * Name: Yousef alRabiah
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 * Also, read the README carefully and in its entirety before beginning.
 *
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//#include <math.h>

#include "memlib.h"
#include "mm.h"

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

//checklist:
//linked list struct address of the free block, size, next and prev pointers
//write linked list with supporting functions insert, delete, find
//write split and coalese
//malloc

//struct
// metadata
typedef struct header {
  size_t size;
  struct header *next;
} header_t;
// footer
typedef struct footer {
  size_t size;
  struct header *prev;
} footer_t;

#define ALIGNMENT 16
#define EXTRA_SIZE (1 << 12) - sizeof(header_t) - sizeof(footer_t)

//header_t **head_ref;
header_t *head[6];
header_t *tail[6];

// declare prologue
header_t *prologue;
//header_t *head = NULL;
header_t **head_ref = head;
header_t **tail_ref = tail;

size_t max(size_t a, size_t b) { return a > b ? a : b; }
size_t min(size_t a, size_t b) { return a < b ? a : b; }
/*
 * Returns whether the pointer is in the heap.
 * May be useful for debugging.
 */
static bool in_heap(const void *p)
{
  return p <= mm_heap_hi() && p >= mm_heap_lo();
}

// rounds up to the nearest multiple of ALIGNMENT
static size_t align(size_t x)
{
  return ALIGNMENT * ((x + ALIGNMENT - 1) / ALIGNMENT);
}

/*
 * Returns whether the pointer is aligned.
 * May be useful for debugging.
 */
static bool aligned(const void *p)
{
  size_t ip = (size_t) p;
  return align(ip) == ip;
}

//insert functions

// get size
size_t get_size(size_t size) {
  // last two bits are used, so shift right, then shift left
  return ((size >> 1) << 1);
}

// check if block is free
bool is_free(header_t *header) {
  if (header) {
    // need to look at the last bit of header->size
    // xxxxxxb2b1
    // can and with 1 (000000000000000001)
    if ((header->size & 1) == 0)
      return true;
    else
      return false;
  }
  return false;
}

  // toggle the allocated bit of a given header
  void toggle_alloc(header_t * header) {
    if (header) {
      header->size = (header->size ^ 1);
    }
  }

// get footer address from a given header address (pointer)
footer_t *get_footer(header_t *header) {
  if (header) {
    if (in_heap((void *)(((char *)((char *)header + sizeof(header_t)) +
                          get_size(header->size))))) {
      //      {footer_t *ft_address = (footer_t *)((
      //        (char *)((char *)header + sizeof(header_t)) + header->size));
      footer_t *ft_address =
          (footer_t *)((char *)header + sizeof(header_t) + get_size(header->size));
      return ft_address;
    } else
      return NULL;
  } else
    return NULL;
}

// get next block address
header_t *get_next(header_t *curr) {
  if (curr) {
    footer_t *ft_address = get_footer(curr);
    if (!in_heap((void *)((char *)((char *)ft_address + sizeof(footer_t)) +
                          sizeof(header_t))))
      return NULL;
    else {
      header_t *next_block =
          (header_t *)((char *)ft_address + sizeof(footer_t));
      return next_block;
    }
  } else
    return NULL;
}

// get prev block address
header_t *get_prev(header_t *curr) {
  if (curr) {
    if (!in_heap((void *)((char *)curr - sizeof(footer_t))))
      return NULL;
    else {
      footer_t *prev_footer = (footer_t *)((char *)curr - sizeof(footer_t));
      if (prev_footer) {
        size_t prev_blk_size = get_size(prev_footer->size);
        if (!in_heap((void *)((char *)((char *)prev_footer - prev_blk_size) -
                              sizeof(header_t))))
          return NULL;
        else
          return (header_t *)((char *)((char *)prev_footer - prev_blk_size) -
                              sizeof(header_t));
      } else
        return NULL;
    }
  } else
    return NULL;
}

int bestList(size_t req_size) {
      // given a size, find the appropriate free list to search this block in
      if (req_size == 0)
        return 0;
      else if (req_size <= 128)
        return 1;
      else if (req_size <= 512)
        return 2;
      else if (req_size <= 2048)
        return 3;
      else if (req_size <= 8192)
        return 4;
      else
        return 5;
}

void insertNode(header_t **head_ref, header_t **tail_ref, header_t *node) {
  // look at the size of the block and put it at the tail of the appropriate
  // free list
  int index = bestList(node->size);
  node->next = NULL;
  footer_t *footer = get_footer(node);
  footer->prev = NULL;

  if (*(head_ref + index) == NULL) {
    *(head_ref + index) = node;
    *(tail_ref + index) = node;
  } else {
    header_t *tail_f = *(tail_ref + index);
    if (tail_f){
      tail_f->next = node;
      footer->prev = tail_f;
      *(tail_ref + index) = node;
    }
    else{
      *(tail_ref + index) = node;
    }
  }
}

// delete node function
void deleteNode(header_t **head_ref, header_t **tail_ref, header_t *del) {
  // the free block to be deleted must be there in some unique free list,
  // find it by size
  int ind = bestList(del->size);
  footer_t *del_foot = get_footer(del);
  if (*(head_ref + ind) == NULL || del == NULL || del_foot == NULL)
    return;

  if (*(head_ref + ind) == del) {
    *(head_ref + ind) = del->next;
    if (del->next == NULL) {
      *(tail_ref + ind) = NULL;
    }
  } else {
      header_t *prev_header = del_foot->prev;
      if(prev_header)
        prev_header->next = del->next;
      if (del->next == NULL) {
        *(tail_ref + ind) = prev_header;
      }
    }

  if (del->next != NULL) {
    footer_t *del_next_foot = get_footer(del->next);
    if (del_next_foot) {
      del_next_foot->prev = del_foot->prev;
    }
  }
  
  del->next = NULL;
  del_foot->prev = NULL;
}

//find best fit function
header_t *firstFit(header_t **head_ref, size_t req_size) {
  header_t *best = NULL;
  header_t *curr = *head_ref;
  while (curr != NULL) {
    if (get_size(curr->size) >= req_size) {
      return curr;
      // if (best == NULL || (get_size(curr->size) <= get_size(best->size))) {
      //   best = curr;
      // }
    }
    curr = curr->next;
  }
  return best;
}

header_t *bestFit(header_t * *head_ref, size_t req_size) {
  // first find the correct list first
  // do first fit in each list
  header_t *best = NULL;
  int start_ind = bestList(req_size);
  for (int i = start_ind; i < 6; i++) {
    // try to do a first fit on this ith list to see if we can find a free
    // block if not, move to the next free list if nothing can be found,
    // return null
    best = firstFit((head_ref + i), req_size);
    if (best)
      return best;
  }
  return NULL;
}

// merge blocks
void merge_right(header_t * node, header_t * next_block) {
	// update metadata and footer of the to be freed block:
	// get last 4 bits of size first
	size_t last_4_bits = node->size & 0x0F;
	size_t sz_val = get_size(node->size) + sizeof(footer_t) +
		      sizeof(header_t) + get_size(next_block->size);
	node->size = sz_val | last_4_bits;
	footer_t *nnode_foot = get_footer(next_block);
	nnode_foot->size = node->size;
}

void merge_left(header_t * node, header_t * prev_block) {
	// update metadata and footer of the prev_block:
	// get last 4 bits of size first
	size_t last_4_bits = prev_block->size & 0x0F;
	size_t sz_val = get_size(prev_block->size) + sizeof(footer_t) +
		      sizeof(header_t) + get_size(node->size);
	prev_block->size = sz_val | last_4_bits;
	footer_t *node_foot = get_footer(node);
	node_foot->size = prev_block->size;
}

header_t *coalesce(header_t **head_ref, header_t ** tail_ref, header_t *node) {
  // node is the to be freed
  // compute the addresses of the next and previous block

  //next block address:
  header_t *next_block = get_next(node);
  // prev block:
  header_t *prev_block = get_prev(node);

  if (!in_heap((void *)prev_block))
    prev_block = NULL;
  if (!in_heap((void *)next_block))
    next_block = NULL;

  if (prev_block == NULL && next_block == NULL) {
    if (node) {
      // set the alloc bit to false
      if (!is_free(node))
        toggle_alloc(node);
      insertNode(head_ref, tail_ref, node);
      return node;
    }
    return NULL;
    // nothing to coaelsce with, both adjacent blocks are invalid
  }
  // case 2:
  else if (prev_block == NULL && next_block) {
    // check if can be coalesced with next block
    if (is_free(next_block)) {
      // next block is free
      // delete the next_block from linked list
      deleteNode(head_ref, tail_ref, next_block);
      // merge the two blocks
      merge_right(node, next_block);
      // free the alloc bit
      if (!is_free(node))
        toggle_alloc(node);
      insertNode(head_ref, tail_ref, node);
      return node;
    } else {
      if (!is_free(node))
        toggle_alloc(node);
      insertNode(head_ref, tail_ref, node);
      return node;
    }
  }
  // case 3:
  else if (prev_block && next_block == NULL) {
    // check if can be coalesced with prev block
    if (is_free(prev_block)) {
      // prev block is free
      // delete node from linked list
      deleteNode(head_ref, tail_ref, prev_block);
      // merge the two blocks
      merge_left(node, prev_block);
      // free the alloc bit
      if (!is_free(prev_block))
        toggle_alloc(prev_block);
      insertNode(head_ref, tail_ref, prev_block);
      return prev_block;
    } else {
      if (!is_free(node))
        toggle_alloc(node);
      insertNode(head_ref, tail_ref, node);
      return node;
    }
  }
  // case 4:
  else{
    // both adjacent blocks are valid
    if (!is_free(prev_block) && !is_free(next_block))
    {
      if (node) {
        // set the alloc bit to false
        if (!is_free(node))
          toggle_alloc(node);
        insertNode(head_ref, tail_ref, node);
        return node;
      }
      return NULL;
    } 
    else if (!is_free(prev_block) && is_free(next_block)) {
      // next block is free
      // delete next_block from linked list
      deleteNode(head_ref, tail_ref, next_block);
      // merge the two blocks
      merge_right(node, next_block);
      // free the bit
      if (!is_free(node))
        toggle_alloc(node);
      insertNode(head_ref, tail_ref, node);
      return node;
    } 
    else if (is_free(prev_block) && !is_free(next_block)) {
      // prev block is free
      // delete node from linked list
      deleteNode(head_ref, tail_ref, prev_block);
      // merge the two blocks
      merge_left(node, prev_block);
      // free the alloc bit
      if (!is_free(prev_block))
        toggle_alloc(prev_block);
      insertNode(head_ref, tail_ref, prev_block);
      return prev_block;
    }
    else{
      // both are free
      // delete both blocks
      deleteNode(head_ref, tail_ref, next_block);
      deleteNode(head_ref, tail_ref, prev_block);
      // merge the right with the middle
      merge_right(node, next_block);
      // merge the left with the middle
      merge_left(node, prev_block);
      // set alloc bit to 1
      if (!is_free(prev_block))
        toggle_alloc(prev_block);
      // add the expanded prev_block to the free list
      insertNode(head_ref, tail_ref, prev_block);
      return prev_block;
    }
  }
  return NULL;
}

void split(header_t **head_ref, header_t **tail_ref, header_t *node, size_t size) {
  // split the node into two blocks
  deleteNode(head_ref, tail_ref, node);
  size_t org_size = get_size(node->size);
  size_t last_4_bits = node->size & 0x0F;
  node->size = size | last_4_bits;
  if (is_free(node))
  	toggle_alloc(node);
  
  footer_t *ft_address = get_footer(node);
  ft_address->size = node->size;
  ft_address->prev = NULL;
  
  header_t *new_header = (header_t *)(((char *)ft_address + sizeof(footer_t)));
  size_t sz_val = org_size - sizeof(footer_t) - size - sizeof(header_t);
  new_header->size = sz_val | 0x0;
  new_header->next = NULL;

  footer_t *new_footer = get_footer(new_header);
  new_footer->size = new_header->size;
  new_footer->prev = NULL;
  coalesce(head_ref, tail_ref, new_header);
}

void arrange(header_t **head_ref, header_t **tail_ref, header_t *node, size_t size) {

  if ((get_size(node->size) - size) <= (sizeof(footer_t) + sizeof(header_t))) {
    deleteNode(head_ref, tail_ref, node);
    if (is_free(node))
      toggle_alloc(node);
  }
  else{
    split(head_ref, tail_ref, node, size);
  }
}

size_t get_extension(size_t size) {
   // calculate k
   size_t k = (size + 15) / 16;
   size_t extension = k * 16;
   return extension;
}

header_t *expand_heap(header_t **head_ref, header_t **tail_ref, size_t size) {
  // call mm_sbrk
  void *new_addr = mm_sbrk(size + sizeof(header_t) + sizeof(footer_t));
  if (new_addr == (void *)-1) {
    return NULL;
  } else {
    // create a new free block
    header_t *new_block = (header_t *)new_addr;
    // set the size of the new block
    new_block->size = size;
    if (!is_free(new_block))
    	toggle_alloc(new_block);
    // set the next pointer to null
    new_block->next = NULL;
    // go to footer first
    footer_t *new_footer = get_footer(new_block);
    // set size
    new_footer->size = new_block->size;
    // update prev pointer to null
    new_footer->prev = NULL;
    // add the new block to the free list by coalescing
    header_t *extra_block = coalesce(head_ref, tail_ref, new_block);
    return extra_block;
  }
}

bool is_valid_ptr(void *ptr) {
  if (ptr == NULL)
    return false;
  // check if pointer is a valid address in the heap
  if (!in_heap(ptr))
    return false;
  // check if 16 byte aligned pointer
  if (!aligned(ptr))
    return false;
  // assume a valid pointer
  // try to get to the head of the block
  if (!in_heap((void *)((char *)ptr - sizeof(header_t))))
    return false;
  // try to get to the footer of the block
  header_t *head_addr = (header_t *)((char *)ptr - sizeof(header_t));
  footer_t *ft_addr = get_footer(head_addr);
  if (!in_heap((void *)ft_addr))
    return false;
  if (!in_heap((void *)((char *)ft_addr + sizeof(footer_t))))
    return false;
  return true;
}

void print_heap() {
  header_t *curr = *head_ref;
  printf("Head of the list address is: %p\n\n", *head_ref);
  while (curr != NULL) {
    // print header, size, footer
    printf("Header address is: %p", curr);
    printf("Header size is: %d\n", (int)(get_size(curr->size)));
    printf("Header next is: %p\n", curr->next);
    printf("Header alloc is %d\n", (int)((curr->size >> 1) & 1));
    footer_t *ft = get_footer(curr);
    printf("Footer address is: %p", ft);
    printf("Footer size is: %d\n", (int)(get_size(ft->size)));
    printf("Footer prev is: %p\n", ft->prev);
//    printf("Footer alloc is: %d\n", ft->alloc);
    printf("----------------------------------\n");
    printf("\n");
    curr = curr->next;
  }
}

/*
 * mm_init: returns false on error, true on success.
 */

bool mm_init(void)
{
  void *new_addr = mm_sbrk(EXTRA_SIZE + sizeof(header_t) + sizeof(footer_t));
  if (new_addr == (void *)-1)
    return false;
  // create a new free block
  header_t *init_block = (header_t *)new_addr;
  // space for prologue
  prologue = init_block;  
  // space for epilogue
  init_block->next = NULL;
  init_block->size = EXTRA_SIZE;
  footer_t *init_footer = get_footer(init_block);
  init_footer->size = EXTRA_SIZE;
  init_footer->prev = NULL;
  // update the head of the free list to be this
  for (int i = 0; i < 6; i++){
    head[i] = NULL;
    tail[i] = NULL;
  }
  insertNode(head_ref, tail_ref, init_block);
  mm_checkheap(__LINE__);
  return true;
  
}

/*
 * malloc
 */
void *malloc(size_t size)
{
  // if size is <=0, return NULL
  if (size <= 0)
    return NULL;
  // calculate the 16 byte aligned extension of size
  size_t extension = get_extension(size);
  // try to search for the best fit block
  header_t *best = bestFit(head_ref, extension);
  if (best) {
    // were able to find the best block
    // now just place and try to split the block if possible
    //printf("MALLOC   size: %d\n", (int)extension);
    arrange(head_ref, tail_ref, best, extension);
    //printf("AFTER SPLIT/ARRANGE ----------\n");
    //print_heap();
    // check heap
    mm_checkheap(__LINE__);
    return (void *)((char *)best + sizeof(header_t));
  } else {
    // need to extend the heap
    // calculate the size of bytes to extend heap by
    size_t heap_extra = max(extension, EXTRA_SIZE);
    header_t *new_block = expand_heap(head_ref, tail_ref, heap_extra);
    //printf("AFTER Expand heap ----------\n");
    //print_heap();
    if (new_block) {
      // were able to expand the heap
      arrange(head_ref, tail_ref, new_block, extension);
      mm_checkheap(__LINE__);
      return (void *)((char *)new_block + sizeof(header_t));
    } else
    {
      return NULL;
    }
  }
}

/*
 * free
 */
void free(void *ptr)
{
  // check if valid ptr
  if (!is_valid_ptr(ptr))
    return;

  // get the header of the block
  header_t *node = (header_t *)((char *)ptr - sizeof(header_t));
  // check if the block is allocated or not
  if (is_free(node))
    return;
  // block is indeed allocated, so need to coalesce and add it to the free list
  node->next = NULL;
  // get footer of the block
  footer_t *foot = get_footer(node);
  // set prev to null
  foot->prev = NULL;
  // set alloc to false to mark this block as free
  if (!is_free(node))
  	toggle_alloc(node);
  // now coalesce the block
  coalesce(head_ref, tail_ref, node);
  mm_checkheap(__LINE__);
  //printf("AFTER FREE ----------\n");
  //print_heap();
}

/*
 * realloc
 */
void *realloc(void *oldptr, size_t size)
{
  if (size == 0) {
    free(oldptr);
    return NULL;
  } else if (oldptr == NULL) {
    return malloc(size);
  } else {
    // need to reallocate block to somewhere else perhaps
    // check if valid ptr

    //if (!is_valid_ptr(oldptr))
      //return NULL;

    
    // first get to the header of the block
    header_t *old_node = (header_t *)((char *)oldptr - sizeof(header_t));
    // check if the block is occupied
    if (is_free(old_node))
      return NULL;

    // first, if requested size is more than size of ptr block
    // in this case, we don't have any option but to move the block somewhere
    // else (of size atleast size) and then return the pointer to the new
    // location get size of the pointer block
    size_t old_size = get_size(old_node->size);
    // now get extended size of the new block
    size_t new_size = get_extension(size);
    // compare the two sizes
    if (new_size > old_size) {
      // need to allocate a new block of new_size, and free the old one
      void *new_ptr = malloc(new_size);
      if (new_ptr) {
        // copy the old block to the new block
        memcpy(new_ptr, oldptr, old_size);
        // now free the old block
        free(oldptr);
        return new_ptr;
      } else
        return NULL;

    } else {
      arrange(head_ref, tail_ref, old_node, new_size);
      return oldptr;
    }
  }
}

/*
 * calloc
 * This function is not tested by mdriver, and has been implemented for you.
 */
void *calloc(size_t nmemb, size_t size)
{
  void *ptr;
  size *= nmemb;
  ptr = malloc(size);
  if (ptr) {
    memset(ptr, 0, size);
  }
  return ptr;
}


/*
 * mm_checkheap
 * You call the function via mm_checkheap(__LINE__)
 * The line number can be used to print the line number of the calling
 * function where there was an invalid heap.
 */

// - Is every block in the free list marked as free?
// - Are there any contiguous free blocks that somehow escaped coalescing?
// - Is every free block actually in the free list?
// - Do the pointers in the free list point to valid free blocks?
// - Do any allocated blocks overlap?
// - Do the pointers in a heap block point to valid heap addresses?

bool mm_checkheap(int line_number)
{
#ifdef DEBUG
  // Write code to check heap invariants here
  // IMPLEMENT THIS
  // check every block in each segregated free list is indeed free
  for(int i = 0; i < 6; i++){
    header_t *curr = *(head_ref + i);
    while(curr != NULL){
      // check the allocated bit
      if (!is_free(curr))
        return false;
      curr = curr->next;
    }
  }

  // check header and footer of each block in the heap for consistency
  // to get the first block of the heap, 
  header_t *block = prologue;
  while(true){
    // check if we are still in the heap first
    if (!in_heap((void *)block))
      break;
    if (!in_heap((void *)((char *)block + get_size(block->size) + sizeof(footer_t))))
      break;
      
    // check if header and footer size and allocated bits are the same
    footer_t *foot = get_footer(block);
    if (get_size(block->size) != ((foot->size >> 1) << 1))
      return false;
    // check alloc bit status
    if (((block->size >> 1) & 1) != ((foot->size >> 1) & 1))
      return false;
    // move to next block
    block = get_next(block);
  }

  // check if each free block in the heap is in some free list
  block = prologue;
  // iterate over the heap
  while (true){
    // check if we are still in the heap first
    if (!in_heap((void *)block))
      break;
    if (!in_heap((void *)((char *)block + get_size(block->size) + sizeof(footer_t))))
      break;
    
    // check if this block is in some free list
    // check if this block is free
    if (is_free(block)){
      bool is_there = false;
      for(int i = 0; i < 6; i++){
        if (!is_there){
          header_t *curr = *(head_ref + i);
          while(curr != NULL){
            // check the allocated bit
            if (block == curr){
              is_there = true;
              break;
            }
            curr = curr->next;
          }
        }
        else
          break;
      }
      // if this free block could not be found in any free list
      if (!is_there)
        return false;
    }
    // move to the next block in the heap
    block = get_next(block);
  }

#endif // DEBUG
  return true;
}

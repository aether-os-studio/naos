/* Luke Tchang
 * CS 107
 * explicit: This program is an implementation of an explicit free list heap
 * allocator. In terms of specs, this program uses headers to track block size
 * and allocation status (as well as the pointers to next and previous free
 * blocks which are contained in the "header" struct). Malloc uses this explicit
 * free list created by the pointers to find a new free block (using first fit).
 * Coalescing of immediate right neighbors is supported when free is called.
 * Additionally, in-place realloc is supported and attempts to merge neighboring
 * right blocks to create enough room in the case of an expansion. If the
 * immediate neighboring space isn't large enough, realloc moves the block to
 * another part of the heap.
 */
#include <mm/mm.h>

// CONSTANTS:
//__________
#define WIDTH 8
#define ALLOC 1
#define FREE 0

/* GLOBAL VARIABLES:
 * _________________
 * segment_start: beginning of heap segment
 * segment_size: total size of heap segment
 * start_block: first block in segment (initialized to start + 8 bytes)
 * nblocks: total number of blocks (free and allocated)
 * nused: total number of allocated blocks
 * last_free_block: most recent free block appended to explicit free list
 */
static void *segment_start;
static size_t segment_size;
static void *start_block;
static size_t nblocks;
static size_t nused;
static void *last_free_block;
static spinlock_t heap_lock = SPIN_INIT;

// STRUCT INFO
//___________

/* Struct: Header
 * ______________
 * Description: The "header" struct is 24-bytes big and contains 8-bytes for
 * the block size and 8 bytes each for the next and previous free block
 * pointers.
 */
typedef struct {
    size_t block_size;
    void *prev_ptr;
    void *next_ptr;
} header;

/* Function: create_hdr
 * ____________________
 * Parameters:
 *    - loc: pointer to starting location of header
 *    - size: size of block (not including header) in bytes
 *    - prev: pointer to previous free block
 *    - next: pointer to next free block
 *
 * Return: N/A
 *
 * Description: This function writes a new header into memory, setting the
 * size, next pointer, and previous pointer.
 */
void create_hdr(void *loc, size_t size, void *prev, void *next) {
    header *h = loc;
    h->block_size = (size << 2);
    h->prev_ptr = prev;
    h->next_ptr = next;
}

// SHORT HELPER FUNCTIONS:
//_______________________

/* Functions: get_hdr
 * __________________
 * Parameters:
 *    - block_ptr: pointer to start of block
 *
 * Return: pointer to block header
 *
 * Description: This function takes a pointer to the start of a block and
 * returns a pointer to the start of that block's header.
 */
header *get_hdr(void *block_ptr) {
    return (header *)((char *)block_ptr - WIDTH);
}

/* Functions: get_block_size
 * __________________
 * Parameters:
 *    - block_ptr: pointer to start of block
 *
 * Return: size of block
 *
 * Description: This function takes a pointer to the start of a block and
 * returns the size of that block.
 */
size_t get_block_size(void *block_ptr) {
    return ((*get_hdr(block_ptr)).block_size) >> 2;
}

/* Functions: get_next_block
 * __________________
 * Parameters:
 *    - block_ptr: pointer to start of block
 *
 * Return: pointer to the neighboring right block
 *
 * Description: This function takes a pointer to the start of a block and
 * returns a pointer to the start of the next block.
 */
void *get_next_block(void *block_ptr) {
    return (char *)block_ptr + get_block_size(block_ptr) + WIDTH;
}

/* Functions: get_next_free
 * __________________
 * Parameters:
 *    - block_ptr: pointer to start of block
 *
 * Return: pointer to next free block in the explicit free list
 *
 * Description: This function takes a pointer to the start of a block and
 * returns a pointer to the start of the next free block.
 */
void *get_next_free(void *block_ptr) {
    return (block_ptr != NULL) ? (*get_hdr(block_ptr)).next_ptr : NULL;
}

/* Functions: get_prev_free
 * __________________
 * Parameters:
 *    - block_ptr: pointer to start of block
 *
 * Return: pointer to the previous free block in the explicit free list
 *
 * Description: This function takes a pointer to the start of a block and
 * returns a pointer to the previous free block.
 */
void *get_prev_free(void *block_ptr) {
    return (block_ptr != NULL) ? (*get_hdr(block_ptr)).prev_ptr : NULL;
}

/* Functions: check_alloc
 * __________________
 * Parameters:
 *    - block_ptr: pointer to start of block
 *
 * Return: 0 if block is free, 1 if block is allocated
 *
 * Description: This function takes a pointer to the start of a block and
 * returns 0 or 1 depending on whether or not the block is free or
 * allocated.
 */
int check_alloc(void *block_ptr) {
    return (*(get_hdr(block_ptr))).block_size & 0x1;
}

/* Functions: round_up
 * __________________
 * Parameters:
 *    - req_size: size specified in malloc or realloc request
 *
 * Return: rounded up version of original request (to nearest multiple of 8)
 *
 * Description: This function rounds up the client's request size to the
 * nearest multiple of 8 and returns that number.
 */
size_t round_up(size_t req_size) {
    size_t rounded_size = (req_size + WIDTH - 1) & ~(WIDTH - 1);
    return (rounded_size < 16) ? 16 : rounded_size;
}

/* Functions: set_hdr_size
 * __________________
 * Parameters:
 *    - block_ptr: pointer to start of block
 *    - upd_size: new size to write into block header
 *
 * Return: N/A
 *
 * Description: This function updates the size written into the header of
 * the given block.
 */
void set_hdr_size(void *block_ptr, size_t upd_size) {
    header *hdr_ptr = get_hdr(block_ptr);
    (*hdr_ptr).block_size = ((*hdr_ptr).block_size & 0x3) | (upd_size << 2);
}

/* Functions: set_hdr_status
 * __________________
 * Parameters:
 *    - block_ptr: pointer to start of block
 *    - status: FREE (0) or ALLOC (1)
 *
 * Return: N/A
 *
 * Description: This function updates the allocation status of written into
 * the last bit of the block's header.
 */
void set_hdr_status(void *block_ptr, unsigned long status) {
    header *hdr_ptr = get_hdr(block_ptr);
    (*hdr_ptr).block_size = ((*hdr_ptr).block_size & ~0x3) | status;
}

/* Functions: set_prev_ptr
 * __________________
 * Parameters:
 *    - block_ptr: pointer to start of block
 *    - prev: pointer to block you intended block_ptr's prev_free field to
 * point to
 *
 * Return: N/A
 *
 * Description: This function sets the given block's prev_free pointer to
 * the provided prev pointer. If the provided block pointer is NULL, the
 * function does nothing.
 */
void set_prev_ptr(void *block_ptr, void *prev) {
    if (block_ptr != NULL) {
        header *hdr_ptr = get_hdr(block_ptr);
        (*hdr_ptr).prev_ptr = prev;
    }
}

/* Functions: set_next_ptr
 * __________________
 * Parameters:
 *    - block_ptr: pointer to start of block
 *    - next: pointer to block you intended block_ptr's next_free field to
 * point to
 *
 * Return: N/A
 *
 * Description: This function sets the given block's next_free pointer to
 * the provided prev pointer. If the provided block pointer is NULL, the
 * function does nothing.
 */
void set_next_ptr(void *block_ptr, void *next) {
    if (block_ptr != NULL) {
        header *hdr_ptr = get_hdr(block_ptr);
        (*hdr_ptr).next_ptr = next;
    }
}

/* Functions: upd_last_free_block
 * __________________
 * Parameters:
 *    - cmp_block: block being checked (whether or not it was the
 * last_free_block)
 *    - new_block: block to be set to last_free_block if cmp_block was the
 * last_free_block
 *
 * Return: N/A
 *
 * Description: This function is used to check if the last_free_block is
 * being allocated and if so, will update the last_free_block (setting it
 * equal to the passed in new_block).
 */
void upd_last_free_block(void *cmp_block, void *new_block) {
    if (last_free_block == cmp_block) {
        last_free_block = new_block;
    }
}

// LONG HELPER FUNCTIONS:
//______________________

/* Function: first_fit
 * ___________________
 * Parameters:
 *    - req_size: requested block size
 *
 * Return: pointer to first free block in explicit free list OR NULL if no
 * block found
 *
 * Description: This function starts at the most recently appended block in
 * the free list (last_free_block) and loops through that list, searching
 * for the free block that meets the size requirements. If no free block big
 * enough for the request is found, NULL is returned.
 */
void *first_fit(size_t req_size) {
    void *curr_block = last_free_block;
    for (int i = 0; i < nblocks - nused; i++) {
        if (get_block_size(curr_block) >= req_size &&
            !check_alloc(curr_block)) {
            return curr_block;
        }
        curr_block = get_prev_free(curr_block);
    }
    return curr_block;
}

/* Function: create_partial_fb
 * ___________________
 * Parameters:
 *    - orig_block: pointer to start of free block about to be allocated
 *    - new_fb:     pointer to start of remaining piece of free block (i.e.
 * start of block + size request)
 *    - fb_size:    size of remaining piece of free block
 *
 * Return: N/A
 *
 * Description: This function is called during alloc and realloc requests
 * when a free block will not be fully allocated. It rearranges the original
 * free block's next and previous free block pointers to point to start of
 * the remaining "free block piece."
 */
void create_partial_fb(void *orig_block, void *new_fb, size_t fb_size) {
    void *new_free_hdr = get_hdr(new_fb);
    void *orig_prev = get_prev_free(orig_block);
    void *orig_next = get_next_free(orig_block);
    set_next_ptr(orig_prev, new_fb);
    set_prev_ptr(orig_next, new_fb);
    create_hdr(new_free_hdr, fb_size, orig_prev, orig_next);
    upd_last_free_block(orig_block, new_fb);
}

/* Function: change_to_free
 * ___________________
 * Parameters:
 *    - new_free: pointer to block being freed
 *
 * Return: N/A
 *
 * Description: This function is used for free and shink realloc requests.
 * It sets the status of the new block to free, sets its prev_ptr to the
 * previously freed block, sets its next_ptr to NULL, and makes the new
 * block the last_free_block.
 */
void change_to_free(void *new_free) {
    set_hdr_status(new_free, FREE);
    set_next_ptr(last_free_block, new_free);
    set_prev_ptr(new_free, last_free_block);
    set_next_ptr(new_free, NULL);
    last_free_block = new_free;
}

/* Function: coalesce
 * ___________________
 * Parameters:
 *    - new_free: pointer to block being freed
 *
 * Return: N/A
 *
 * Description: This function is called on each free request after it has
 * been confirmed that in-place realloc has enough space. It sets the size
 * of the freed block to account for the added size of its neighbor and
 * rearranges the pointers for the two blocks given that the two blocks are
 * now merged under one block.
 */
void coalesce(void *new_free) {
    void *neighbor = get_next_block(new_free);
    void *neighbor_prev = get_prev_free(neighbor);
    void *neighbor_next = get_next_free(neighbor);

    set_hdr_status(new_free, FREE);
    set_hdr_size(new_free,
                 get_block_size(new_free) + get_block_size(neighbor) + WIDTH);

    set_prev_ptr(new_free, neighbor_prev);
    set_next_ptr(new_free, neighbor_next);
    set_prev_ptr(neighbor_next, new_free);
    set_next_ptr(neighbor_prev, new_free);

    upd_last_free_block(neighbor, new_free);
}

/* Function: right_search
 * ___________________
 * Parameters:
 *    - r_neighbor: pointer to right neighbor (for expanding realloc
 * request)
 *    - add_size: the additional size to be added in realloc request
 *
 * Return: number of right neighboring blocks to be used for in-place
 * realloc, 0 if not enough space for in-place realloc
 *
 * Description: This function checks if there is enough space for in-place
 * realloc, looping through right neighboring blocks. If an allocated block
 * is appears before the size requirement has been filled, the function
 * returns 0. Otherwise, the function returns the number of neighboring
 * blocks to use for the realloc request.
 */
int right_search(void *r_neighbor, size_t add_size) {
    int block_count = 0;
    size_t total_space = 0;

    while (total_space < add_size) {
        if (check_alloc(r_neighbor)) {
            return 0;
        }
        total_space += (get_block_size(r_neighbor) + WIDTH);
        r_neighbor = get_next_block(r_neighbor);
        block_count += 1;
    }
    return block_count;
}

/* Function: fix_neighbors
 * ___________________
 * Parameters:
 *    - neighbor: pointer to first right neighboring block (for in-place
 * realloc)
 *    - new_size: pointer to size_t storing size of the to-be reallocated
 * block
 *    - num_blocks: number of right neighboring blocks to include in
 * in-place realloc
 *    - space_needed: remaining number of bytes to add to allocate as part
 * of realloc request
 *
 * Return: N/A
 *
 * Description: This function is called when in-place realloc is possible.
 * It loops through the appropriate right neighboring blocks, rearranging
 * pointers to maintain the free list (since the free right neighbors will
 * be converted to allocated). The final free block to be allocated has a
 * special case. If the resulting fragment of that free block is smaller
 * than the size of a header (24 bytes), it is included as padding (thus the
 * pointer to new_size is dereferenced and the value updated). Otherwise,
 * the resulting piece of the free block is left in the free list.
 */
void fix_neighbors(void *neighbor, size_t *new_size, int num_blocks,
                   size_t space_needed) {
    for (int i = 1; i <= num_blocks; i++) {
        if (i == num_blocks) {
            size_t remaining_space =
                get_block_size(neighbor) + WIDTH - space_needed;
            if (remaining_space >= sizeof(header)) {
                void *new_partial_fb = (char *)neighbor + space_needed;
                size_t new_fb_size = get_block_size(neighbor) - space_needed;
                create_partial_fb(neighbor, new_partial_fb, new_fb_size);
                return;
            } else {
                *new_size += remaining_space;
            }
        }
        void *neighbor_prev = get_prev_free(neighbor);
        set_next_ptr(neighbor_prev, get_next_free(neighbor));
        set_prev_ptr(get_next_free(neighbor), get_prev_free(neighbor));
        upd_last_free_block(neighbor, neighbor_prev);

        space_needed -= (get_block_size(neighbor) + WIDTH);
        neighbor = get_next_block(neighbor);
        nblocks -= 1;
    }
}

// ALLOCATOR FUNCTIONS:
//____________________

/* Function: init
 * ___________________
 * Parameters:
 *    - heap_start: start of heap segment
 *    - heap_size: size of heap segment
 *
 * Return: true if segment available for use, false otherwise
 *
 * Description: This function initializes global variables for the rest of
 * the program. This includes initializing the start of the heap, the heap's
 * size, the first block, the number of total blocks, and the number of
 * allocated blocks.
 */
bool init_heap(void *heap_start, size_t heap_size) {
    segment_start = heap_start;
    segment_size = heap_size;
    last_free_block = (char *)segment_start + WIDTH;
    start_block = last_free_block;
    create_hdr(segment_start, heap_size - WIDTH, NULL, NULL);

    nblocks = 1;
    nused = 0;
    return true;
}

/* Function: malloc
 * ___________________
 * Parameters:
 *    - req_size: requested block size
 *
 * Return: N/A
 *
 * Description: This function allocates a block on the heap (using first_fit
 * search). If the search is successful, a few different cases are checked
 * regarding the difference in size between the block to be used for
 * allocation and the size of the request. If the difference is less than
 * the size of a header (24 bytes including pointers), the entire block is
 *              allocated (extra space used as padding). Otherwise, part of
 * the free block is allocated and a partial free block is left in the free
 * list.
 */
void *malloc(size_t req_size) {
    if (req_size <= 0) {
        return NULL;
    }

    spin_lock(&heap_lock);

    void *alloc_block = NULL;
    req_size = round_up(req_size);
    if ((alloc_block = first_fit(req_size)) != NULL) {
        size_t size_diff = get_block_size(alloc_block) - req_size;

        if (size_diff < sizeof(header)) {
            req_size = size_diff + req_size;
            if (alloc_block == last_free_block) {
                last_free_block = get_prev_free(last_free_block);
                set_next_ptr(last_free_block, NULL);
            } else {
                set_prev_ptr(get_next_free(alloc_block),
                             get_prev_free(alloc_block));
                set_next_ptr(get_prev_free(alloc_block),
                             get_next_free(alloc_block));
            }
        } else {
            void *new_partial_fb = (char *)alloc_block + req_size + WIDTH;
            create_partial_fb(alloc_block, new_partial_fb, size_diff - WIDTH);
            nblocks += 1;
        }

        set_hdr_size(alloc_block, req_size);
        set_hdr_status(alloc_block, ALLOC);

        nused += 1;
        spin_unlock(&heap_lock);
        return alloc_block;
    }
    spin_unlock(&heap_lock);
    return NULL;
}

/* Function: free
 * ___________________
 * Parameters:
 *    - ptr: pointer to block to be freed
 *
 * Return: N/A
 *
 * Description: This function first checks if the block to be freed has a
 * free right neighbor. If so, coalesce is called. Otherwise, the allocated
 * block is changed to a free block.
 */
void free(void *ptr) {
    spin_lock(&heap_lock);
    if (ptr != NULL) {
        if (!check_alloc(get_next_block(ptr))) {
            coalesce(ptr);
            nblocks -= 1;
        } else {
            change_to_free(ptr);
        }
        nused -= 1;
    }
    spin_unlock(&heap_lock);
}

/* Function: realloc
 * ___________________
 * Parameters:
 *    - old_ptr: pointer to original block (subject of realloc request)
 *    - new_size: size of realloc request
 *
 * Return: N/A
 *
 * Description: This function fulfills reallocation requests. If the request
 * will shrink the block, there are two cases. The implicit case is that the
 * difference in size between the reallocated block and original block is
 * less than the size of a header (24 bytes including pointers). In this
 * case, nothing changes, as the remaining space is treated as padding. If
 * the size difference >= 24 bytes, the remaining space added as a block to
 * the free list. For expand requests, right search is used to determine if
 * in-place realloc is possible. If so, the blocks size is updated and the
 * pointers of the free blocks being allocated are arranged by
 * fix_neighbors. Otherwise, normal realloc occurs and moves the block
 * somewhere else in memory.
 */
void *realloc(void *old_ptr, size_t new_size) {
    if (old_ptr == NULL) {
        return malloc(new_size);
    }
    if (new_size == 0) {
        free(old_ptr);
        return NULL;
    }

    spin_lock(&heap_lock);

    size_t curr_size = get_block_size(old_ptr);
    new_size = round_up(new_size);
    if (curr_size >= new_size) { // SHRINK
        size_t size_diff = curr_size - new_size;

        if (size_diff >= sizeof(header)) {
            void *new_free_start = (char *)old_ptr + new_size + WIDTH;
            set_hdr_size(old_ptr, new_size);
            change_to_free(new_free_start);
            set_hdr_size(new_free_start, size_diff - WIDTH);
            nblocks += 1;
        }
        spin_unlock(&heap_lock);
        return old_ptr;
    } else { // EXPAND
        size_t size_diff = new_size - curr_size;
        int r_free_blocks =
            right_search((char *)old_ptr + curr_size + WIDTH, size_diff);

        if (r_free_blocks) {
            fix_neighbors(get_next_block(old_ptr), &new_size, r_free_blocks,
                          size_diff);
            set_hdr_size(old_ptr, new_size);
            spin_unlock(&heap_lock);
            return old_ptr;
        } else {
            void *new_ptr = malloc(new_size);
            memcpy(new_ptr, old_ptr, new_size);
            free(old_ptr);
            spin_unlock(&heap_lock);
            return new_ptr;
        }
    }
    spin_unlock(&heap_lock);
    return NULL;
}

void *calloc(size_t num, size_t size) {
    void *ptr = malloc(num * size);
    if (ptr)
        memset(ptr, 0, num * size);
    return ptr;
}

bool validate_heap() {
    void *curr_block = start_block;
    size_t used_bytes = 0;
    size_t free_bytes = 0;
    int free_count = 0;
    int n_free = nblocks - nused;

    for (int i = 0; i < nblocks; i++) {
        size_t block_width_size = get_block_size(curr_block) + WIDTH;
        if (check_alloc(curr_block)) {
            used_bytes += block_width_size;
        } else {
            free_count += 1;
            free_bytes += block_width_size;
        }
        curr_block = get_next_block(curr_block);
    }
    if (used_bytes + free_bytes != segment_size) {
        return false;
    }
    if (free_count != n_free) {
        return false;
    }
    void *curr_free_block = last_free_block;
    while (curr_free_block != NULL) {
        if (check_alloc(curr_free_block)) {
            return false;
        }
        if (get_prev_free(curr_free_block) &&
            get_next_free(get_prev_free(curr_free_block)) != curr_free_block) {
            return false;
        }

        n_free -= 1;
        curr_free_block = get_prev_free(curr_free_block);
    }
    if (n_free != 0) {
        return false;
    }
    return true;
}

void heap_init() {
    map_page_range(get_current_page_dir(false), KERNEL_HEAP_START, 0,
                   KERNEL_HEAP_SIZE, PT_FLAG_R | PT_FLAG_W);
    init_heap((void *)KERNEL_HEAP_START, KERNEL_HEAP_SIZE);
}

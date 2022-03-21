#include <mm/mm_tracker.h>

/**
 * @brief Initialize the Memory Tracker.
 *
 * @param mmt Memory Tracker
 * @param slabs Slab allocator
 *
 */
void mm_tracker_init(mm_tracker_t *mmt, struct slab_allocator *slabs)
{
    mmt->slabs = slabs;

    slab_init(mmt->slabs, sizeof(mmnode_t), NULL);
    mmt->head = NULL;
    mmt->refill_lock = 0;
}

/**
 * @brief Refill the slab allocator if necessary
 *
 * @param mmt Memory Tracker
 *
 * @note Necessary is when there are less than 16 slabs remaining.
 */
errval_t mm_tracker_refill(mm_tracker_t *mmt)
{
    errval_t err = SYS_ERR_OK;
    if (!mmt->refill_lock) {
        mmt->refill_lock = true;

        if (slab_freecount(mmt->slabs) < 16) {
            err = slab_default_refill(mmt->slabs);
            if (err_is_fail(err)) {
                err = err_push(err, LIB_ERR_SLAB_REFILL);
            }
        }
        mmt->refill_lock = false;
    }

    return err;
}

/**
 * @brief Allocate a new slab node.
 *
 * @param mmt memory tracker instance
 * @param retnode Pointer to node to fill in
 *
 */
errval_t mm_tracker_alloc(mm_tracker_t *mmt, mmnode_t **retnode)
{
    errval_t err = SYS_ERR_OK;

    *retnode = slab_alloc(mmt->slabs);
    if (*retnode == NULL) {
        err = LIB_ERR_SLAB_ALLOC_FAIL;
    }

    return err;
}


/**
 * @brief inserts a node before the current head
 *
 * @param mmt the memory tracker instance
 * @param node the node to be inserted
 */
void mm_tracker_node_insert(struct mm_tracker *mmt, mmnode_t *node)
{
    if (mmt->head == NULL) {
        mmt->head = node;
    } else {
        mmnode_t *tail = mmt->head->prev;
        tail->next = node;
        node->prev = tail;
    }
    node->next = mmt->head;
    mmt->head->prev = node;
}


/**
 * @brief splits a node into two nodes
 *
 * @param mmt the memory tracker instance
 * @param node the node to be split
 * @param offset the offset at which the node should be split
 * @param left_split a pointer that will point to the left split
 * @param right_split pointer that will point to the rigth split
 * @return errval_t
 */
errval_t mm_tracker_node_split(struct mm_tracker *mmt, mmnode_t *node, size_t offset,
                               mmnode_t **left_split, mmnode_t **right_split)
{
    mmnode_t *new_node;
    errval_t err = mm_tracker_alloc(mmt, &new_node);
    if (err_is_fail(err)) {
        return err_push(err, MM_ERR_ALLOC_NODE);
    }

    *left_split = node;
    *right_split = new_node;

    // adjust sizes
    new_node->base = node->base + offset;
    new_node->size = node->size - offset;
    // capinfo stays the same
    new_node->capinfo = node->capinfo;

    node->size = offset;

    // relink nodes
    new_node->next = node->next;
    node->next->prev = new_node;
    node->next = new_node;
    new_node->prev = node;

    return SYS_ERR_OK;
}

/**
 * @brief merges a node with its right neighbour
 *
 * @param mmt the memory tracker instance
 * @param left_split the left node that is merged
 * @return errval_t
 */
void mm_tracker_node_merge(struct mm_tracker *mmt, mmnode_t *left_split)
{
    assert(left_split != NULL);

    mmnode_t *right_split = left_split->next;

    if (right_split == NULL) {
        return;
    }

    // we migh have a circular buffer but the memory is still linear
    if (left_split->base > right_split->base) {
        return;
    }

    // the underlying capability needs to be the same
    if (!capcmp(left_split->capinfo.cap, right_split->capinfo.cap)) {
        return;
    }

    // only merge if both are free
    if (left_split->type == NodeType_Free && right_split->type == NodeType_Free) {
        assert(left_split->base + left_split->size == right_split->base);

        debug_printf("Coalescing blocks at: %lu and %lu\n", left_split->base,
                     right_split->base);

        // resize left split
        left_split->size += right_split->size;

        // relink nodes
        if (mmt->head == right_split) {
            mmt->head = right_split->next;
        }
        left_split->next = right_split->next;
        right_split->next->prev = left_split;

        slab_free(mmt->slabs, right_split);
    }
}


/**
 * @brief prints the current state of the memory allocator
 *
 * @param mmt the memory tracker instance
 */
void mm_tracker_debug_print(mm_tracker_t *mmt)
{
    printf("===\n");
    printf("Current state:\n");
    if (mmt->head == NULL) {
        printf("none");
        printf("\n\n");
        return;
    }
    printf("Head at %p\n", mmt->head->base);
    mmnode_t *curr = mmt->head;
    do {
        if (curr->type == NodeType_Allocated) {
            printf("Allocated: (%p, %lu)\n", curr->base, curr->base + curr->size - 1);
        } else if (curr->type == NodeType_Free) {
            printf("Free: (%p, %lu)\n", curr->base, curr->base + curr->size - 1);
        } else {
            printf("Type unknown\n");
        }
        curr = curr->next;
    } while (curr != mmt->head);
    printf("===\n");
}

errval_t mm_tracker_get_next_fit(mm_tracker_t *mmt, mmnode_t **retnode, size_t size,
                                 size_t alignment)
{
    assert(mmt != NULL);
    assert(retnode != NULL);

    mmnode_t *current = mmt->head;
    do {
        size_t alignment_padding = (current->base % alignment)
                                       ? alignment - (current->base % alignment)
                                       : 0;
        if (current->type == NodeType_Free && current->size >= (size + alignment_padding)) {
            *retnode = current;
            mmt->head = current;
            return SYS_ERR_OK;
        }
        current = current->next;
    } while (current != mmt->head);

    return MM_ERR_NOT_FOUND;
}

void mm_tracker_destroy(mm_tracker_t *mmt)
{
    if (mmt->head == NULL) {
        return;
    }
    mmnode_t *curr = mmt->head->next;
    while (curr != mmt->head) {
        mmnode_t *prev = curr;
        curr = curr->next;
        slab_free(mmt->slabs, prev);
    }
    slab_free(mmt->slabs, mmt->head);
    mmt->head = NULL;
}


/**
 * @brief frees an allocated memory region
 *
 * @param mmt the memory tracker
 * @param cap the capability that represent the freed memory region
 * @return errval_t
 *
 * partial free have to respect that the size needs to be aligned to the BASE_PAGE_SIZE
 */
errval_t mm_tracker_free(mm_tracker_t *mmt, genpaddr_t memory_base, gensize_t memory_size)
{
    assert(mmt->head);

    mmnode_t *curr = mmt->head;
    do {
        // search for node that represent the freed region
        if (memory_base != curr->base || curr->size != memory_size) {
            curr = curr->next;
            continue;
        }

        curr->type = NodeType_Free;
        mm_tracker_node_merge(mmt, curr);
        mm_tracker_node_merge(mmt, curr->prev);

        return SYS_ERR_OK;
    } while (curr != mmt->head);
    mmt->head = curr;

    // Invalid reference, as this was never allocated
    printf("Invalid memory free request: (%p %lu)\n", memory_base, memory_size);
    return MM_ERR_NOT_FOUND;
}

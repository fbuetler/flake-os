
#ifndef AOS_MM_TRACKER_H
#define AOS_MM_TRACKER_H

#include <sys/cdefs.h>
#include <errors/errno.h>
#include <aos/types.h>
#include <aos/domain.h>

// forward declarations
struct slab_allocator;
// forward declaration
typedef struct mmnode_t mmnode_t;


typedef struct mm_tracker {
    struct slab_allocator *slabs;
    struct mmnode_t *head;
    bool refill_lock;
} mm_tracker_t;


#include <aos/capabilities.h>
#include <aos/slab.h>
#include "slot_alloc.h"


enum nodetype { NodeType_Free, NodeType_Allocated, NodeType_Mapped };

struct capinfo {
    struct capref cap;  ///< Capability reference
    genpaddr_t base;    ///< Memory base address of the capref
    size_t size;        ///< Memory size of the capref
};

typedef struct mmnode_t {
    enum nodetype type;      ///< Nodetype is either free or allocated
    struct capinfo capinfo;  ///< Capability information
    struct mmnode_t *prev;   ///< Pointer to the previous node
    struct mmnode_t *next;   ///< Pointer to the next node
    genpaddr_t base;         ///< Memory base address that is represented by this node
    gensize_t size;          ///< Memory size that is represented by this node
} mmnode_t;


void mm_tracker_init(mm_tracker_t *mmt, struct slab_allocator *slabs);
errval_t mm_tracker_refill(mm_tracker_t *mmt);
errval_t mm_tracker_alloc(mm_tracker_t *mmt, mmnode_t **retnode);
void mm_tracker_debug_print(mm_tracker_t *mmt);
void mm_tracker_node_insert(mm_tracker_t *mmt, mmnode_t *node);
errval_t mm_tracker_node_split(mm_tracker_t *mmt, mmnode_t *node, size_t offset,
                               mmnode_t **left_split, mmnode_t **right_split);
void mm_tracker_node_merge(struct mm_tracker *mmt, mmnode_t *left_split);

errval_t mm_tracker_get_next_fit(mm_tracker_t *mmt, mmnode_t **retnode, size_t size,
                                enum nodetype type, size_t alignment);

void mm_tracker_destroy(mm_tracker_t *mmt);

errval_t mm_tracker_get_node_at(mm_tracker_t *mmt, genpaddr_t addr, size_t size, enum nodetype type, mmnode_t **retnode);

errval_t mm_tracker_free(mm_tracker_t *mmt, genpaddr_t memory_base, gensize_t memory_size);
errval_t mm_tracker_unmap(mm_tracker_t *mmt, genpaddr_t memory_base, gensize_t memory_size);

errval_t mm_tracker_alloc_slice(mm_tracker_t *mmt, mmnode_t *node, 
                            size_t size, size_t offset, 
                            mmnode_t **retleft, mmnode_t **allocated_node, mmnode_t **retright);

errval_t mm_tracker_alloc_range(mm_tracker_t *mmt, genpaddr_t base, gensize_t size, mmnode_t **retnode);
errval_t mm_tracker_map_range(mm_tracker_t *mmt, genpaddr_t base, gensize_t size, mmnode_t **retnode);

bool mm_tracker_is_allocated(mm_tracker_t *mmt, genvaddr_t vaddr, size_t size);
bool mm_tracker_is_mapped(mm_tracker_t *mmt, genvaddr_t vaddr, size_t size);

errval_t mm_tracker_find_allocated_node(mm_tracker_t *mmt, genpaddr_t memory_base,
                                        mmnode_t **retnode);
errval_t mm_tracker_find_mapped_node(mm_tracker_t *mmt, genpaddr_t memory_base,
                                        mmnode_t **retnode);

#endif
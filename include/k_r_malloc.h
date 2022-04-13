#ifndef _LIBC_K_R_MALLOC_H_
#define _LIBC_K_R_MALLOC_H_

#include <sys/cdefs.h>
#include <inttypes.h>

__BEGIN_DECLS

#define NALLOC  0x10000		/* minimum #units to request */

typedef uint64_t Align[4];	/* for alignment to long long boundary */

union header {			/* block header */
	struct {
		union header   *ptr;	/* next block if on free list */
		unsigned long	magic;  /* to mark malloced region */
		unsigned long   size;	/* size of this block */
	} s;
	Align           x;	/* force alignment of blocks */
};

typedef union header Header;

Header  *morecore(unsigned long nu);
void lesscore(void);
void __free_locked(void *ap);
void __malloc_init(void*, void*);

__END_DECLS

#endif /* _LIBC_K_R_MALLOC_H_ */

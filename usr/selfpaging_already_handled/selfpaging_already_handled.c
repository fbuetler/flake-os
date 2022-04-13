/**
 * \file
 * \brief Self-Paging application
 */

/*
 * Copyright (c) 2022 Team 007 - License to slab
 * All rights reserved.
 */


#include <stdio.h>

#include <aos/aos.h>

struct mregion{
    char *start;
    size_t size;
    bool moveUpwards;
};

__attribute__((unused))
static int walk_array(void *arg)
{
    struct mregion *region = (struct mregion *)arg; 

    char *start = region->start;

    if(region->moveUpwards){
        for(int i = 0; i < region->size; i+= BASE_PAGE_SIZE){
            printf("upwards: %d\n", i/BASE_PAGE_SIZE);
            start[i] = 'a';
        }
    }else{
        for(int i = region->size - BASE_PAGE_SIZE; i >= 0; i-= BASE_PAGE_SIZE){
            printf("downward: %d\n", i/BASE_PAGE_SIZE);
            start[i] = 'a';
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    size_t size = 10 * BASE_PAGE_SIZE;
    char *mem = malloc(size);

    mem[0] = 1;
    
    int N = 2;
    struct thread *threads[N];


    struct mregion regionUp = {
        .start = mem,
        .size = size,
        .moveUpwards = true
    };

    struct mregion regionDown = regionUp;
    regionDown.moveUpwards = false;

    threads[0] = thread_create(walk_array, (void*)&regionUp);
    threads[1] = thread_create(walk_array, (void*)&regionDown);

    for(int i = 0; i < N; i++){
        int retval;
        thread_join(threads[i], &retval);
    }

    free(mem);

    DEBUG_PRINTF("done with all threads\n");


    return EXIT_SUCCESS;
}

#include <stdbool.h>
#include <stdlib.h>

// TODO optimize to log log n
typedef struct region_t {
    size_t lower;  // inclusive
    size_t upper;  // inclusive
} region_t;

typedef struct list_node_t {
    struct region_t *region;
    struct list_node_t *prev;
    struct list_node_t *next;
} list_node_t;

typedef struct list_t {
    list_node_t *head;
    list_node_t *tail;
    size_t size;
} list_t;

void list_node_init(list_node_t *node, region_t *region);
void list_init(list_t *list);
void list_destroy(list_t *list);
void list_insert_first(list_t *list, region_t *region);
void list_insert_last(list_t *list, region_t *region);
bool list_insert_after(list_t *list, int index, region_t *region);
region_t *list_remove_first(list_t *list);
region_t *list_remove_last(list_t *list);
region_t *list_remove_index(list_t *list, int index);
region_t *list_get_index(list_t *list, int index);
void list_print(list_t *list);

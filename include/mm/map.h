#include <stdbool.h>
#include <stdlib.h>

typedef struct map_node_t {
    size_t key;
    size_t value;
    struct map_node_t *prev;
    struct map_node_t *next;
} map_node_t;

typedef struct map_t {
    map_node_t *head;
    map_node_t *tail;
    size_t size;
} map_t;

void map_node_init(map_node_t *node, size_t key, size_t value);
void map_init(map_t *map);
void map_destroy(map_t *map);
void map_put(map_t *map, size_t key, size_t values);
size_t map_get(map_t *map, size_t key);
size_t map_remove(map_t *map, size_t key);
bool map_contains(map_t *map, size_t key);
void map_print(map_t *map);
#include "mm/map.h"

#include <stdio.h>

void map_node_init(map_node_t *node, size_t key, size_t value)
{
    node->key = key;
    node->value = value;
    node->prev = NULL;
    node->next = NULL;
}

void map_init(map_t *map)
{
    map->head = NULL;
    map->tail = NULL;
    map->size = 0;
}

void map_destroy(map_t *map)
{
    map_node_t *curr = map->head;
    map_node_t *prev = NULL;
    while (curr != NULL) {
        prev = curr;
        curr = curr->next;
        free(prev);
    }
    map->head = NULL;
    map->tail = NULL;
    map->size = 0;
}

void map_put(map_t *map, size_t key, size_t value)
{
    map_node_t *entry = malloc(sizeof(map_node_t));
    map_node_init(entry, key, value);

    if (map->size == 0) {
        map->head = entry;
    } else {
        map->tail->next = entry;
        entry->prev = map->tail;
    }

    map->tail = entry;
    map->size++;
}

size_t map_get(map_t *map, size_t key)
{
    map_node_t *curr = map->head;
    if (map->head == NULL) {
        return -1;
    }

    while (curr != NULL) {
        if (curr->key == key) {
            return curr->value;
        }
        curr = curr->next;
    }
    return -1;
}

size_t map_remove(map_t *map, size_t key)
{
    map_node_t *curr = map->head;
    if (map->head == NULL) {
        return -1;
    }

    while (curr->key != key) {
        if (curr->next == NULL) {
            return -1;
        }
        curr = curr->next;
    }

    if (curr == map->head) {
        map->head = map->head->next;
    } else {
        curr->prev->next = curr->next;
    }

    if (curr == map->tail) {
        map->tail = curr->prev;
    } else {
        curr->next->prev = curr->prev;
    }
    map->size--;

    size_t value = curr->value;
    free(curr);
    return value;
}

bool map_contains(map_t *map, size_t key)
{
    return map_get(map, key) != -1;
}

void map_print(map_t *map)
{
    map_node_t *curr = map->head;
    if (map->head == NULL) {
        printf("none");
        return;
    }
    while (curr != NULL) {
        printf("(%lu, %lu),", curr->key, curr->value);
        curr = curr->next;
    }
}

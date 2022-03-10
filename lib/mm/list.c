#include "mm/list.h"

#include <stdio.h>

void list_node_init(list_node_t *node, region_t *region)
{
    node->region = region;
    node->prev = NULL;
    node->next = NULL;
}

void list_init(list_t *list)
{
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
}

void list_destroy(list_t *list)
{
    list_node_t *curr = list->head;
    list_node_t *prev = NULL;
    while (curr != NULL) {
        prev = curr;
        curr = curr->next;
        free(prev);
    }
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
}

void list_insert_first(list_t *list, region_t *region)
{
    list_node_t *entry = malloc(sizeof(list_node_t));
    list_node_init(entry, region);

    if (list->head == NULL) {
        list->tail = entry;
    } else {
        list->head->prev = entry;
    }

    entry->next = list->head;
    list->head = entry;
    list->size++;
}

void list_insert_last(list_t *list, region_t *region)
{
    list_node_t *entry = malloc(sizeof(list_node_t));
    list_node_init(entry, region);

    if (list->head == NULL) {
        list->head = entry;
    } else {
        list->tail->next = entry;
        entry->prev = list->tail;
    }

    list->tail = entry;
    list->size++;
}

bool list_insert_after(list_t *list, int index, region_t *region)
{
    list_node_t *entry = malloc(sizeof(list_node_t));
    list_node_init(entry, region);

    if (list->head == NULL) {
        // list is empty
        return false;
    }

    list_node_t *curr = list->head;
    for (int i = 0; i < index; i++) {
        if (curr->next == NULL) {
            // out of bounds
            return false;
        }
        curr = curr->next;
    }

    if (curr == list->tail) {
        entry->next = NULL;
        list->tail = entry;
    } else {
        entry->next = curr->next;
        curr->next->prev = entry;
    }
    entry->prev = curr;
    curr->next = entry;
    list->size++;
    return true;
}

region_t *list_remove_first(list_t *list)
{
    list_node_t *curr = list->head;
    if (list->head->next == NULL) {
        list->tail = NULL;
    } else {
        list->head->next->prev = NULL;
    }

    list->head = list->head->next;
    list->size--;

    region_t *region = curr->region;
    free(curr);
    return region;
}

region_t *list_remove_last(list_t *list)
{
    list_node_t *curr = list->tail;
    if (list->head->next == NULL) {
        list->head = NULL;
    } else {
        list->tail->prev->next = NULL;
    }

    list->tail = list->tail->prev;
    list->size--;

    region_t *region = curr->region;
    free(curr);
    return region;
}

region_t *list_remove_index(list_t *list, int index)
{
    list_node_t *curr = list->head;
    if (list->head == NULL) {
        return NULL;
    }

    for (int i = 0; i < index; i++) {
        if (curr->next == NULL) {
            return NULL;
        }
        curr = curr->next;
    }

    if (curr == list->head) {
        list->head = list->head->next;
    } else {
        curr->prev->next = curr->next;
    }

    if (curr == list->tail) {
        list->tail = curr->prev;
    } else {
        curr->next->prev = curr->prev;
    }
    list->size--;

    region_t *region = curr->region;
    free(curr);
    return region;
}

region_t *list_get_index(list_t *list, int index)
{
    list_node_t *curr = list->head;
    if (list->head == NULL) {
        return NULL;
    }

    for (int i = 0; i < index; i++) {
        if (curr->next == NULL) {
            return NULL;
        }
        curr = curr->next;
    }

    return curr->region;
}

void list_print(list_t *list)
{
    list_node_t *curr = list->head;
    if (list->head == NULL) {
        printf("none");
        return;
    }
    while (curr != NULL) {
        printf("(%lu, %lu),", curr->region->lower, curr->region->upper);
        curr = curr->next;
    }
}

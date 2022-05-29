#ifndef _COLLECTIONS_PATH_LIST_H
#define _COLLECTIONS_PATH_LIST_H

#include <aos/aos.h>

struct path_list_node {
    char *dir;
    struct path_list_node *next;
    struct path_list_node *prev;
};


struct path_list_node *init_new_path_list_node(char *dir, struct path_list_node *prev);

void free_path_list(struct path_list_node *head);

struct path_list_node *get_path_list(const char *orig_path);

void split_path(const char *full_path, char **path_prefix, char **fname);

/**
 * @brief Get the path dir prefix object
 *
 * @param path path
 * @return uint32_t index of last '/' in path, or -1 if no '/' found
 */
int get_path_dir_prefix(const char *name);

char *clean_path(const char *path);


#endif
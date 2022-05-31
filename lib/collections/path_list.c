#include <collections/path_list.h>
#include <aos/aos.h>

struct path_list_node *init_new_path_list_node(char *dir, struct path_list_node *prev)
{
    struct path_list_node *node = malloc(sizeof(struct path_list_node));
    node->dir = strdup(dir);
    node->next = NULL;
    node->prev = prev;
    return node;
}

void free_path_list(struct path_list_node *head)
{
    struct path_list_node *node = head;
    while (node != NULL) {
        struct path_list_node *next = node->next;
        free(node->dir);
        free(node);
        node = next;
    }
}

struct path_list_node *get_path_list(const char *orig_path)
{
    // copy path
    int N = strlen(orig_path);
    char *path = malloc(N + 1);
    memcpy(path, orig_path, N + 1);

    char *separator = "/";
    char *token = strtok(path, separator);

    if (!token) {
        // either no delimiter exists, or the path is empty, or the path
        // consists entirely of delimiters.

        if (*path == separator[0] || *path == 0) {
            free(path);
            return NULL;
        } else {
            free(path);
            return init_new_path_list_node(path, NULL);
        }
    }

    struct path_list_node *head = init_new_path_list_node(token, NULL);
    struct path_list_node *curr = head;
    while ((token = strtok(NULL, separator)) != NULL) {
        if (memcmp(token, ".", 2) == 0) {
            continue;
        } else if (memcmp(token, "..", 3) == 0) {
            if (curr->prev) {
                struct path_list_node *prev = curr->prev;
                free(curr);
                curr = prev;
                curr->next = NULL;
            }
            continue;
        }

        struct path_list_node *node = init_new_path_list_node(token, curr);
        curr->next = node;
        curr = node;
    }

    free(path);
    return head;
}

void split_path(const char *full_path, char **path_prefix, char **fname)
{
    // TODO malloc fail
    uint32_t last_separator = get_path_dir_prefix(full_path);
    if (last_separator == -1) {
        *path_prefix = strdup("");
        *fname = strdup(full_path);
    } else {
        int full_path_len = strlen(full_path);
        *path_prefix = malloc(last_separator + 1);
        *fname = malloc(full_path_len - last_separator + 1);

        memcpy(*path_prefix, full_path, last_separator);
        (*path_prefix)[last_separator] = '\0';
        memcpy(*fname, full_path + last_separator + 1, full_path_len - last_separator + 1);
    }
}

/**
 * @brief Get the path dir prefix object
 *
 * @param path path
 * @return uint32_t index of last '/' in path, or -1 if no '/' found
 */
int get_path_dir_prefix(const char *name)
{
    size_t N = strlen(name);

    for (int i = N - 1; i >= 0; i--) {
        if (name[i] == '/') {
            return i;
        }
    }
    return -1;
}

char *clean_path(const char *path)
{
    struct path_list_node *path_list = get_path_list(path);
    if (path_list == NULL) {
        if(strcmp(path, "/") == 0){
            return strdup("/");
        }
        return NULL;
    }

    // calculate total length
    size_t total_len = 0;
    struct path_list_node *curr = path_list;
    while (curr != NULL) {
        total_len += strlen(curr->dir) + 1;
        curr = curr->next;
    }

    // allocate memory
    char *cleaned_path = malloc(total_len + 1);
    if (cleaned_path == NULL) {
        return NULL;
    }

    curr = path_list;
    size_t offset = 0;
    while (curr != NULL) {
        cleaned_path[offset] = '/';
        offset++;

        size_t len = strlen(curr->dir);
        memcpy(cleaned_path + offset, curr->dir, len);
        offset += len;

        curr = curr->next;
    }
    cleaned_path[total_len] = '\0';

    DEBUG_PRINTF("clean path: %s\n", cleaned_path);

    return cleaned_path;
}

#include "name_tree.h"

static name_tree_t tree;

static errval_t name_node_new(char *name, name_node_t **ret)
{
    name_node_t *new = malloc(sizeof(name_node_t));
    if (new == NULL) {
        DEBUG_PRINTF("Failed to allocate new name node\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    new->name = malloc(strlen(name) + 1);
    if (new == NULL) {
        DEBUG_PRINTF("Failed to allocate memory for name\n");
        return LIB_ERR_MALLOC_FAIL;
    }
    new->name = strncpy(new->name, name, strlen(name));
    new->next_same_level = NULL;
    new->next_lower_level = NULL;
    new->info = NULL;

    *ret = new;

    return SYS_ERR_OK;
}

errval_t initialize_name_tree(void)
{
    errval_t err = name_node_new("root_node", &tree.root);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to create root node");
        return err_push(err, LIB_ERR_NAMESERVICE_NEW_NODE);
    }

    tree.num_nodes = 0;

    return SYS_ERR_OK;
}

/**
 * @brief Finds a node with the same name on a level
 *
 * @param node First node of the level
 * @param name to search for
 * @param ret Return pointer. Either the node we looked for, or the last node of the level
 * if we could not find the name on this level.
 *
 * @return error value: SYS_ERR_OK in case the name was found,
 * LIB_ERR_NAMESERVICE_UNKNOWN_NAME in case no node was found and no error ocurred, other
 * errors upon failure
 */
static errval_t find_name_on_level(name_node_t *node, char *name, name_node_t **ret)
{
    size_t len = strlen(name);

    for (; node->next_same_level != NULL; node = node->next_same_level) {
        if (strncmp(name, node->name, len) == 0) {
            // found the node
            *ret = node;
            return SYS_ERR_OK;
        }
    }

    *ret = node;
    if (strncmp(name, node->name, len) == 0) {
        return SYS_ERR_OK;
    } else {
        return LIB_ERR_NAMESERVICE_UNKNOWN_NAME;
    }
}

/**
 * @brief Insert name node into the name tree
 *
 * @param tree Pointer to the root of the tree
 * @param name Full name of the service
 * @param info Service info of the named service:w
 */
errval_t insert_name(char *name, service_info_t *info)
{
    errval_t err = SYS_ERR_OK;

    struct name_parts p;
    err = name_into_parts(name, &p);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to split name into parts\n");
        return err_push(err, LIB_ERR_NAMESERVICE_SPLIT_NAME);
    }

    name_node_t *node = tree.root;
    for (int i = 0; i < p.num_parts; i++) {
        if (node->next_lower_level == NULL) {
            // add new level
            name_node_t *new;
            err = name_node_new(p.parts[i], &new);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to create name node\n");
                err = err_push(err, LIB_ERR_NAMESERVICE_NEW_NODE);
                goto unwind;
            }
            node->next_lower_level = new;

            node = node->next_lower_level;

            tree.num_nodes++;
        } else {
            // find node in next level
            node = node->next_lower_level;

            name_node_t *find;
            err = find_name_on_level(node, p.parts[i], &find);
            if (err == LIB_ERR_NAMESERVICE_UNKNOWN_NAME) {
                // we need to insert a new node at the end
                name_node_t *new;
                err = name_node_new(p.parts[i], &new);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "Failed to create name node");
                    err = err_push(err, LIB_ERR_NAMESERVICE_NEW_NODE);
                    goto unwind;
                }
                find->next_same_level = new;
                node = find->next_same_level;
                tree.num_nodes++;
            } else if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failure during lookup of name on a level");
                goto unwind;
            } else {
                // found the node
                node = find;
            }
        }
    }

    // check if the name is already registered
    if (node->info != NULL) {
        //DEBUG_PRINTF("Failed to insert node as it already exists\n");
        err = LIB_ERR_NAMESERVICE_NODE_EXISTS;
        goto unwind;
    }

    node->info = info;

unwind:
    name_parts_contents_free(&p);
    return err;
}

errval_t find_name(char *name, service_info_t **ret)
{
    errval_t err = SYS_ERR_OK;

    struct name_parts parts;
    err = name_into_parts(name, &parts);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to split name");
        return err_push(err, LIB_ERR_NAMESERVICE_SPLIT_NAME);
    }

    name_node_t *node = tree.root;

    for (int i = 0; i < parts.num_parts; i++) {
        if (node->next_lower_level == NULL) {
            // we should not have reached the bottom yet
            err = LIB_ERR_NAMESERVICE_NOT_BOUND;
            goto unwind;
        }

        node = node->next_lower_level;
        err = find_name_on_level(node, parts.parts[i], &node);
        if (err_is_fail(err)) {
            if (err_no(err) == LIB_ERR_NAMESERVICE_UNKNOWN_NAME) {
                err = LIB_ERR_NAMESERVICE_NOT_BOUND;
                goto unwind;
            }

            DEBUG_ERR(err, "failed to find name %s on level %d\n", parts.parts[i], i);
            goto unwind;
        }
    }

    *ret = node->info;

unwind:
    name_parts_contents_free(&parts);
    return err;
}

static size_t tree_list_walk(name_node_t *node, size_t idx, service_info_t *list[])
{
    if (node == NULL || list == NULL) {
        return idx;
    }

    if (node->info != NULL) {
        list[idx++] = node->info;
    }

    // walk depth first
    if (node->next_lower_level != NULL) {
        idx = tree_list_walk(node->next_lower_level, idx, list);
    }

    if (node->next_same_level != NULL) {
        idx = tree_list_walk(node->next_same_level, idx, list);
    }

    return idx;
}

typedef struct {
    size_t len;
    service_info_t **list;
} service_info_list_t;


/**
 * @brief Returns a list with pointers to all service infos in the tree.
 *
 * @param tree The tree to list
 * @param retlist Pointer to the return list
 *
 * @return error code
 *
 * @note The returned list contains pointers to service infos, that are to be treated
 * read-only, as they are the service infos in the tree nodes.
 */
static errval_t list_service_infos(service_info_list_t *retlist)
{
    // TODO: allocate the number of services not the number of nodes. This is too much
    retlist->list = malloc(sizeof(service_info_t) * tree.num_nodes);
    if (retlist == NULL) {
        DEBUG_PRINTF("Failed to allocate service info list");
        return LIB_ERR_MALLOC_FAIL;
    }

    if (tree.num_nodes == 0) {
        retlist->len = 0;
        return SYS_ERR_OK;
    }

    retlist->len = tree_list_walk(tree.root->next_lower_level, 0, retlist->list);

    return SYS_ERR_OK;
}

errval_t print_service_names(void)
{
    service_info_list_t si_list;
    errval_t err = list_service_infos(&si_list);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to list service infos.");
        return err_push(err, LIB_ERR_NAMESERVICE_LIST_INFOS);
    }

    if (si_list.len == 0) {
        printf("There are no services registered.\n");
    }

    for (size_t i = 0; i < si_list.len; i++) {
        printf("service %d: %s\n", i, si_list.list[i]->name);
    }

    free(si_list.list);

    return SYS_ERR_OK;
}

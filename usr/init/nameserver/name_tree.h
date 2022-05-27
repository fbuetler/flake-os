#ifndef NAMESERVER_NAME_TREE_H__
#define NAMESERVER_NAME_TREE_H__

#include <aos/aos.h>
#include <aos/nameserver.h>


/**
 * @brief A name node stores a name and pointers to other nodes in the name tree
 * 
 * A node is the last node of a level if next_same_level == NULL.
 * A node is the name of a service iff info != NULL
 */
typedef struct name_node {
	char *name;
	struct name_node *next_same_level;
	struct name_node *next_lower_level;
	service_info_t *info;
} name_node_t;

typedef struct name_tree {
	name_node_t *root;
	size_t num_nodes;
} name_tree_t;

errval_t initialize_name_tree(void);
errval_t insert_name(char *name, service_info_t *info);
errval_t find_name(char *name, service_info_t **ret);
errval_t print_service_names(void);



#endif //NAMESERVER_NAME_TREE_H__

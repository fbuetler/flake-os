/**
 * \file nameservice.h
 * \brief
 */

#ifndef INCLUDE_NAMESERVICE_H_
#define INCLUDE_NAMESERVICE_H_

#include <aos/aos.h>
#include <aos/aos_rpc.h>

#define NAMESERVER_CORE 0

/**
 * @brief validates a name
 * 
 * @param name the name to validate
 *
 * @return bool
 */
bool name_is_valid(char *name);

struct name_parts {
    size_t num_parts;
	///< array of name parts
	///< needs to be freed before the struct is freed
    char **parts;
};

/**
 * @brief splits a name into its parts delimited by '.'
 * 
 * @param name string containing the name to split
 * @param ret pointer to an allocated name_parts structure
 * 
 * @return error value
 */
errval_t name_into_parts(char *name, struct name_parts *ret);
void name_parts_contents_free(struct name_parts *p);

///< handler which is called when a message is received over the registered channel
typedef void(nameservice_receive_handler_t)(void *st, 
										    void *message, size_t bytes,
										    void **response, size_t *response_bytes,
                                            struct capref tx_cap, struct capref *rx_cap);

typedef struct {
    struct aos_rpc rpc;
    nameservice_receive_handler_t *handler;
    void *st;
} *nameservice_chan_t;

struct nameservice_rpc_msg {
    nameservice_receive_handler_t *handler;
    void *st;
    void *message;
    size_t bytes;
};

/**
 * @brief sends a message back to the client who sent us a message
 *
 * @param chan opaque handle of the channel
 * @oaram message pointer to the message
 * @param bytes size of the message in bytes
 * @param response the response message
 * @param response_bytes the size of the response
 *
 * @return error value
 */
errval_t nameservice_rpc(nameservice_chan_t chan, void *message, size_t bytes, 
                         void **response, size_t *response_bytes, struct capref tx_cap,
                         struct capref *rx_cap);


/**
 * @brief registers our selves as 'name'
 *
 * @param name  our name
 * @param recv_handler the message handler for messages received over this service
 * @param st  state passed to the receive handler
 *
 * @return SYS_ERR_OK
 */
errval_t nameservice_register(const char *name, 
                              nameservice_receive_handler_t recv_handler, void *st);


/**
 * @brief deregisters the service 'name'
 *
 * @param the name to deregister
 *
 * @return error value
 */
errval_t nameservice_deregister(const char *name);


/**
 * @brief lookup an endpoint and obtain an RPC channel to that
 *
 * @param name  name to lookup
 * @param chan  pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_lookup(const char *name, nameservice_chan_t *chan);


/**
 * @brief enumerates all entries that match an query (prefix match)
 *
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries
 */
errval_t nameservice_enumerate(char *query, size_t *num, char **result);

typedef struct service_info {
    coreid_t core;
    nameservice_receive_handler_t *handle;
	void *handler_state;
    domainid_t pid;
    size_t name_len;
    ///< Full name of the service
    char name[0];
} service_info_t;

errval_t service_info_new(coreid_t core, nameservice_receive_handler_t *handle, void *handler_state,
                          domainid_t pid, const char *name, service_info_t **ret);


#endif /* INCLUDE_AOS_AOS_NAMESERVICE_H_ */

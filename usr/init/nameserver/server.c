#include "name_tree.h"
#include "server.h"
#include "../init_ump.h"

static errval_t register_service(service_info_t *info)
{
    errval_t err;

    size_t info_size = sizeof(service_info_t) + info->name_len;
    service_info_t *info_ptr = malloc(info_size);
    if (info_ptr == NULL) {
        DEBUG_PRINTF("Failed to allocate service info\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    memcpy(info_ptr, info, info_size);
    err = insert_name(info_ptr->name, info_ptr);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to insert name into name tree");
        return err_push(err, LIB_ERR_NAMESERVICE_NAME_INSERT);
    }

    print_service_names();

    return SYS_ERR_OK;
}

errval_t aos_process_service_register(char *payload, size_t bytes)
{
    errval_t err;

    if (disp_get_current_core_id() != NAMESERVER_CORE) {
        // relay to core where the nameserver resides
        size_t resp_bytes;
        errval_t *resp_err;
        aos_rpc_msg_type_t resp_type;
        err = aos_ump_call(&aos_ump_client_chans[NAMESERVER_CORE], AosRpcNsRegister,
                           payload, bytes, &resp_type, (char **)&resp_err, &resp_bytes);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to relay service registration to nameserver");
            return err_push(err, LIB_ERR_UMP_CALL);
        }

        assert(resp_type == AosRpcErrvalResponse);
        assert(resp_bytes == sizeof(errval_t));

        return *resp_err;
    }

    service_info_t *info = (service_info_t *)payload;
    if (bytes != sizeof(service_info_t) + info->name_len) {
        DEBUG_PRINTF("Invalid length for the service registration request\n");
        return LIB_ERR_MSGBUF_WRONG_SIZE;
    }

    err = register_service(info);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to register service");
        return err_push(err, LIB_ERR_NAMESERVICE_REGISTER);
    }

    return SYS_ERR_OK;
}

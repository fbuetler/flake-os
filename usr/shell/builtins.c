#include "builtins.h"
#include "helper.h"

#include <aos/aos_rpc.h>
#include <aos/aos.h>
#include <aos/deferred.h>
#include <fs/dirent.h>
#include <collections/path_list.h>


void help(char *args)
{
    write_str("Available commands:\n");
    write_str("help: this message\n");
    write_str("ps: TODO print process status\n");
    write_str("kill: TODO terminate a specific process\n");
    write_str("echo: write arguments back to screen\n");
    write_str("time: measure the runtime of a command\n");
    write_str("run_fg: run a process in the foreground\n");
    write_str("run_bg: run a process in the background\n");
}

static bool fs_path_exists(char *clean_path)
{
    fs_dirhandle_t dh;
    errval_t err = opendir(clean_path, &dh);
    if (err_is_fail(err)) {
        return false;
    }

    closedir(dh);
    return true;
}

static void write_no_such_dir(char *dir_path)
{
    write_str("cd: no such directory exists: ");
    write_str(curr_fs_path);
    write_str("\n");
}

void cd(char *args)
{
    if (args[0] != '/') {
        // concat curr_fs_path with args
        char *new_path = malloc(strlen(curr_fs_path) + 1 + strlen(args) + 1);
        strcpy(new_path, curr_fs_path);
        strcat(new_path, "/");
        strcat(new_path, args);

        char *cleaned_path = clean_path(new_path);
        free(new_path);

        debug_printf("clean path: %s\n", cleaned_path);

        if (!fs_path_exists(cleaned_path)) {
            write_no_such_dir(cleaned_path);
            free(cleaned_path);
        } else {
            free(curr_fs_path);
            curr_fs_path = cleaned_path;
        }
    } else {
        // absolute path
        char *new_path = clean_path(args);
        if (!new_path) {
            write_no_such_dir(args);
            return;
        }
        // check if path exists
        if (fs_path_exists(new_path)) {
            free(curr_fs_path);
            curr_fs_path = new_path;
        } else {
            write_no_such_dir(new_path);
            free(new_path);
        }
    }
}

void pwd(char *args)
{
    printf("%s\n", curr_fs_path);
}

void ls(char *args)
{
    fs_dirhandle_t dh;
    errval_t err = opendir(curr_fs_path, &dh);
    do {
        char *name;
        err = readdir(dh, &name);
        if (err_no(err) == FS_ERR_INDEX_BOUNDS) {
            break;
        } else if (err_is_fail(err)) {
            break;
        }
        printf("%s\n", name);
    } while (err_is_ok(err));

    closedir(dh);
}

void kill(char *args)
{
    write_str("kill\n");
}

void run_bg(char *args)
{
    // ToDo: add core_id
    if (args == NULL) {
        printf("run_fg: provide a binary name\n");
        return;
    }

    domainid_t pid;
    errval_t err = aos_rpc_process_spawn(get_init_rpc(), args, 0, &pid);
    if (err_pop(err) == SPAWN_ERR_FIND_MODULE) {
        printf("Could not find binary \"%s%\"\n", args);
        return;
    } else if (err_is_fail(err)) {
        printf("Failed to spawn process \"%s\"\n", args);
        return;
    }

    return;
}

void run_fg(char *args)
{
    // ToDo: add core_id
    if (args == NULL) {
        printf("run_fg: provide a binary name\n");
        return;
    }

    domainid_t pid;

    errval_t err;
    err = aos_rpc_process_spawn(get_init_rpc(), args, 0, &pid);
    if (err_pop(err) == SPAWN_ERR_FIND_MODULE) {
        printf("Could not find binary \"%s%\"\n", args);
        return;
    } else if (err_is_fail(err)) {
        printf("Failed to spawn process \"%s\"\n", args);
        return;
    }

    do {
        char *rname;
        err = aos_rpc_process_get_name(get_init_rpc(), pid, &rname);
        if (err == SPAWN_ERR_PID_NOT_FOUND) {
            break;
        } else if (err_is_fail(err)) {
            DEBUG_ERR(err, "Something went wrong \n");
        }
        thread_yield();
    } while (1);
}

/*
void spawn_hello(char **args) {
    abort();
    domainid_t pid;
    aos_rpc_process_spawn(get_init_rpc(), "hello", 0, &pid);
}
*/

void ps(char *args)
{
    domainid_t *pids;
    size_t pid_count;
    aos_rpc_process_get_all_pids(get_init_rpc(), &pids, &pid_count);
    printf("process count: %zu \n", pid_count);
    for (int i = 0; i < pid_count; i++) {
        char *pname;
        aos_rpc_process_get_name(get_init_rpc(), pids[i], &pname);
        printf("0x%x: %s\n", pids[i], pname);
    }
    free(pids);
}

void shell_exit(char *args)
{
    shell_state.exit = true;
    // write_str("exiting shell...\n");
    // shell_state.exit = true;

    /*
    size_t pid_count;
    domainid_t *pids;
    DEBUG_PRINTF("calling get_all_pids \n");
    aos_rpc_process_get_all_pids(shell_state.init_rpc, &pids, &pid_count);
    DEBUG_PRINTF("finished calling get_all_pids \n");
    DEBUG_PRINTF("PID count: %d\n", pid_count);

    for (int i = 0; i < pid_count; i++) {
        DEBUG_PRINTF("received pid: 0x%lx\n", pids[i]);
    }
     */
}

void echo(char *args)
{
    if (args != NULL) {
        printf("%s\n", args);
    }
}
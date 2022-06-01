#include "builtins.h"
#include "helper.h"

#include <aos/aos_rpc.h>
#include <aos/aos.h>
#include <aos/deferred.h>
#include <fs/dirent.h>
#include <collections/path_list.h>
#include <fs/fat32fs.h>
#include <fs/fs_rpc_requests.h>

void help(char *args)
{
    write_str("Available commands:\n");
    write_str("help: this message\n");
    write_str("ps: TODO print process status\n");
    write_str("kill: TODO terminate a specific process\n");

    write_str("echo: [argument...]\n");
    write_str("\t write the arguments back to the screen\n");
    write_str("time: command [argument...] \n");
    write_str("\t measure the runtime of a command\n");
    write_str("run_fg [core_id] process [argument...]\n");
    write_str("\t Run a process in the foreground. The default core is 0.\n");
    write_str("run_bg: [core_id] process [argument...]\n");
    write_str("\t Run a process in the background. The default core is 0.\n");

    write_str("cd: change directory\n");
    write_str("mkdir: create directory\n");
    write_str("rm: remove file\n");
    write_str("rmdir: remove directory\n");
    write_str("cat: print file content\n");
    write_str("fwrite [fname] [str]: writes [str] into [fname]\n");
    write_str("ls: list directory\n");

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


static char *format_path(char *path){
    char *new_path;
    if(path[0] != '/'){
        new_path = malloc(strlen(curr_fs_path) + 1 + strlen(path) + 1);
        strcpy(new_path, curr_fs_path);
        strcat(new_path, "/");
        strcat(new_path, path);
        char *cleaned_path = clean_path(new_path);
        free(new_path);
        return cleaned_path;
    }else{
        new_path = clean_path(path);
        return new_path;
    }
}

static void write_no_such_dir(char *dir_path){
    write_str("cd: no such directory exists: ");
    write_str(dir_path);
    write_str("\n");
}

void cd(char *args){
    if(!args){
        write_str("cd: no arguments given\n");
        return;
    }

    char *path = format_path(args);
    if(!path){
        write_str("cd: invalid path\n");
        return;
    }

    if(!fs_path_exists(path)){
        write_no_such_dir(path);
        free(path);
        return;
    }

    free(curr_fs_path);
    curr_fs_path = path;
}

void shell_mkdir(char *args){
    if(!args){
        write_str("mkdir: no name specified\n");
        return;
    }
    char *path = format_path(args);
    if(!path){
        write_str("mkdir: invalid path\n");
        return;
    }

    errval_t err = mkdir(path);
    if(err_is_fail(err)){
        write_str("mkdir: failed to create directory\n");
    }
    free(path);
}

void cat(char *args){

    if(!args){
        write_str("cat: no file specified\n");
        return;
    }

    char *path = format_path(args);

    FILE *f = fopen(path, "r");
    free(path);
    if(!f){
        write_str("cat: failed to open file\n");
        return;
    }

    char b[2];
    b[1] = 0;
    while(1){
        int c;
        c = fgetc(f);
        if(c == EOF){
            break;
        }
        b[0] = c;
        write_str(b);
    }
    fclose(f);

    write_str("\n");

}

void pwd(char *args)
{
    printf("%s\n", curr_fs_path);
}

void shell_rm(char *args){
    if(!args){
        write_str("rm: no file specified\n");
        return;
    }

    char *path = format_path(args);
    if(!path){
        write_str("rm: invalid path\n");
        return;
    }

    errval_t err = rm(path);
    if(err_is_fail(err)){
        if(err == FS_ERR_NOTFILE){
            write_str("rm: not a file\n");
        }else{
            write_str("rm: failed to remove file\n");
        }
    }

    free(path);
}

void shell_rmdir(char *args){
    if(!args){
        write_str("rmdir: no dir specified\n");
        return;
    }

    char *path = format_path(args);
    if(!path){
        write_str("rmdir: invalid path\n");
        return;
    }

    errval_t err = rmdir(path);
    if(err_is_fail(err)){
        if(err == FS_ERR_NOTDIR){
            write_str("rmdir: not a directory\n");
        }else{
            write_str("rmdir: failed to remove dir\n");
        }
    }

    free(path);
}

void shell_write(char *args){
    if(!args){
        write_str("write: no file specified\n");
        return;
    }

    char *buf = strchr(args, ' ');
    if(!buf){
        write_str("write: no data specified\n");
        return;
    }
    *buf = 0;
    buf++;

    char *unformatted_path = args;

    char *path = format_path(unformatted_path);
    if(!path){
        write_str("write: invalid path\n");
        return;
    }

    FILE *f = fopen(path, "w");
    if(!f){
        write_str("write: failed to open file\n");
        free(path);
        return;
    }

    while(*buf){
        fputc(*buf, f);
        buf++;
    }

    fclose(f);
    free(path); 
}

void ls(char *args){

    fs_dirhandle_t dh;
    errval_t err = opendir(curr_fs_path, &dh);
    do {
        char *name;
        struct fs_fileinfo fi;
        err = aos_rpc_fs_readdir(fs_chan, ((struct fat32fs_handle *)dh)->fid, &fi, &name);
        if (err_no(err) == FS_ERR_INDEX_BOUNDS) {
            break;
        } else if (err_is_fail(err)) {
            break;
        }
        write_str(name);
        if(fi.type == FS_DIRECTORY){
            write_str("/");
        }

        free(name);

        write_str("\n");
    } while(err_is_ok(err));

    closedir(dh);
}

void kill(char *args)
{
    write_str("kill\n");
}

void run_bg(char *args)
{
    domainid_t pid;
    spawn_process(args, &pid);
}

void run_fg(char *args)
{
    domainid_t pid;
    errval_t  err = spawn_process(args, &pid);
    if(err_is_fail(err)) {
        return;
    }

    do {
        char *rname;
        err = aos_rpc_process_get_name(shell_state.init_rpc, pid, &rname);
        if (err == SPAWN_ERR_PID_NOT_FOUND) {
            break;
        } else if (err_is_fail(err)) {
            DEBUG_ERR(err, "Something went wrong \n");
        }
        barrelfish_usleep(200 * 1000);
        thread_yield();
    } while (1);
}

void ps(char *args)
{
    domainid_t *pids;
    size_t pid_count;
    aos_rpc_process_get_all_pids(shell_state.init_rpc, &pids, &pid_count);
    printf("process count: %zu \n", pid_count);
    for (int i = 0; i < pid_count; i++) {
        char *pname;
        aos_rpc_process_get_name(shell_state.init_rpc, pids[i], &pname);
        printf("0x%x: %s\n", pids[i], pname);
    }
    free(pids);
}

void shell_exit(char *args)
{
    shell_state.exit = true;
}

void echo(char *args)
{
    if (args != NULL) {
        printf("%s\n", args);
    }
}
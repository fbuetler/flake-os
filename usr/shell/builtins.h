#ifndef BUILTINS_H
#define BUILTINS_H

int num_builtins(void);

void help(char *args);
void shell_exit(char *args);
void echo(char *args);
void ps(char *args);
void run_bg(char *args);
void run_fg(char *args);

void pwd(char *args);
void cd(char *args);
void ls(char *args);

void cat(char *args);
void shell_mkdir(char *args);

void shell_rm(char *args);
void shell_rmdir(char *args);
void shell_write(char *args);

char *curr_fs_path;

#endif

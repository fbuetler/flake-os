#ifndef BUILTINS_H
#define BUILTINS_H

int num_builtins(void);

void help(char *args);
void shell_exit(char *args);
void echo(char *args);
void ps(char *args);
void kill(char *args);
void run_bg(char *args);
void run_fg(char *args);

#endif

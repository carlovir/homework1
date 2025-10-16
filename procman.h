#ifndef PROCMAN_H
#define PROCMAN_H

#include <sys/types.h>

#define MAX_PROCESSES 10

typedef struct {
    pid_t pid;
    char command[256];
    time_t start_time;
    int status;  // 0=running, 1=terminated, -1=error
} process_info_t;

// Process creation and management
int create_process(const char *command, char *args[]);
int check_process_status(pid_t pid);
int terminate_process(pid_t pid, int force);

// Process table management
void add_process(pid_t pid, const char *command);
void remove_process(pid_t pid);
void update_process_status(pid_t pid, int status);
void list_processes(void);
void wait_all_processes(void);

// Signal handling
void sigint_handler(int signum);
void sigchld_handler(int signum);

// Process tree visualization
void print_process_tree(pid_t root_pid, int depth);

// Interactive shell
void interactive_shell(void);

#endif // PROCMAN_H



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>

#define MAX_PROCESSES 10

typedef struct {
    pid_t pid;
    char command[256];
    time_t start_time;
    int status;  // 0=running, 1=terminated, -1=error
} process_info_t;

process_info_t process_table[MAX_PROCESSES];
int process_count = 0;
int running = 1;

// === Part 1: Basic Process Management ===

int create_process(const char *command, char *args[]) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        // Child process
        if (execvp(command, args) == -1) {
            perror("execvp");
            _exit(EXIT_FAILURE);
        }
    }
    return pid;
}

int check_process_status(pid_t pid) {
    int status;
    pid_t result = waitpid(pid, &status, WNOHANG);
    if (result == 0) {
        // Still running
        return 1;
    } else if (result == -1) {
        perror("waitpid");
        return -1;
    } else {
        // Process terminated
        if (WIFEXITED(status)) {
            printf("Process %d exited with status %d\n", pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Process %d killed by signal %d\n", pid, WTERMSIG(status));
        }
        return 0;
    }
}

int terminate_process(pid_t pid, int force) {
    int sig = (force == 0) ? SIGTERM : SIGKILL;
    if (kill(pid, sig) == -1) {
        perror("kill");
        return -1;
    }
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }
    return 0;
}

// === Part 2: Process Manager ===

void add_process(pid_t pid, const char *command) {
    if (process_count >= MAX_PROCESSES) {
        fprintf(stderr, "Process table full\n");
        return;
    }
    process_table[process_count].pid = pid;
    strncpy(process_table[process_count].command, command, 255);
    process_table[process_count].command[255] = '\0';
    process_table[process_count].start_time = time(NULL);
    process_table[process_count].status = 0; // running
    process_count++;
}

void remove_process(pid_t pid) {
    for (int i = 0; i < process_count; i++) {
        if (process_table[i].pid == pid) {
            for (int j = i; j < process_count - 1; j++) {
                process_table[j] = process_table[j + 1];
            }
            process_count--;
            break;
        }
    }
}

void update_process_status(pid_t pid, int status) {
    for (int i = 0; i < process_count; i++) {
        if (process_table[i].pid == pid) {
            process_table[i].status = status;
            break;
        }
    }
}

void list_processes(void) {
    printf("PID\tCOMMAND\t\tRUNTIME\t\tSTATUS\n");
    printf("----\t-------\t\t-------\t\t------\n");
    time_t now = time(NULL);

    for (int i = 0; i < process_count; i++) {
        time_t elapsed = now - process_table[i].start_time;
        int hours = elapsed / 3600;
        int minutes = (elapsed % 3600) / 60;
        int seconds = elapsed % 60;
        const char *status_str = (process_table[i].status == 0) ? "Running" :
                                 (process_table[i].status == 1) ? "Terminated" : "Error";
        printf("%d\t%s\t\t%02d:%02d:%02d\t%s\n",
               process_table[i].pid,
               process_table[i].command,
               hours, minutes, seconds,
               status_str);
    }
}

void wait_all_processes(void) {
    for (int i = 0; i < process_count; i++) {
        pid_t pid = process_table[i].pid;
        if (process_table[i].status == 0) {
            int status;
            if (waitpid(pid, &status, 0) == -1) {
                perror("waitpid");
            } else {
                update_process_status(pid, 1);
            }
        }
    }
    printf("All processes have completed.\n");
}

// === Part 3: Signal Handling ===

void sigint_handler(int signum) {
    (void)signum;
    printf("\nShutting down gracefully...\n");
    for (int i = 0; i < process_count; i++) {
        if (process_table[i].status == 0) {
            kill(process_table[i].pid, SIGTERM);
        }
    }
    wait_all_processes();
    exit(0);
}

void sigchld_handler(int signum) {
    (void)signum;
    int status;
    pid_t pid;
    // Reap all terminated children
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        for (int i = 0; i < process_count; i++) {
            if (process_table[i].pid == pid) {
                process_table[i].status = 1; // terminated
                break;
            }
        }
    }
}

// === Part 4: Process Tree Visualization ===

pid_t get_ppid(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    pid_t ppid = -1;
    // Format: pid (comm) state ppid ...
    // Need to read up to 4th field
    int dummy_pid;
    char comm[256], state;
    if (fscanf(fp, "%d %255s %c %d", &dummy_pid, comm, &state, &ppid) != 4) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return ppid;
}

void print_process_tree(pid_t root_pid, int depth) {
    // Print indentation
    for (int i = 0; i < depth; i++) printf("  ");
    printf("[%d] ", root_pid);

    // Print command name
    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", root_pid);
    FILE *fp = fopen(cmdline_path, "r");
    if (fp) {
        char cmd[256] = {0};
        if (fgets(cmd, sizeof(cmd), fp) != NULL) {
            printf("%s\n", cmd);
        } else {
            printf("(unknown)\n");
        }
        fclose(fp);
    } else {
        printf("(unknown)\n");
    }

    // List children by scanning /proc
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;
    struct dirent *entry;
    pid_t children[MAX_PROCESSES];
    int child_count = 0;

    while ((entry = readdir(proc_dir)) != NULL && child_count < MAX_PROCESSES) {
        if (!isdigit(entry->d_name[0])) continue;
        pid_t pid = atoi(entry->d_name);
        pid_t ppid = get_ppid(pid);
        if (ppid == root_pid) {
            children[child_count++] = pid;
        }
    }
    closedir(proc_dir);

    for (int i = 0; i < child_count; i++) {
        print_process_tree(children[i], depth + 1);
    }
}

// === Part 5: Interactive Shell ===

void interactive_shell(void) {
    char input[512];
    while (running) {
        printf("ProcMan> ");
        if (!fgets(input, sizeof(input), stdin)) {
            printf("\n");
            break;
        }
        // Remove newline
        input[strcspn(input, "\n")] = '\0';

        if (strncmp(input, "help", 4) == 0) {
            printf(
                "Available commands:\n"
                "  create <command> [args...] - Create new process\n"
                "  list                       - List all processes\n"
                "  kill <pid> [force]         - Terminate process\n"
                "  tree                       - Show process tree\n"
                "  wait                       - Wait for all processes\n"
                "  quit                       - Exit program\n"
            );
        } else if (strncmp(input, "create ", 7) == 0) {
            char *cmdline = input + 7;
            char *args[64];
            int argc = 0;

            char *token = strtok(cmdline, " ");
            while (token && argc < 63) {
                args[argc++] = token;
                token = strtok(NULL, " ");
            }
            args[argc] = NULL;

            if (argc == 0) {
                printf("No command given\n");
                continue;
            }

            pid_t pid = create_process(args[0], args);
            if (pid == -1) {
                printf("Failed to create process\n");
            } else {
                add_process(pid, args[0]);
                printf("Created process %d\n", pid);
            }
        } else if (strcmp(input, "list") == 0) {
            list_processes();
        } else if (strncmp(input, "kill ", 5) == 0) {
            char *cmd = input + 5;
            char *pid_str = strtok(cmd, " ");
            char *force_str = strtok(NULL, " ");
            if (!pid_str) {
                printf("Usage: kill <pid> [force]\n");
                continue;
            }
            pid_t pid = atoi(pid_str);
            int force = (force_str && strcmp(force_str, "1") == 0) ? 1 : 0;
            if (terminate_process(pid, force) == 0) {
                update_process_status(pid, 1);
                printf("Terminated process %d %s\n", pid, force ? "forcefully" : "gracefully");
            } else {
                printf("Failed to terminate process %d\n", pid);
            }
        } else if (strcmp(input, "tree") == 0) {
            print_process_tree(getpid(), 0);
        } else if (strcmp(input, "wait") == 0) {
            wait_all_processes();
        } else if (strcmp(input, "quit") == 0) {
            printf("Shutting down...\n");
            running = 0;
        } else if (strcmp(input, "") == 0) {
            // do nothing on blank input
        } else {
            printf("Unknown command: %s\n", input);
        }
    }
}

int main() {
    // Set signal handlers
    signal(SIGINT, sigint_handler);
    signal(SIGCHLD, sigchld_handler);

    printf("ProcMan started. Type 'help' for commands.\n");
    interactive_shell();

    // Cleanup before exit - terminate running processes
    for (int i = 0; i < process_count; i++) {
        if (process_table[i].status == 0) {
            terminate_process(process_table[i].pid, 0);
        }
    }

    return 0;
}

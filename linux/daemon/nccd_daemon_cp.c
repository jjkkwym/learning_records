#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>

static void daemon_init()
{
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Catch, ignore and handle signals */
    //TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");

    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }
}

char *get_basename (char *path)
{
    char *s = strrchr (path, '/');

    return (s == NULL) ? path : ++s;
}

#define PROC_PATH "/home/flc/project/learning_records/linux/daemon/"
#define NCCD_SERVER_PATH PROC_PATH"nccd_server"
#define FTP_PATH PROC_PATH""
int start_process(char *proc_path)
{
    pid_t pid, child_pid;
    char *proc_name;
    child_pid = 0;

    if (access(proc_path, X_OK | F_OK) != 0) 
    {
        printf("process not exist\n");
        return 0;
    }
    proc_name = get_basename(proc_path);
    printf("proc_path :%s,procname:%s\n",proc_path,proc_name);

    pid = fork();
    if (pid < 0) 
    {
        return 0;
    }
    else if (pid == 0) 
    {
        if (execl(proc_path, proc_name, (char *)NULL) != -1) 
        {
            return 1;
        } 
        else 
        {
            return 0;
        }
    } 
    else 
    {
        printf("child pid:%d\n",pid);
        child_pid = pid;
    }

    return (int)child_pid;
}

typedef enum
{
    NCCD_SERVER = 0,
    FTP,
    MAX_PROC
}proc_pid_t;
pid_t proc_pid[MAX_PROC];

void print_proc_pid()
{
    int i;
    for(i = 0;i < MAX_PROC;i++)
    {
        printf("proc_pid[%d]:%d\n",i,proc_pid[i]);
    }
}

int find_proc_index(pid_t pid)
{
    int i;
    for(i = 0;i < MAX_PROC;i++)
    {
        if(pid == proc_pid[i])
        return i;
    }
    printf("pid not found\n");
    return -1;    
}

void start_process_by_proc_pid(int proc_pid_index)
{
    switch (proc_pid_index)
    {
    case NCCD_SERVER:
        proc_pid[NCCD_SERVER] = start_process(PROC_PATH"nccd_server");
        break;
    case FTP:
        proc_pid[FTP] = start_process(PROC_PATH"ftp");
        break;
    default:
        break;
    }
    printf("start proc_pid[%d] = %d\n",proc_pid_index,proc_pid[proc_pid_index]);
}
int log_fd;
char log_buf[256];

/* void write_log()
{
    sprintf(log_buf,));
    write(log_fd,log_buf,strlen(log_buf));
} */
int main()
{
    //daemon_init();
    time_t t;
    int status;
    pid_t exit_pid;
    int exit_pid_index;
    log_fd = open(PROC_PATH"nccd_daemon.log",O_RDWR | O_CREAT);
    
    printf("%s\n", asctime(localtime(&t)));
    pid_t nccd_server,ftp;
    proc_pid[NCCD_SERVER] = start_process(PROC_PATH"nccd_server");
    proc_pid[FTP] = start_process(PROC_PATH"ftp");
    print_proc_pid();
    while (1)
    {
        exit_pid = wait(&status);
        exit_pid_index=find_proc_index(exit_pid);           
        if(exit_pid_index >= 0 && exit_pid_index < MAX_PROC)
        {
            if(WIFEXITED(status))
            {
                
                printf("process proc_pid[%d]:%d exit normal\n",exit_pid_index,exit_pid);
                printf("the return code is %d\n",WEXITSTATUS(status));
            }
            else
            {
                printf("process proc_pid[%d]:%d exit abnormal\n",exit_pid_index,exit_pid);
            }
            printf("try restart proc_pid[%d]..\n",exit_pid_index);
            start_process_by_proc_pid(exit_pid_index);
        }
        else
        {
            printf("fault,exit_pid_index:%d\n",exit_pid_index);
        }
    }
    return EXIT_SUCCESS;
}
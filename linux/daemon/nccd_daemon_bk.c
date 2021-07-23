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
#include <sys/param.h>

int log_fd;
char log_buf[256];


#if 1
#define LOG(format,...)   \
    do                          \
    {                           \
        sprintf(log_buf,format,##__VA_ARGS__); \
        write(log_fd,log_buf,strlen(log_buf));  \
    }while(0)
#else
#define LOG(format,...) printf(format,##__VA_ARGS__);
#endif

int daemon_init(void)  
{   
    /* Our process ID and Session ID */
    pid_t pid, sid;
    
    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
            exit(EXIT_FAILURE);
    }
    /* If we got a good PID, then
       we can exit the parent process. */
    if (pid > 0) {
            exit(EXIT_SUCCESS);
    }
    /* Change the file mode mask */
    umask(0);
            
    /* Open any logs here */        
            
    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
            /* Log the failure */
            exit(EXIT_FAILURE);
    }
    
    
    /* Change the current working directory */
    if ((chdir("/")) < 0) {
            /* Log the failure */
            exit(EXIT_FAILURE);
    }
    
    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO); 
}

char *get_basename (char *path)
{
    char *s = strrchr (path, '/');

    return (s == NULL) ? path : ++s;
}

#define PROC_PATH "/home/flc/project/learning_records/linux/daemon/"

int start_process(char *proc_path)
{
    pid_t pid, child_pid;
    char *proc_name;
    child_pid = 0;

    if (access(proc_path, X_OK | F_OK) != 0) 
    {
        LOG("process not exist\n");
        return 0;
    }
    proc_name = get_basename(proc_path);
    LOG("proc_path :%s,procname:%s\n",proc_path,proc_name);

    pid = fork();
    if (pid < 0) 
    {
        LOG("process not exist\n");
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
        LOG("child pid:%d\n",pid);
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
        LOG("proc_pid[%d]:%d\n",i,proc_pid[i]);
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
    LOG("pid not found\n");
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
    LOG("start proc_pid[%d] = %d\n",proc_pid_index,proc_pid[proc_pid_index]);
}

int main()
{
    daemon_init();
    //time_t t;
    int status;
    pid_t exit_pid;
    int exit_pid_index;
    
    log_fd = open(PROC_PATH"nccd_daemon.log",O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    LOG("log_fd:%d\n",log_fd);
    //LOG("%s\n", asctime(localtime(&t)));
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
                LOG("process proc_pid[%d]:%d exit normal\n",exit_pid_index,exit_pid);
                LOG("the return code is %d\n",WEXITSTATUS(status));
            }
            else
            {
                LOG("process proc_pid[%d]:%d exit abnormal\n",exit_pid_index,exit_pid);
            }
            LOG("try restart proc_pid[%d]..\n",exit_pid_index);
            start_process_by_proc_pid(exit_pid_index);
        }
        else
        {
            LOG("fault,exit_pid_index:%d\n",exit_pid_index);
        }
    }
    close(log_fd);
    return EXIT_SUCCESS;
}
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
#include <sys/prctl.h>

int log_fd;
int config_fd;
char log_buf[256];

#define LOG_FILE 1
#if LOG_FILE
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
#if 0
#define PROC_PATH "/home/flc/project/learning_records/linux/daemon/"
#else
#define PROC_PATH "/mnt/UDISK/nccd/"
#endif
int start_process(char *proc_path)
{
    pid_t pid, child_pid;
    char *proc_name;
    child_pid = 0;

    if (access(proc_path, X_OK | F_OK) != 0) 
    {
        LOG("process not exist or execute\n");
        return 0;
    }
    proc_name = get_basename(proc_path);
    pid = fork();
    if (pid < 0) 
    {
        LOG("process not exist\n");
        return 0;
    }
    else if (pid == 0) 
    {
        prctl(PR_SET_PDEATHSIG,SIGKILL);
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
        //LOG("child pid:%d\n",pid);
        child_pid = pid;
    }
    LOG("%s process started\n",proc_name);
    return (int)child_pid;
}

typedef enum
{
    NCCD_SERVER = 0,
    FTP,
    MAX_PROC
}proc_pid_t;
pid_t proc_pid[MAX_PROC];

void print_proc_pid(int num)
{
    int i;
    for(i = 0;i < num;i++)
    {
        LOG("proc_pid[%d]:%d\n",i,proc_pid[i]);
    }
}

int find_proc_index(pid_t pid,int num)
{
    int i;
    for(i = 0;i < num;i++)
    {
        if(pid == proc_pid[i])
        return i;
    }
    LOG("pid not found\n");
    return -1;    
}

char proc_path[10][128];
void start_process_by_proc_pid(int proc_pid_index)
{
    proc_pid[proc_pid_index] = start_process(proc_path[proc_pid_index]);  
    LOG("start proc_pid[%d] = %d\n",proc_pid_index,proc_pid[proc_pid_index]);
}

#define MAX_PROC_NUM 10
int read_config_file(char *config_file_path)
{
    FILE *config_fd = fopen(config_file_path,"r");
    int num = 0; //process num
    if(config_fd == NULL)
    {
        LOG("open config file error\n");
        return 0;
    }
    char buf[128];
    while(fgets(buf,sizeof(buf),config_fd))
    {
        
        char *find = strchr(buf, ' ');  //找出data中的" "
        if(find)
            *find = '\0';   //替换
        find = strchr(buf, '\n');  //找出data中的"\n"
        if(find)
            *find = '\0';   //替换
        //LOG("readline:%s",buf);
        //check path
        if (access(buf, X_OK | F_OK) != 0) 
        {
            LOG("%s process not exist or execute\n",buf);
            continue;
        }
        strncpy(proc_path[num],buf,sizeof(proc_path[0]));
        num++;
        if(num > MAX_PROC_NUM)
        {
            break;
        }
    }
    fclose(config_fd);
    return num;
}

void signal_handler()
{
    LOG("signal recv,exit\n");
#if LOG_FILE
    close(log_fd);
#endif
    exit(0);
}

int main(int argc,char *argv[])
{
    int status;
    pid_t exit_pid;
    int exit_pid_index;
    int proc_num;
    signal(SIGTERM, signal_handler);
    char log_file_path[128],config_file_path[128];
    if(argc < 3)
    {
        printf("Usage:nccd_daemon config_file_path log_file_path\n");
        exit(0);
    }
    strncpy(config_file_path,argv[1],sizeof(config_file_path));
    strncpy(log_file_path,argv[2],sizeof(log_file_path));
    printf("log_file_path:%s\n",log_file_path);
    printf("config_file_path:%s\n",config_file_path);
#if LOG_FILE
    daemon_init();
    log_fd = open(log_file_path,O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
    proc_num = read_config_file(config_file_path);
    
    LOG("value process num:%d\n",proc_num);
    if(proc_num == 0)
    {
        LOG("no found exec,exit\n");
        exit(0);
    }
    int i = 0;
    for(i = 0;i < proc_num;i++)
    {
        proc_pid[i] = start_process(proc_path[i]);    
    }
    //print_proc_pid(proc_num);
    while (1)
    {
        exit_pid = wait(&status);
        exit_pid_index=find_proc_index(exit_pid,proc_num);           
        if(exit_pid_index >= 0 && exit_pid_index < proc_num)
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
//./nccd_daemon /mnt/UDISK/nccd/nccd_daemon.conf /mnt/UDISK/nccd/nccd_daemon.log
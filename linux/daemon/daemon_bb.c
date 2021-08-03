#include <unistd.h>   
#include <signal.h>   
#include <fcntl.h>  
#include <sys/syslog.h>  
#include <sys/param.h>   
#include <sys/types.h>   
#include <sys/stat.h>   
#include <stdio.h>  
#include <stdlib.h>  
#include <time.h>
#include <pthread.h>


#define PROC_NAME_CLIENT "/home/flc/project/learning_records/linux/daemon"
#define PROC_FILE_PATH   "/home/flc/project/learning_records/linux/daemon" 
/**************************************************************************************************
**  函数名称:  lockfile
**  功能描述:  对文件加锁/解锁
**  输入参数:  lock: 1表示进行加锁处理，0表示进行解锁处理
**  输出参数:  无
**  返回参数:  无
**************************************************************************************************/
int tryto_lockfile(int fd, int lock)
{
    struct flock fl;

    fl.l_type   = (lock == 1) ? F_WRLCK : F_UNLCK;
    fl.l_start  = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len    = 0;

    return (fcntl(fd, F_SETLK, &fl));
}

/**************************************************************************************************
**  函数名称:  get_proc_running_state
**  功能描述:  获取进程运行状态
**  输入参数:  无
**  输出参数:  无
**  返回参数:  返回-1表示路径错误
**  返回参数:  返回0表示进程从未运行过，返回1表示进程曾经运行过但是现在停止运行了，返回2表示进程正在运行中
**************************************************************************************************/
static int get_proc_running_state(const char* filename)
{
    int  fd;

    if (filename == NULL) {                                                    /* 文件名为空 */
        return -1;
    }

    fd = open(filename, O_RDWR, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));

    if (fd < 0) {                                                              /* 文件不存在，表示进程从未运行过 */
        return 0;
    }

    if (tryto_lockfile(fd, 1) == -1) {                                         /* 文件加锁失败，表示进程在运行中 */
        close(fd);
        return 2;
    } else {                                                                   /* 文件加锁成功，表示进程已经消失 */
        tryto_lockfile(fd, 0);                                                 /* 此处要注意记得解锁和关闭文件 */
        close(fd);
        return 1;
    }
}

/**************************************************************************************************
**  函数名称:  proc_watch
**  功能描述:  检测进程是否有在运行，没有运行则重新启动之
**  输入参数:  procname: 进程名
**  输出参数:  无
**  返回参数:  返回-1表示进程从未运行过；返回0表示进程当前运行正常；
**  返回参数:  返回其他非零值表示进程不存在且已被重新启动，返回的值是新的pid值
**************************************************************************************************/
int proc_watch(const char *procname)
{
    int  result, state;
    char filename[100];

    result = 0;

    sprintf(filename, "/var/run/%s.pid", procname);

    state = get_proc_running_state(filename);

    switch (state)
    {
        case 0:
            result = -1;
            break;

        case 1:
            result = start_proc_by_name(procname);
            break;

        case 2:
            result = 0;
            break;

        default:
            break;
    }

    return result;
}

/**************************************************************************************************
**  函数名称:  start_proc
**  功能描述:  启动进程开始运行
**  输入参数:  无
**  输出参数:  无
**  返回参数:  进程的ID号，若启动失败则返回0
**************************************************************************************************/
int start_proc_by_name(const char* procname)
{
    pid_t pid, child_pid;
    char  filename[100];

    sprintf(filename, "%s%s", PROC_FILE_PATH, procname);

    child_pid = 0;

    if (access(filename, X_OK | F_OK) != 0) {                                  /* 如果文件存在，并且可执行 */
        return 0;
    }

    pid = fork();                                                              /* 首先要fork一个进程出来 */

    if (pid < 0) {                                                             /* 创建进程失败 */
        return 0;
    } else if (pid == 0) {                                                     /* 创建进程成功，此处是子进程的代码 */
        if (execl(filename, procname, (char *)NULL) != -1) {
            return 1;
        } else {
            return 0;
        }
    } else {                                                                   /* 创建进程成功，此处是父进程代码 */
        child_pid = pid;
    }

    return (int)child_pid;
}

/**************************************************************************************************
**  函数名称:  thread_client_hdl
**  功能描述:  client进程监视线程
**  输入参数:  无
**  输出参数:  无
**  返回参数:  无
**************************************************************************************************/
static void *thread_client_hdl(void *pdata)
{
    int result;

    pdata = pdata;

    sleep(10);                                                /* 第一次要进行延时 */

    for (;;) {
        printf("time to check thread_client...\n");

        result = proc_watch(PROC_NAME_CLIENT);
        if (result == -1) {
            printf("thread_client never exist...\n");
        } else if (result == 0) {
            printf("thread_client running ok...\n");
        } else {
            printf("thread_client has gone! but restarted...\n");
        }
        sleep(10);
    }

    return NULL;
}

/**************************************************************************************************
**  函数名称:  main
**  功能描述:  入口主函数
**  输入参数:  无
**  输出参数:  无
**  返回参数:  无
**************************************************************************************************/
int main(int argc, char *argv[])
{
    int       client_para;
    char     *p, *process_name;
    pthread_t thread_client;

    process_name = argv[0];                                                    /* 获取进程名称 */

    p = process_name + strlen(process_name);

    while (*p != '/' && p != process_name) {
        p--;
    }

    if (*p == '/') {
        process_name = p + 1;
    }

    printf("\"%s\" starting...\n", process_name);

    client_para  = 0x01;

    if (pthread_create(&thread_client, NULL, thread_client_hdl, &client_para) != 0) {
        printf("create thread_client failed!\n");
        return 1;
    }

    if (start_proc_by_name(PROC_NAME_CLIENT) == 0) {
        printf("start thread_client failed!\n");
        return 1;
    }

    for (;;) {
        sleep(60);
        printf("i am still alive...\n");
    }

    return 0;
}
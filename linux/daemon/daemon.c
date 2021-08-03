#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
typedef struct
{
    int log_fd;
    int cfg_fd;
    char *log_path;
    char *cfg_path;
}daemon_data_t;

typedef struct
{
    char *process_basename;
    char *process_fullpath;
}cfg_file_info_t;

typedef struct pro_info_s
{
    pid_t proc_pid;
    char process_fullpath[128];
    char *process_basename;
    struct pro_info_s *next;
}proc_info_t;

int main(int argc,char *argv[])
{
    printf("argc:%d\n",argc);
    if(argc < 3)
    {
        printf("Usage:daemon cfg_file_path log_file_path\n");
        exit(1);
    }
    
    exit(0);
}
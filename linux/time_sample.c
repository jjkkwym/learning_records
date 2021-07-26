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
#include <sys/time.h>     // for timestamps
#include <stdarg.h>
static void printf_timestamp(char *timestamp,uint16_t len){
    struct tm* ptm;
    struct timeval curr_time;
    char time_string[40];
    gettimeofday(&curr_time, NULL);
    time_t curr_time_secs = curr_time.tv_sec;
    /* Obtain the time of day, and convert it to a tm struct. */
    ptm = localtime (&curr_time_secs);
    /* assert localtime was successful */
    if (!ptm) return;
    /* Format the date and time, down to a single second. */
    strftime (time_string, sizeof (time_string), "%Y-%m-%d %H:%M:%S", ptm);
    /* Compute milliseconds from microseconds. */
    uint16_t milliseconds = curr_time.tv_usec / 1000;
    /* Print the formatted time, in seconds, followed by a decimal point and the milliseconds. */
    snprintf (timestamp,len,"[%s.%03u]", time_string, milliseconds);
}
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

#define LOG(format,...) write_log(format,##__VA_ARGS__)
int log_fd;
void write_log(char *format,...)
{   
    char buf[512];
    int pos;
    va_list args;
    //char color[10];
    va_start(args,format);
    //printf("%s",buf);
    vsprintf(buf,format,args);
    va_end(args);
    printf("%s\n",buf);
} 

int main(int argc,char *argv[])
{
    char log_file_path[128];
    realpath(argv[1],log_file_path);
    printf("%s\n",log_file_path);
    //daemon_init();
    log_fd = open(log_file_path,O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    write_log("%s\n%s\n",log_file_path,"123");
    LOG("456\n");
    printf_timestamp();
    close(log_fd);
}



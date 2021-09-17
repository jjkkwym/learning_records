#include "log.h"
#include <stdio.h>
#include "fcntl.h"
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>

static const char *g_log_file_path = NULL;

off_t get_file_size(const char *filename) 
{ 
    struct stat sstat; 
    stat(filename, &sstat); 
    off_t size=sstat.st_size; 

    return size; 
}

void log_init(const char *log_file_path)
{
    if(log_file_path == NULL)
    {
        printf("log_file_path is null\n");
        return;
    }
    g_log_file_path = log_file_path;
    reset_log_file(log_file_path);
    printf("LOG_FILE_PATH:%s\n",g_log_file_path);
}

void reset_log_file(const char *log_file_path)
{
    if(log_file_path == NULL)
    {
        printf("log_file_path is null\n");
        return;
    }
    FILE *log_fp = fopen(g_log_file_path,"w+");
    if(log_fp == NULL)
    {
        printf("open log file error\n");
    }
    fclose(log_fp);
}

char *log_timestamp(void)
{
    static char timestamp[16] = {0};
    struct tm* ptm;
    struct timeval curr_time;
    char time_string[10];
    gettimeofday(&curr_time, NULL);
    time_t curr_time_secs = curr_time.tv_sec;
    /* Obtain the time of day, and convert it to a tm struct. */
    ptm = localtime (&curr_time_secs);
    /* assert localtime was successful */
    if (!ptm) return NULL;
    /* Format the date and time, down to a single second. */
    strftime (time_string, sizeof (time_string), "%H:%M:%S", ptm);
    /* Compute milliseconds from microseconds. */
    uint16_t milliseconds = curr_time.tv_usec / 1000;
    sprintf(timestamp,"%s.%03u",time_string,milliseconds);
    return timestamp;        
}

void write_log(const char *format,...)
{       
    char buf[512];
    va_list args;
    va_start(args,format);
    vsprintf(buf,format,args);
    va_end(args);
    //stdout 
    printf("%s",buf);
    if(g_log_file_path == NULL)
    {
        return;
    }

    if(get_file_size(g_log_file_path) > MAX_LOG_FILE_SIZE)
    {
        reset_log_file(g_log_file_path);
    }

    FILE *log_fp = fopen(g_log_file_path,"a+");
    if(log_fp == NULL)
    {
        printf("open log file error\n");
    }
    //write log file
    fprintf(log_fp,"%s\n",buf);
    fclose(log_fp);
}

void array_print(const char *str,uint8_t *data,uint16_t len)
{
#define WIDTH 16
#define __is_print(ch)       ((unsigned int)((ch) - ' ') < 127u - ' ')
    char print_char[WIDTH + 1];
    write_log("%s\n",str);
    for (int i = 0; i < len; i += WIDTH)
    {
        write_log("%04X-%04X: ",i,i + WIDTH - 1);
        for(int j = 0;j < WIDTH ;j++)
        {
            ((i + j) < len) ? write_log("%02X ",data[i + j]) : write_log("   ");
            sprintf(print_char + j,"%c", __is_print(data[i + j]) ? data[i + j] : '.');
        }
        print_char[WIDTH + 1] = '\0';
        write_log("\t%s\n",print_char);
    }
}

#include "log.h"
#include "time.h"
#include <sys/time.h>
void print_timesamp()
{
    struct tm *curr_tm;
    time_t curr_time;
    curr_time = time(NULL);
    curr_tm = localtime(&curr_time);
    printf(LOG_TIMESTAMP_COLOR"[%02d:%02d:%02d]"RESET,curr_tm->tm_hour,curr_tm->tm_min,curr_tm->tm_sec);
}

int get_timestamp(char *timestamp,uint16_t len){
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

void log_with_level(log_level_t log_level,char *format,...)
{
    char buf[512];
    char *pos = buf;
    int n;
    n = get_timestamp(buf,sizeof(buf));
    pos += n;
    va_list args;
    va_start(args,format);
    vsprintf(pos,format,args);
    va_end(args);    
    switch(log_level)
    {
    case  LOG_LEVEL_INFO:
        printf(LOG_INFO_COLOR"[INFO]   "RESET"%s\n",buf);
        break;
    case  LOG_LEVEL_DEBUG:
        PRINT(LOG_DEBUG_COLOR"[DEBUG]  "RESET"%s\n",buf);
        break;
    case  LOG_LEVEL_WARNING:
        PRINT(LOG_WARNING_COLOR"[WARNING]"RESET"%s\n",buf);
        break;
    case  LOG_LEVEL_ERROR:
        PRINT(LOG_ERROR_COLOR"[ERROR]  "RESET"%s\n",buf);
        break;
    default:
        break;
    }   
}
#include "log.h"
#include "time.h"
void print_timesamp()
{
    struct tm *curr_tm;
    time_t curr_time;
    curr_time = time(NULL);
    curr_tm = localtime(&curr_time);
    printf(LOG_TIMESTAMP_COLOR"[%02d:%02d:%02d]"RESET,curr_tm->tm_hour,curr_tm->tm_min,curr_tm->tm_sec);
}

void log_with_level(log_level_t log_level,char *format,...)
{
    char buf[512];
    int pos;
    va_list args;
    //char color[10];
    va_start(args,format);
    sprintf(buf,format,args);
    va_end(args);
    print_timesamp();
    switch(log_level)
    {
    case  LOG_LEVEL_INFO:
        PRINT(LOG_INFO_COLOR"[INFO]   "RESET"%s",buf);
        break;
    case  LOG_LEVEL_DEBUG:
        PRINT(LOG_DEBUG_COLOR"[DEBUG]  "RESET"%s",buf);
        break;
    case  LOG_LEVEL_WARNING:
        PRINT(LOG_WARNING_COLOR"[WARNING]"RESET"%s",buf);
        break;
    case  LOG_LEVEL_ERROR:
        PRINT(LOG_ERROR_COLOR"[ERROR]  "RESET"%s",buf);
        break;
    default:
        break;
    }   
}
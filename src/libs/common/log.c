#include "log.h"


void log_with_level(log_level_t log_level,char *format,...)
{
    char buf[512];
    va_list args;
    va_start(args,format);
    sprintf(buf,format,args);
    va_end(args);
    PRINT("%s",buf);
}
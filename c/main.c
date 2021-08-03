#include "common.h"
#include "log.h"

//对于传参中参数类型和个数不确定的格式转换，请使用 vsprintf
void write_log(char *format,...)
{   
    char buf[512];
    int pos;
    va_list args;
    //char color[10];
    va_start(args,format);
    //printf("%s",buf);
    vsnprintf(buf,sizeof(buf),format,args);
    va_end(args);
    printf("%s\n",buf);
} 


int main()
{
    write_log("test:%s","123");
    LOG_DEBUG("123");
    LOG_INFO("hello %s","world");
    
}
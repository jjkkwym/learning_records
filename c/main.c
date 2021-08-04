#include "common.h"
#include "log.h"
#include "list.h"
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


typedef struct pro_info_s
{
    int proc_pid;
    char process_fullpath[128];
    char *process_basename;
}proc_info_t;


void data_free(void *data)
{
    free(data);
}

const char *g_data;
void init(const char *data)
{
    g_data = data;
    printf("%s\n",g_data);
}
int main()
{
    const char *abc="abcdefg";
    init(abc);
    char buf[128];
    fprintf(stdout,"abc\n");
    write_log("test:%s","123");
    LOG_DEBUG("123");
    LOG_INFO("hello %s","world");
    list_t *list = list_new(data_free);
    proc_info_t *data = malloc(sizeof(proc_info_t));
    data->proc_pid = 1;
    memcpy(data->process_fullpath,"/mnt/",sizeof("/mnt/"));
    data->process_basename = data->process_fullpath; 
    list_append(list,data);
    printf("head:%p,length:%ld\n",list->head,list->length);
    list_free(list);
    int n;
    while(n = fread(buf,1,sizeof(buf),stdin))
    {
        printf("readsize:%d\n",n);
        sleep(1);
        printf("stdin:%s\n",buf);
    }
}
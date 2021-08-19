/* #include "common.h"
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
} */
#include "common.h"
#include <termios.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "pthread.h"
#include <time.h>
typedef struct
{
    uint32_t baudrate;
    int flow_control;
    const char *device_name;
} uart_config_t;

int uart_fd;
uart_config_t uart_config =
    {
        .baudrate = 115200,
        .flow_control = 0,
        .device_name = "/dev/ttyUSB0"};
static void uart_set_parity(struct termios *toptions, int parity)
{
    if (parity)
    {
        toptions->c_cflag |= PARENB;
    }
    else
    {
        toptions->c_cflag &= ~PARENB;
    }
}
static void uart_set_flow_control(struct termios *toptions, int flow_control)
{
    if (flow_control)
    {
        toptions->c_cflag |= CRTSCTS;
    }
    else
    {
        toptions->c_cflag &= ~CRTSCTS;
    }
}
static void uart_set_baudrate(struct termios *toptions, uint32_t baudrate)
{
    cfsetispeed(toptions, baudrate);
    cfsetospeed(toptions, baudrate);
}
bool uart_open(void)
{
    time_t now;
    struct tm ptm;
    const char *device_name = uart_config.device_name;
    const int flow_control = uart_config.flow_control;
    const uint32_t baudrate = uart_config.baudrate;
    struct termios toptions;
    char rx_buf[4048];
    char rx;
    int flags = O_RDWR | O_NOCTTY | O_NONBLOCK;
    uart_fd = open(device_name, flags);
    if (uart_fd == -1)
    {
        DEBUG("Unable to open port %s\n", device_name);
        return false;
    }
    if (tcgetattr(uart_fd, &toptions) < 0)
    {
        DEBUG("Couldn't get term attributes\n");
        return false;
    }
    cfmakeraw(&toptions);
    toptions.c_cflag &= ~CSTOPB;
    toptions.c_cflag |= CS8;
    toptions.c_cflag |= CREAD | CLOCAL;
    toptions.c_iflag &= ~(IXON | IXOFF | IXANY);
    toptions.c_cc[VMIN] = 0;
    toptions.c_cc[VTIME] = 0;
    uart_set_parity(&toptions, 0);
    uart_set_flow_control(&toptions, flow_control);
    cfsetispeed(&toptions, B115200);
    cfsetospeed(&toptions, B115200);
    if (tcsetattr(uart_fd, TCSANOW, &toptions) < 0)
    {
        DEBUG("Coundn't set term attributes");
        return false;
    }
    return true;
}
/* void print_timesamp()
{
    struct tm *curr_tm;
    time_t curr_time;
    curr_time = time(NULL);
    curr_tm = localtime(&curr_time);
    printf("[%02d:%02d:%02d]\n", curr_tm->tm_hour, curr_tm->tm_min, curr_tm->tm_sec);
} */
void *uart_read(void *args)
{
    char read_buf[1024];
    int read_len;
    int flag = 0;
    while (1)
    {
        read_len = read(uart_fd, read_buf, sizeof(read_buf));
        if (read_len > 0)
        {
            if (flag == 0)
            {
                //print_timesamp();
            }
            //printf("%s",read_buf);
            DEBUG_ARRAY("read_buf: ", read_buf, read_len);
            memset(read_buf, 0, sizeof(read_buf));
            fflush(stdout);
            flag = 1;
        }
        else
        {
            flag = 0;
        }
        usleep(20000);
    }
}
void *uart_write(void *args)
{
    char wirte_buf[1024];
    uint8_t wirte_buf_hex[1024];
    uint8_t hci_reset[] = {0x01, 0x03, 0x0c, 0x00};
    uint8_t hci_read_bdaddr[] = {0x01,0x09,0x10,0x00};
    write(uart_fd, hci_reset, sizeof(hci_reset));
    while (1)
    {
        scanf("%s", wirte_buf);
        //DEBUG_STR(wirte_buf);
        //StrToHex(wirte_buf_hex,wirte_buf,strlen(wirte_buf));
        //DEBUG_ARRAY(wirte_buf_hex,strlen(wirte_buf));
        write(uart_fd, wirte_buf, strlen(wirte_buf));
        write(uart_fd, "\r\n", 2);
    }
}
bool uart_init()
{
    pthread_t read_p, write_p;
    uint32_t rc;
    rc = uart_open();
    if (rc > 0)
    {
        pthread_create(&read_p, NULL, uart_read, NULL);
        DEBUG("create uart read thread");
        pthread_create(&write_p, NULL, uart_write, NULL);
        DEBUG("create uart write thread");
    }
    return rc;
}
int main()
{
    uart_init();
    
    int null_fd = open("/dev/null",O_WRONLY | O_TRUNC);
    dup2(null_fd,STDOUT_FILENO);
    dup2(null_fd,STDERR_FILENO);
    dup2(null_fd,STDIN_FILENO);
    close(null_fd);

    printf("123\n");
    //system("arecord 2.wav | aplay 2.wav");  
    while (1)
    {

    }
}
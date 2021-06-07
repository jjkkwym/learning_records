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
#define BLACK  "\033[22;30m"
#define GREEN  "\033[22;31m"
int uart_fd;
uart_config_t uart_config = 
{
    .baudrate = 115200,
    .flow_control = 0,
    .device_name = "/dev/ttyUSB0"
};
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
void print_timesamp()
{
    struct tm *curr_tm;
    time_t curr_time;
    curr_time = time(NULL);
    curr_tm = localtime(&curr_time);
    printf("\n[%02d:%02d:%02d]##RX##\n",curr_tm->tm_hour,curr_tm->tm_min,curr_tm->tm_sec);
}
void *uart_read(void *args)
{
    char read_buf[1024];
    int read_len;
    int flag = 0;
    while(1)
    { 
        read_len = read(uart_fd,read_buf,sizeof(read_buf));
        if(read_len > 0)
        {
            if(flag == 0)
            {
                print_timesamp();
            }
            printf("%s",read_buf);
            memset(read_buf,0,sizeof(read_buf));
            fflush(stdout);
            flag = 1;
        }
        else
        {
            flag = 0;
        }
        usleep(20000); //recive 
    }
}
void *uart_write(void *args)
{
    char wirte_buf[1024];
    uint8_t wirte_buf_hex[1024];
    while (1)
    {
        scanf("%s",wirte_buf);
        //DEBUG_STR(wirte_buf);
        //StrToHex(wirte_buf_hex,wirte_buf,strlen(wirte_buf));
        //DEBUG_ARRAY(wirte_buf_hex,strlen(wirte_buf));
        write(uart_fd,wirte_buf,strlen(wirte_buf));
        write(uart_fd,"\r\n",2);
    }
}
bool uart_init()
{
    pthread_t read_p,write_p;
    uint32_t rc;
    rc = uart_open();
    if(rc > 0)
    {
        pthread_create(&read_p,NULL,uart_read,NULL);
        //DEBUG("create uart read thread");
        pthread_create(&write_p,NULL,uart_write,NULL);
        //DEBUG("create uart write thread");
    }
    return rc;
}
int main(int argc,char *argv[])  //UASGE ./uart /dev/ttyUSBx
{
    printf("argc:%d\n",argc);
    if(argc == 2)    
    {
        uart_config.device_name = argv[1];
    }
    uart_init();

    while(1)
    {

    }
}
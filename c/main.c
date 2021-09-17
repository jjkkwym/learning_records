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
//test  abest 
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

//$4.13
#include "common.h"
#include <termios.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "pthread.h"
#include <time.h>
#include "log.h"
//Encodes Base64
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include "base64.h"
#include "cJSON.h"
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
    uint8_t hci_read_bdaddr[] = {0x01, 0x09, 0x10, 0x00};
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

int Base64Encode(const unsigned char *buffer, size_t length, char **b64text)
{ //Encodes a binary safe base 64 string
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text = (*bufferPtr).data;

    return (0); //success
}


void json_creat(char *buf)
{
    cJSON * root =  cJSON_CreateObject();

    cJSON_AddStringToObject(root, "PartNumber", "0000000001");
    cJSON_AddStringToObject(root, "Unique serial number", "0202107161");
    cJSON_AddStringToObject(root, "Model", "0000000001");
    cJSON_AddStringToObject(root, "Hardware Initial Version", "0000000101");
    cJSON_AddStringToObject(root, "Data Pack Initial Version", "0000000101");
    cJSON_AddStringToObject(root, "Maker", "0000000001");
    cJSON_AddStringToObject(root, "FCC", "0000000001");
    cJSON_AddStringToObject(root, "Manufacture Date", "0000000000");
    cJSON_AddStringToObject(root, "Project ID", "0202107161");
    cJSON_AddStringToObject(root, "MB Number", "0000000001");
    cJSON_AddStringToObject(root, "FW Version", "1.0.21.0716");
    cJSON_AddStringToObject(root, "Device Type", "1");
    cJSON_AddStringToObject(root, "Provision Status", "0");

    sprintf(buf,"%s", cJSON_Print(root));
    printf("%s",buf);
    cJSON_Delete(root);
}
void printJson(cJSON * root)//以递归的方式打印json的最内层键值对
{
    for(int i=0; i<cJSON_GetArraySize(root); i++)   //遍历最外层json键值对
    {
        cJSON * item = cJSON_GetArrayItem(root, i);        
        if(cJSON_Object == item->type)      //如果对应键的值仍为cJSON_Object就递归调用printJson
            printJson(item);
        else                                //值不为json对象就直接打印出键和值
        {
            printf("%s->", item->string);
            printf("%s\n", cJSON_Print(item));
        }
    }
}
void json_parse(char *buf)
{
    cJSON * root = NULL;
    cJSON * data = NULL;
    root = cJSON_Parse(buf);
    if(!root)
    {
        printf("Error before: [%s]\n",cJSON_GetErrorPtr());
    }
    else
    {
        printf("%s\n\n", cJSON_Print(root));
        //printf("%s\n\n", cJSON_PrintUnformatted(root));

        data = cJSON_GetObjectItem(root, "PartNumber");
        printf("type:%x,%s:",data->type ,data->string);
        printf("%s\n", data->valuestring);
        cJSON_ReplaceItemInObject(root,"PartNumber",cJSON_CreateString("123456"));
        data = cJSON_GetObjectItem(root, "PartNumber");
        printf("%s:", data->string);
        printf("%s\n", data->valuestring);
        data = cJSON_GetObjectItem(root, "Unique serial number");
        printf("%s:", data->string);
        printf("%s\n", data->valuestring); 
    }
    printf("%s", cJSON_Print(root));
}


int main()
{
    //uart_init();
    //char json_buf[1024];
    //json_creat(json_buf);
    //json_parse(json_buf);
    cJSON * root =  cJSON_CreateObject();
    cJSON_AddStringToObject(root, "PartNumber", "0000000001");
    cJSON_AddArrayToObject(root,"version_reports");
    printf("%s\n",cJSON_Print(root));

    char *base64EncodeOutput, *text = "6033e422c2a6acc6a175fb1eedde0f6c8eaf66b3737f6888cfbc379e20ea97e0";
    char buf[128];
    //base64_encode(text,buf,strlen(text));
    //printf("Output (base64): %s\n", buf);
    LOG_INFO("program pid: %d", getpid());
    LOG_INFO("program uid: %d", getuid());
    LOG_INFO("program gid: %d", getgid());
    char log_buf[512];
    for (int i = 0; i < 512; i++)
    {
        log_buf[i] = i;
    }
    //array_print("log_buf", log_buf, sizeof(log_buf) - 12);
    


    
    /* int null_fd = open("/dev/null", O_WRONLY | O_TRUNC);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);
    dup2(null_fd, STDIN_FILENO);
    close(null_fd);
    system("ls | grep log");
    char buf[1024];
    int n;
        
    int i = 0;

    system("arecord 2.wav | aplay 2.wav");
    while (1)
    {
        n = read(STDIN_FILENO, buf, sizeof(buf));
        printf("read %d len\n", n);
        if (n > 0)
        {
            printf("write %d len\n", n);
            LOG_HEXDUMP("stdin: ", buf, n);
            write(STDOUT_FILENO, buf, n);
        }
        else if (n == 0)
        {
            printf("end\n");
        }
        LOG_INFO("test");
        sleep(1);
    } */
}
#include "common.h"
#include "fcntl.h"
#include "signal.h"
#include <termios.h>

static size_t FlcGetLine(char **lineptr, size_t *n, FILE *stream)
{
    size_t i = 0;
    char* tmp = NULL;
    if (lineptr == NULL || n == NULL || stream == NULL) {
        return -1;
    }

    if (*lineptr == NULL) {
        *lineptr = (char*)malloc(*n * sizeof(char));
        tmp = *lineptr;
    }

    for (; i < *n; ) {
        if (fread(&tmp[i], sizeof(char), 1, stream)) {
            if (tmp[i] != EOF && tmp[i] != '\n') {
                i ++;
            } else {
                break;
            }
        } else {
            /*fread fail */
            return -1;
        }
    }

    if (i == 0 && tmp[i] == EOF) {
        return -1;
    } else {
        tmp[i == (*n - 1) ? i : ++ i] = 0;
        /*return the length of string, not include \0 */
        return i;
    }
}
static void sigint_handler(int param){
    //UNUSED(param);
    (void) param;
    printf("CTRL-C - SIGINT received, shutting down..\n");   
    
    struct termios term = {0};
    if (tcgetattr(0, &term) < 0){
        perror("tcsetattr()");
    }
    term.c_lflag |= ICANON;
    term.c_lflag |= ECHO;
    if (tcsetattr(0, TCSANOW, &term) < 0){
        perror("tcsetattr ICANON");
    }
    DEBUG("reset the stdin");
    //log_info("sigint_handler: shutting down");
    // reset anyway
    //btstack_stdin_reset();

    // power down
    //hci_power_control(HCI_POWER_OFF);
    //hci_close();
    //uint8_t reset[] = {0x01,0x03,0x0c,0x00};
    //printf("%02x %02x %02x %02x\n",hci_reset.opcode);
    //hci_send_cmd((uint8_t *)&hci_reset,sizeof(hci_reset));
    //log_info("Good bye, see you.\n");    
    exit(0);
}
int main()
{
    signal(SIGINT, sigint_handler);
    struct termios term = {0};
    if (tcgetattr(0, &term) < 0)
            perror("tcsetattr()");
    term.c_lflag &= ~ICANON;  // do not need to stdin add enter key
    term.c_lflag &= ~ECHO;    // no echo the input char
    if (tcsetattr(0, TCSANOW, &term) < 0) {
        perror("tcsetattr ICANON");
    }
    char data;
    
    while(1)
    {
        int result = read(0, &data, 1);
        if(result < 1)
        continue;
        else
        {
            DEBUG("recv:%c",data);
        }
        sleep(1);
        printf("test\n");
    }
    // char *s;
    // size_t len = 512;
    // FILE *fd = fopen("/home/flc/project/learning_record/test.c","r");
    // printf("%ld\n",FlcGetLine(&s,&len,fd));
    // while(FlcGetLine(&s,&len,fd))
    // {
    //     printf("%s\n",s);
    // }        
}

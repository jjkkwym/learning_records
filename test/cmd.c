#include "common.h"
#include "fcntl.h"
#include "signal.h"
#include <termios.h>

void (*packet_handler)(char c);
void reset_stdin(void)
{
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
}
void stdin_init(void (*handler)(char c)) //set
{
    struct termios term = {0};
    if (tcgetattr(0, &term) < 0)
            perror("tcsetattr()");
    term.c_lflag &= ~ICANON;  // do not need to stdin add enter key
    term.c_lflag &= ~ECHO;    // no echo the input char
    if (tcsetattr(0, TCSANOW, &term) < 0) {
        perror("tcsetattr ICANON");
    }
    packet_handler = handler;
}
static void sigint_handler(int param){
    //UNUSED(param);
    (void) param;
    printf("CTRL-C - SIGINT received, shutting down..\n");   
    reset_stdin();
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
void stdin_packet_handler(char c)
{
    DEBUG("process cmd %c",c);
    switch(c)
    {
        case '1':
            DEBUG("1");
            break;
        default:
            break;
    }

}
int main()
{
    signal(SIGINT, sigint_handler);
    stdin_init(stdin_packet_handler);
    char data;
    while(1)
    {
        int result = read(0, &data, 1);
        if(result < 1)
        continue;
        else
        {
            packet_handler(data);
        }
        //printf("test\n");
    }
}

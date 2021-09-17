#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#define NCCD_DAEMON_FIFO_PATH "/mnt/UDISK/daemon/nccd_daemon_fifo"
int main(int argc, char const *argv[])
{

    int fd = open(NCCD_DAEMON_FIFO_PATH, O_WRONLY);
    uint8_t buf = atoi(argv[1]);
    printf("buf:%02x\n",buf);
    write(fd, &buf,sizeof(buf));    
    close(fd);
    return 0;
}

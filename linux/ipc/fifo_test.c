#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#define FIFO_PATH "/home/flc/nccd_proj/daemon/nccd_daemon_fifo"

int main(void)
{
    int fd;
    int ret;

    if (access(FIFO_PATH, F_OK) != 0)
    {
        mkfifo(FIFO_PATH, 0666);
    }

    fd = open(FIFO_PATH, O_RDONLY | O_NONBLOCK);
    char read_buf[1024];
    while (1)
    {
        if ((ret = read(fd, read_buf, 1024)) > 0)
        {
            printf("ret:%d\n",ret);
            if(strcmp(read_buf,"bmp start") == 0)
            {
                printf("bmp start\n");
            }
            else
            {
                printf("reader got: %s\n", read_buf);
            }
        }
        sleep(2);
        printf("test\n");
    }
    close(fd);
    return 0;
}

#include "stdio.h"
#include "string.h"
#include "unistd.h"
#include "stdlib.h"
#include "fcntl.h"
int main()
{
    char buf[1024] = "hello world\n";
    //scanf("%s",buf);
    printf("%s", buf);
    int fd = open("./1.txt", O_RDWR | O_APPEND);
    write(fd, buf, strlen(buf));
    system("cat 1.txt");
    system("ls -al");

}

int the_day(int fa)
{
    printf("\n");
    printf("\n");
    printf("efef\n");
    printf("fefaf\n");
    return 0;
}
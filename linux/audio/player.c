#include "unistd.h"
#include "stdio.h"
#include "getopt.h"

static const char short_options[] = "hnld:";

static const struct option long_options[] = {
    {"help", 0, 0, 'h'},
    {"list-devnames", 0, 0, 'n'},
    {"list-devices", 0, 0, 'l'},
    {"device",1,0,'d'},
    {0,0,0,0}
};

char *name;
int main(int argc, char *argv[])
{
    int c;
    int option_index;
    char buf[128];
    fread(buf,sizeof(buf),sizeof(buf),stdin);
    printf("stdin:%s\n",buf);
    fclose(stdout);
    while ((c = getopt_long(argc, argv, short_options,
                long_options, &option_index)) != -1) {
        switch(c){
        case 'd':
            name = optarg;
            printf("%s\n",name);
            break;
        case 'h':
            printf("help\n");
            return;
        }
    }
    while (1)
    {
        /* code */
    }
}
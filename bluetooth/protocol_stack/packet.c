/******************************************************************************
**  Copyright (C) 2021 ~ , Flaircomm Technologies, Inc.
**
** FILE NAME
**   
**
** DESCRIPTION
**    
**
** History:
**  Author:    $
**  Revision:  $
**  Date:      $
**  Header:    $
/******************************************************************************
******************************************************************************/
#include "common.h"

inline void test(int i)
{
    i++;
    printf("i:%d\n", i);
}
int main()
{
    char read_buf[20];
    int rc;
    int i = 0;
    test(i);
    test(i);

    while (1)
    {
        rc = read(0, read_buf, sizeof(read_buf));
        read_buf[rc] = '\0';
        
        if (rc > 0)
        {
            printf("read_buf: %s", read_buf);
        }
    }
}

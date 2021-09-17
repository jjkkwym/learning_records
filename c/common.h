#ifndef __COMMON_H__
#define __COMMON_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <ctype.h>
#define DEBUG_INT(x)  printf(#x ":%d\n",x)
#define DEBUG_STR(x)  printf(#x ":%s\n",x)
#define DEBUG_CHAR(x) printf(#x ":%c\n",x)
#define DEBUG(format,...)   printf(format "\n",##__VA_ARGS__);
#define DEBUG_ARRAY(str,data,length)  array_print(str,data,length)


// #define INT_MAX  (int)(pow(2,31) - 1)
// #define INT_MIN  (int)(-pow(2,31))
#define ASSERT(EXPR)                                                 \
if (!(EXPR))                                                         \
{                                                                    \
    printf("(%s) has assert failed at %s:%ld.\n", #EXPR, __FUNCTION__, __LINE__); \
    while (1);                                                       \
}

#define CONCAT_2(p1, p2)     p1##p2
#define CONCAT_3(p1,p2,p3)   p1##p2#p3

//fetch the uint8
#define MSB_32(a) (((a) & 0xFF000000) >> 24)
#define LSB_32(a) ((a) & 0x000000FF)
#define MSB_16(a) (((a) & 0xFF00) >> 8)
#define LSB_16(a) ((a) & 0x00FF)

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) < (b) ? (b) : (a))

bool AsciiToHex(uint8_t *pbDest, char *pbSrc, int nLen);

#endif



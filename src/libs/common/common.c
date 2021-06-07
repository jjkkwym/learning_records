#include "common.h"

void array_print(const char *str,uint8_t *data,uint16_t length)
{
    int i;
    printf("%s",str);
    for(i = 0;i < length;i++)
    {
        printf("%02x ",data[i]);
    }
    printf("\n");
}


/******************************************************************************* 
    two ascii to one hex.example FF to 0xff. 
    nLen: the len of the pbSrc
********************************************************************************/
bool AsciiToHex(uint8_t *pbDest, char *pbSrc, int nLen)
{
    char h1, h2;
    char s1, s2;
    int i;
    uint8_t *temp = (uint8_t *)pbSrc;
    for (i = 0; i < nLen; i++)
    {
        if (isxdigit(*temp) == 0)
            return false;
        temp++;
    }
    for (i = 0; i < nLen / 2; i++)
    {
        h1 = pbSrc[2 * i];
        h2 = pbSrc[2 * i + 1];

        s1 = toupper(h1) - 0x30; //toupper 转换为大写字母
        if (s1 > 9)
            s1 -= 7;
        s2 = toupper(h2) - 0x30;
        if (s2 > 9)
            s2 -= 7;
        pbDest[i] = s1 * 16 + s2;
    }
    return true;
}
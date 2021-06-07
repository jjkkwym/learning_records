#include "common/common.h"

typedef struct
{
    /*! Connection identifier of remote device. */
    uint16_t                  cid;
    /*! Handle being accessed. */
    uint16_t                  handle;
    /*! Flags - uses ATT_ACCESS range. */
    uint16_t                  flags;
    /*! The offset of the first octet to be accessed. */
    uint16_t                  offset;
    /*! Length of the value. */
    uint16_t                  size_value;
    /*! Value data. */
    uint8_t                   value[1];
} GATT_ACCESS_IND_T;

int main()
{
    char buf[1024];
    scanf("%s",buf);
    printf("%s\n",buf);
}
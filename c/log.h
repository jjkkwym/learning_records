#ifndef LOG_H
#define LOG_H
#include <stdint.h>
#include <stdio.h>
#include "common.h"

#define MAX_LOG_FILE_SIZE (10*1024*1024)

typedef enum
{
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
}log_level_t;

/**
 * CSI(Control Sequence Introducer/Initiator) sign
 * more information on https://en.wikipedia.org/wiki/ANSI_escape_code
 */
#define CSI_START                      "\033["
#define CSI_END                        "\033[0m"
/* output log front color */
#define F_BLACK                        "30;"
#define F_RED                          "31;"
#define F_GREEN                        "32;"
#define F_YELLOW                       "33;"
#define F_BLUE                         "34;"
#define F_MAGENTA                      "35;"
#define F_CYAN                         "36;"
#define F_WHITE                        "37;"
/* output log background color */
#define B_NULL
#define B_BLACK                        "40;"
#define B_RED                          "41;"
#define B_GREEN                        "42;"
#define B_YELLOW                       "43;"
#define B_BLUE                         "44;"
#define B_MAGENTA                      "45;"
#define B_CYAN                         "46;"
#define B_WHITE                        "47;"
/* output log fonts style */
#define S_BOLD                         "1m"
#define S_UNDERLINE                    "4m"
#define S_BLINK                        "5m"
#define S_NORMAL                       "22m"

/* output log default color definition: [front color] + [background color] + [show style] */

#ifndef LOG_COLOR_INFO
    #define LOG_COLOR_INFO                F_CYAN B_NULL S_NORMAL
#endif
#ifndef LOG_COLOR_DEBUG
    #define LOG_COLOR_DEBUG               F_GREEN B_NULL S_NORMAL
#endif
#ifndef LOG_COLOR_WARN
    #define LOG_COLOR_WARN                F_YELLOW B_NULL S_NORMAL
#endif
#ifndef LOG_COLOR_ERROR
    #define LOG_COLOR_ERROR               F_RED B_NULL S_NORMAL
#endif

#define LOG(format,...)            write_log(format,##__VA_ARGS__)
#define LOG_INFO(format,...)       write_log("[%s][INFO]"format"\n",log_timestamp(),##__VA_ARGS__)
#define LOG_DEBUG(format,...)      write_log("[%s][DEBUG]"format"\n",log_timestamp(),##__VA_ARGS__)
#define LOG_WARNING(format,...)    write_log("[%s][WARNING]"format"\n",log_timestamp(),##__VA_ARGS__)
#define LOG_ERROR(format,...)      write_log("[%s][ERROR]"format"\n",log_timestamp(),##__VA_ARGS__)

#define LOG_HEXDUMP(str,data,length) array_print("[HEXDUMP] "str,data,length)
#define LOG_HEX(x)          printf(#x ":0x%02x\n",x)

char *log_timestamp(void);

void log_init(const char *log_file_path);

void write_log(const char *format,...);

void reset_log_file(const char *log_file_path);

void array_print(const char *str,uint8_t *data,uint16_t length);

#endif
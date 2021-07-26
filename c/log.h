#ifndef __LOG_H__
#define __LOG_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <ctype.h>

/* multi color and style output print */
#define RESET           "\033[1;0m"
#define BOLD            "\033[1;1m"
#define UNDERLINE       "\033[1;4m"
#define INVERSE         "\033[1;7m"
#define BOLD_OFF        "\033[1;21m"
#define UNDERLINE_OFF   "\033[1;24m"
#define INVERSE_OFF     "\033[1;27m"
#define BLACK           "\033[1;30m"
#define RED             "\033[1;31m"
#define GREEN           "\033[1;32m"
#define YELLOW          "\033[1;33m"
#define BLUE            "\033[1;34m"
#define MAGENTA         "\033[1;35m"
#define CYAN            "\033[1;36m"
#define WHITE           "\033[1;37m"

#define LOG_ERROR_COLOR   RED
#define LOG_WARNING_COLOR YELLOW
#define LOG_INFO_COLOR    GREEN
#define LOG_DEBUG_COLOR   BLUE
#define LOG_TIMESTAMP_COLOR CYAN

#define LOG_ERROR(format,...)   log_with_level(LOG_LEVEL_ERROR,format,##__VA_ARGS__)   
#define LOG_WARNING(format,...) log_with_level(LOG_LEVEL_WARNING,format,##__VA_ARGS__)
#define LOG_INFO(format,...)    log_with_level(LOG_LEVEL_INFO,format,##__VA_ARGS__)
#define LOG_DEBUG(format,...)   log_with_level(LOG_LEVEL_DEBUG,format,##__VA_ARGS__)

#define LOG_HEXDUMP_ERROR(p_data, len)   
#define LOG_HEXDUMP_WARNING(p_data, len) 
#define LOG_HEXDUMP_INFO(p_data, len)    
#define LOG_HEXDUMP_DEBUG(p_data, len) 

#define LOG_HEXDUMP

#define PRINT(format,...)      printf(format,__VA_ARGS__)

/* reset             0  (everything back to normal)
bold/bright       1  (often a brighter shade of the same colour)
underline         4
inverse           7  (swap foreground and background colours)
bold/bright off  21
underline off    24
inverse off      27 */


/* black        30         40
red          31         41
green        32         42
yellow       33         43
blue         34         44
magenta      35         45
cyan         36         46
white        37         47
 */
typedef enum 
{
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
}log_level_t;

void log_with_level(log_level_t log_level,char *format,...);

#endif
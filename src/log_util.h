/**
 * @file log_util.h
 * @brief
 * @version 1.0
 * @date 03/06/2016 07:57:53 PM
 * @author sammieliu,sammieliu@tencent.com 
 * @copyright Copyright 1998 - 2016 Tencent. All Rights Reserved.
 */
#ifndef  __LOG_UTIL_H__
#define  __LOG_UTIL_H__

#include <stdio.h>

namespace tcpdump_parser_ns {

#define LOG_ERROR(__fmt, __args...) do { \
    printf("[ERR:%s:%s:%d]" __fmt, __FILE__, __FUNCTION__, __LINE__, ##__args); \
} while (0)

}
#endif


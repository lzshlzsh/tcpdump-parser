/**
 * @file utility.h
 * @brief
 * @version 1.0
 * @date 03/06/2016 07:59:51 PM
 * @author sammieliu,sammieliu@tencent.com 
 * @copyright Copyright 1998 - 2016 Tencent. All Rights Reserved.
 */

#ifndef  __UTILITY_H__
#define  __UTILITY_H__

#include <ctype.h>
#include <stdio.h>

#include <string>

namespace tcpdump_parser_ns {
/**
 * @brief 
 * @class Utility
 */
class Utility
{
public:
    /**
     * @brief 
     * @param[in,out] str
     */
    static void remove_leading_space(std::string &str) {
        size_t pos;

        for (pos = 0; pos < str.length() && isspace(str[pos]); ++pos);
        if (pos) {
            str.erase(0, pos);
        }
    }
    /**
     * @brief 
     * @param[in,out] str
     */
    static void remove_trailing_space(std::string &str) {
        size_t pos, len = str.length();

        for (pos = len; static_cast<int>(pos - 1) >= 0 && isspace(str[pos - 1]); --pos);
        if (pos < len) {
            str.erase(pos, len - pos);
        }
    }
    /**
     * @brief 
     * @param[in] c
     * @return
     */
    static int hexadecimal_lower_char_to_int(const char c) {
        return isdigit(c) ? (c - '0') : (c - 'a' + 10);
    }
    /**
     * @brief 
     * @param[in] context
     */
    static void dump_buffer(const std::string &context) {
        size_t i;
        char buf[LINE_BYTES + 1];

        buf[LINE_BYTES] = '\0';

        for (i = 0; i < context.length(); i++) {
            if (!(i % LINE_BYTES)) {
                printf("\t0x%04lx:  ", i);
            }
            printf("%02x", static_cast<unsigned int>(static_cast<unsigned char>(context[i])));
            if (isprint(context[i])) {
                buf[i % LINE_BYTES] = context[i];
            } else {
                buf[i % LINE_BYTES] = '.';
            }
            if (i % 2) {
                printf(" ");
            }
            if (!((i + 1) % LINE_BYTES)) {
                printf(" %s\n", buf);
            }
        }

        if (i % LINE_BYTES) {
            for (; (i % LINE_BYTES); i++) {
                printf("  ");
                buf[i % LINE_BYTES] = ' ';
                if (i % 2) {
                    printf(" ");
                }
            }
            printf(" %s\n", buf);
        }
    }
protected:
private:
    enum {
        LINE_BYTES = 16,
    };
};
}
#endif


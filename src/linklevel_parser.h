/**
 * @file linklevel_parser.h
 * @brief
 * @version 1.0
 * @date 03/06/2016 10:00:13 PM
 * @author sammieliu,sammieliu@tencent.com 
 * @copyright Copyright 1998 - 2016 Tencent. All Rights Reserved.
 */

#ifndef  __LINKLEVEL_PARSER_H__
#define  __LINKLEVEL_PARSER_H__
#include <stdint.h>
#include <stdio.h>

#include <string>

#include "base_parser.h"

namespace tcpdump_parser_ns {
/**
 * @brief 
 * @class LinkLevelParser
 */
class LinkLevelParser: public BaseParser
{
public:
    enum {
        LINK_LEVEL_HEAD_LEN = 14,
        MAC_LEN = 6,
        TYPE_LEN = 2,

        TYPE_IP = 0x0800,
        TYPE_ARP = 0x0806,
        TYPE_RARP = 0x8035,
    };

    /**
     * @brief 
     * @param[in,out] context
     * @param[out] parser
     * @return 0 if success, < 0 otherwise
     */
    virtual int parse(std::string &context, BaseParser *&parser) {
        uint16_t type;

        parser = NULL;

        if (context.length() < LINK_LEVEL_HEAD_LEN) {
            LOG_ERROR("link level len error\n");
            return -1;
        }
        for (size_t i = MAC_LEN; i < (2 * MAC_LEN); i++) {
            if (i == MAC_LEN) {
                printf("%02x", static_cast<unsigned int>(
                        static_cast<unsigned char>(context[i])));
            } else {
                printf(":%02x", static_cast<unsigned int>(
                        static_cast<unsigned char>(context[i])));
            }
        }
        printf(" > ");
        for (size_t i = 0; i < MAC_LEN; i++) {
            if (!i) {
                printf("%02x", static_cast<unsigned int>(
                        static_cast<unsigned char>(context[i])));
            } else {
                printf(":%02x", static_cast<unsigned int>(
                        static_cast<unsigned char>(context[i])));
            }
        }
        printf("\n");
        type = htons(*reinterpret_cast<uint16_t *>(&context[LINK_LEVEL_HEAD_LEN
            - TYPE_LEN]));
        if (0x0000 == type) {
            if (context.length() < LINK_LEVEL_HEAD_LEN + TYPE_LEN) {
                LOG_ERROR("type len error\n");
                return -1;
            }
            type = htons(*reinterpret_cast<uint16_t *>(&context[LINK_LEVEL_HEAD_LEN]));
            context.erase(LINK_LEVEL_HEAD_LEN + TYPE_LEN);
        } else {
            context.erase(LINK_LEVEL_HEAD_LEN);
        }
        switch (type) {
        case TYPE_IP:
            printf("tpye: 0x%04x IP\n", type);
            break;
        case TYPE_ARP:
            printf("tpye: 0x%04x ARP\n", type);
            break;
        case TYPE_RARP:
            printf("tpye: 0x%04x RARP\n", type);
            break;
        default:
            LOG_ERROR("invalid type 0x%04x\n", type);
            return -1;
            break;
        }
        return 0;
    }
    /**
     * @brief 
     * @return
     */
    static LinkLevelParser &instance() {
        static LinkLevelParser inst;
        return inst;
    }
protected:
private:
};
}
#endif


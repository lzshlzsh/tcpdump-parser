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

#include "common_const.h"
#include "utility.h"
#include "base_parser.h"
#include "arp_parser.h"
#include "rarp_parser.h"
#include "ip_parser.h"

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
        Utility::dump_mac_addr(context.substr(MAC_LEN, MAC_LEN));
        printf(" > ");
        Utility::dump_mac_addr(context.substr(0, MAC_LEN));
        printf("\n");
        type = htons(*reinterpret_cast<uint16_t *>(&context[LINK_LEVEL_HEAD_LEN
            - TYPE_LEN]));
        if (0x0000 == type) {
            if (context.length() < LINK_LEVEL_HEAD_LEN + TYPE_LEN) {
                LOG_ERROR("type len error\n");
                return -1;
            }
            type = htons(*reinterpret_cast<uint16_t *>(&context[LINK_LEVEL_HEAD_LEN]));
            context.erase(0, LINK_LEVEL_HEAD_LEN + TYPE_LEN);
        } else {
            context.erase(0, LINK_LEVEL_HEAD_LEN);
        }
        switch (type) {
        case TYPE_IP:
            printf("tpye: 0x%04x IP\n", type);
            parser = &IpParser::instance();
            break;
        case TYPE_ARP:
            printf("tpye: 0x%04x ARP\n", type);
            parser = &ArpParser::instance();
            break;
        case TYPE_RARP:
            printf("tpye: 0x%04x RARP\n", type);
            parser = &RarpParser::instance();
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


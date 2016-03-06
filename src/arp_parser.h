/**
 * @file arp_parser.h
 * @brief
 * @version 1.0
 * @date 03/06/2016 10:17:11 PM
 * @author sammieliu,sammieliu@tencent.com 
 * @copyright Copyright 1998 - 2016 Tencent. All Rights Reserved.
 */

#ifndef  __ARP_PARSER_H__
#define  __ARP_PARSER_H__

#include "utility.h"
#include "base_parser.h"

namespace tcpdump_parser_ns {
/**
 * @brief 
 * @class ArpParser
 */
class ArpParser: public BaseParser
{
public:
    enum {
        ARP_LEN = 28,

        ARP_REQ = 0x0001,
        ARP_RSP = 0x0002,
    };
    /**
     * @brief 
     * @param[in,out] context
     * @param[out] parser
     * @return 0 if success, < 0 otherwise
     */
    virtual int parse(std::string &context, BaseParser *&parser) {
        size_t offset = 0;

        parser = NULL;
        if (context.length() < ARP_LEN) {
            LOG_ERROR("arp length error %d\n", context.length());
            return -1;
        }
        printf("hardware type: 0x%04x\n",
            ntohs(*reinterpret_cast<uint16_t *>(&context[offset])));
        offset += 2;
        printf("protocol type: 0x%04x\n", 
            ntohs(*reinterpret_cast<uint16_t *>(&context[offset])));
        offset += 2;
        printf("hardware size: %d\n", context[offset]);
        offset++;
        printf("protocol size: %d\n", context[offset]);
        offset++;
        printf("opcode: %d\n",
            ntohs(*reinterpret_cast<uint16_t *>(&context[offset])));
        offset += 2;
        printf("sender mac address: ");
        Utility::dump_mac_addr(context.substr(offset, MAC_LEN));
        offset += MAC_LEN;
        printf("\n");
        printf("sender ip address: ");
        Utility::dump_ip4(context.substr(offset, IP4_LEN));
        offset += IP4_LEN;
        printf("\n");
        printf("receiver mac address: ");
        Utility::dump_mac_addr(context.substr(offset, MAC_LEN));
        offset += MAC_LEN;
        printf("\n");
        printf("receiver ip address: ");
        Utility::dump_ip4(context.substr(offset, IP4_LEN));
        offset += IP4_LEN;
        printf("\n");
        return 0;
    }
    /**
     * @brief 
     * @return
     */
    static ArpParser &instance() {
        static ArpParser inst;
        return inst;
    }
protected:
private:
};

}
#endif


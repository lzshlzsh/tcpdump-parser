/**
 * @file tcpdump-parser.cpp
 * @brief
 * @version 1.0
 * @date 03/03/2016 11:13:43 PM
 * @author sammieliu,sammieliu@tencent.com 
 * @copyright Copyright 1998 - 2016 Tencent. All Rights Reserved.
 */
#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <iostream>

#include "log_util.h"
#include "utility.h"
#include "linklevel_parser.h"

namespace tcpdump_parser_ns {

/**
 * @brief 
 * @class Parser
 */
class Parser
{
public:
    /**
     * @brief 
     * @param[in] filename
     * @return 0 if success, < 0 otherwise
     */
    int usage(const char *filename) {
        std::cerr << "usage: " << filename << " [0|1]" << std::endl
            << "0: default, without link level head" << std::endl
            << "1: with link level head" << std::endl;
        return 0;
    }
    /**
     * @brief 
     * @[in] wt_ll with link level data
     * @return 0 if success, < 0 otherwise
     */
    int init(const bool wt_ll = false) {
        std::string line, context;
        size_t cxt_len = 0;

        context.resize(64 << 10);

        while (std::getline(std::cin, line)) {
            Utility::remove_leading_space(line);
            if (line.length() < ADDR_LEN || line[0] != '0' || (line[1] != 'x' && line[1] != 'X')) {
                continue;
            }
            line.erase(0, ADDR_LEN);
            Utility::remove_leading_space(line);
            if (line.length() < HEX_BYTE_LEN) {
                continue;
            }
            for (int i = 0; (i + 3) < HEX_BYTE_LEN; i += 5) {
                if (isspace(line[i])) {
                    break;
                }
                context[cxt_len] = 16 * Utility::hexadecimal_lower_char_to_int(line[i]);
                context[cxt_len++] += Utility::hexadecimal_lower_char_to_int(line[i + 1]);
                context[cxt_len] = 16 * Utility::hexadecimal_lower_char_to_int(line[i + 2]);
                context[cxt_len++] += Utility::hexadecimal_lower_char_to_int(line[i + 3]);
            }
        }
        context.resize(cxt_len);

        return init(context, wt_ll);
    }
    /**
     * @brief 
     * @param[in] context
     * @[in] wt_ll with link level data
     * @return 0 if success, < 0 otherwise
     */
    int init(const std::string &context, const bool wt_ll = false) {
        context_ = context;
        wt_ll_ = wt_ll;
        Utility::dump_buffer(context);
        return 0;
    }
    /**
     * @brief 
     * @return 0 if success, < 0 otherwise
     */
    int parse() {
        BaseParser *parser = NULL;
        if (wt_ll_) {
            parser = &LinkLevelParser::instance();
        }
        while (parser) {
            if (parser->parse(context_, parser)) {
                return -1;
            }
        }
        
        return 0;
    }
protected:
private:
    enum {
        ADDR_LEN = 7,
        HEX_BYTE_LEN = 39,
    };
    std::string context_;
    bool wt_ll_;
};
}

using namespace tcpdump_parser_ns;

/**
 * @brief 
 * @param[in]
 * @param[in,out]
 * @param[out]
 * @return 0 if success, < 0 otherwise
 */
int main(int argc, char **argv) {
    Parser parser;
    bool wt_ll = false;

    parser.usage(argv[0]);

    if (argc >= 2) {
        wt_ll = (atoi(argv[1]) != 0);
    }
    if (parser.init(wt_ll)) {
        LOG_ERROR("init failed\n");
        return -1;
    }
    if (parser.parse()) {
        LOG_ERROR("parse failed\n");
    }
    return 0;
}


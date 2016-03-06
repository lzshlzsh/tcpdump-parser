/**
 * @file rarp_parser.h
 * @brief
 * @version 1.0
 * @date 03/06/2016 10:33:37 PM
 * @author sammieliu,sammieliu@tencent.com 
 * @copyright Copyright 1998 - 2016 Tencent. All Rights Reserved.
 */

#ifndef  __RARP_PARSER_H__
#define  __RARP_PARSER_H__

#include "log_util.h"
#include "base_parser.h"

namespace tcpdump_parser_ns {
/**
 * @brief 
 * @class RarpParser
 */
class RarpParser: public BaseParser
{
public:
    /**
     * @brief 
     * @param[in,out] context
     * @param[out] parser
     * @return 0 if success, < 0 otherwise
     */
    virtual int parse(std::string &context, BaseParser *&parser) {
        parser = NULL;
        LOG_ERROR("rapr parser not implemented\n");
        return -1;
    }
    /**
     * @brief 
     * @return
     */
    static RarpParser &instance() {
        static RarpParser inst;
        return inst;
    }
protected:
private:
};

}
#endif


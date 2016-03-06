/**
 * @file base_parser.h
 * @brief
 * @version 1.0
 * @date 03/06/2016 09:59:19 PM
 * @author sammieliu,sammieliu@tencent.com 
 * @copyright Copyright 1998 - 2016 Tencent. All Rights Reserved.
 */
#ifndef  __BASE_PARSER_H__
#define  __BASE_PARSER_H__

#include <string>

namespace tcpdump_parser_ns {
/**
 * @brief 
 * @class BaseParser
 */
class BaseParser
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
        return 0; 
    }
    /**
     * @brief 
     * @return
     */
    static BaseParser &instance() {
        static BaseParser inst;
        return inst;
    }
protected:
    /**
     * @brief
     */
    BaseParser() {}
    /**
     * @brief
     */
    BaseParser(const BaseParser &);
    /**
     * @brief
     */
    BaseParser &operator = (const BaseParser &);
private:
};
}
#endif


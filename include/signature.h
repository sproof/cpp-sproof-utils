
#ifndef SPROOF_UTILS_SIGNATURE_H
#define SPROOF_UTILS_SIGNATURE_H

#include <string>

#include <jsoncpp/json/json.h>

namespace sproof {

    struct Signature {
        std::string r;
        std::string s;
        int v;
    };

}


#endif //SPROOF_UTILS_SIGNATURE_H

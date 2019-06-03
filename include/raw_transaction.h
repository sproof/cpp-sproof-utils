

#ifndef SPROOF_UTILS_RAW_TRANSACTION_H
#define SPROOF_UTILS_RAW_TRANSACTION_H

#include <vector>
#include <cstdint>

#include <jsoncpp/json/json.h>

namespace sproof {

    class RawTransaction {

    public:

        static RawTransaction from_json(const Json::Value &json);

        std::vector<uint8_t> encoded() const;
        void sign(const std::string& private_key_hex);

    private:
        std::vector<uint8_t> m_nonce;
        std::vector<uint8_t> m_gas_price;
        std::vector<uint8_t> m_gas_limit;
        std::vector<uint8_t> m_to;
        std::vector<uint8_t> m_value;
        std::vector<uint8_t> m_data;
        std::vector<uint8_t> m_signature;
        long int m_chain_id;
    };

}

#endif //SPROOF_UTILS_RAW_TRANSACTION_H

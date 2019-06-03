

#include "raw_transaction.h"
#include "sproof-utils.h"



namespace sproof {

    namespace {

        std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
            const std::string hex_string = utils::remove_hex_prefix(hex);
            std::vector<uint8_t> result_vector;
            for (unsigned int i = 0; i < hex_string.length(); i += 2) {
                std::string byteString = hex_string.substr(i, 2);
                auto byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
                result_vector.push_back(byte);
            }
            return result_vector;
        }

    }

    RawTransaction RawTransaction::from_json(const Json::Value &json) {

        RawTransaction transaction;

        Json::Value rawTrans = json["rawTransaction"];
        transaction.m_nonce = hex_to_bytes(rawTrans["nonce"].asString());
        transaction.m_gas_limit = hex_to_bytes(rawTrans["gasLimit"].asString());
        transaction.m_gas_price = hex_to_bytes(rawTrans["gasPrice"].asString());
        transaction.m_to = hex_to_bytes(rawTrans["to"].asString());
        transaction.m_data = hex_to_bytes(rawTrans["data"].asString());
        transaction.m_value = hex_to_bytes(rawTrans["value"].asString());

        return transaction;
    }

    std::vector<uint8_t> RawTransaction::encoded() const {
        return std::vector<uint8_t>();  //TODO: implementieren
    }

    void RawTransaction::sign(const std::string& private_key_hex) {
        //TODO: signen
    }

}

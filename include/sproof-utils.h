#ifndef _SPROOF_UTILS_H
#define _SPROOF_UTILS_H

#include <vector>
#include <string>
#include <chrono>

#include "credentials.h"
#include "signature.h"
#include "raw_transaction.h"

namespace sproof
{
namespace utils
{

bool is_hash(const std::string& str);

std::string as_hex(const std::vector<uint8_t>& bytes);
std::string as_hex(const std::string& data);
std::string as_hex_with_prefix(const std::vector<uint8_t>& bytes);
std::string remove_hex_prefix(const std::string& hash);

std::string get_hash(const std::vector<uint8_t>& bytes);
std::string get_hash(const std::string& str);

std::chrono::seconds unix_time();
bool is_time_in_range(std::chrono::seconds valid_from, std::chrono::seconds valid_until);

std::string get_salt();

std::string public_key_to_address(const std::vector<uint8_t>& public_key);

sproof::Credentials get_credentials();
sproof::Credentials restore_credentials(const std::string& mnemonic);

std::string base64_encode(const std::string &data);
std::string base64_decode(const std::string &in);

Signature sign(const std::string& message, const Credentials& credentials);
bool verify(const std::string& message, const Signature& signature, const std::string& public_key);

std::pair<std::string,std::string> sign_transaction(RawTransaction& transaction, const Credentials& credentials);

std::string encrypt(const std::string& public_key, const std::string& data);
std::string decrypt(const std::string& private_key, const std::string& data);

}
}

#endif

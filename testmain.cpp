

#include <iostream>

#include "sproof-utils.h"


int main(int argc, char **argv)
{
  const std::vector<uint8_t> testbytes{1,2,3,4,5,6,7,8,9,0};
  std::string result = sproof::utils::as_hex(testbytes);

  std::cout << result << std::endl;

  result = sproof::utils::as_hex_with_prefix(testbytes);
  std::cout << result << std::endl;

  std::string test_string = "asdfasdfasdf";
  result = sproof::utils::get_hash(test_string);
  std::cout << result << std::endl;
  bool ishash = sproof::utils::is_hash(result);
  std::cout << ishash << std::endl;

  result = sproof::utils::remove_hex_prefix(result);
  std::cout << result << std::endl;
  result = sproof::utils::remove_hex_prefix(result);
  std::cout << result << std::endl;

  sproof::Credentials cred = sproof::utils::get_credentials();

  sproof::Credentials cred2 = sproof::utils::restore_credentials("symptom furnace insect easy egg rubber lend boil shell beauty february remind");
  std::cout << cred2.get_address() << std::endl;

//  sproof::Signature signature = sproof::utils::sign("foobar", cred2);
//  bool is_valid = sproof::utils::verify("foobar", signature, cred2.get_public_key());
//
//    if(is_valid)
//        std::cout << "Verified signature on message" << std::endl;
//    else
//        std::cerr << "Failed to verify signature on message" << std::endl;

    sproof::Signature java_sig{};
    java_sig.r = "44c615561bd3a4b6fc1029fe5ea6d91cf9b17fda07bff186b3939b42a7574fb1";
    java_sig.s = "fb829e6cce56466323a6bffabee423bed0c36f8e9c739a19d7d2a1fcfa344523";
    std::string pub = "75c776a51693451f41677da145ec6b8c0e07c6d9d88457398ffb9016c221a46013e5164f66be52c4e7c9d0a4415233880db87f887e252117399670e9088bcd38";

    bool is_valid = sproof::utils::verify("foobar", java_sig, pub);

    if(is_valid)
        std::cout << "Verified signature on message" << std::endl;
    else
        std::cerr << "Failed to verify signature on message" << std::endl;


    std::string encr = sproof::utils::encrypt(cred2.get_public_key(), "ich bin ein ber...teststring");
    std::cout << encr << std::endl;
    std::string decr = sproof::utils::decrypt(cred2.get_private_key(), encr);
    std::cout << decr << std::endl;

  return 0;
}

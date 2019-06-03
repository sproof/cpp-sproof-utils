
#include "config.h"

#include "sproof-utils.h"

void test_get_credentials();
void test_restore_credentials();
void test_encrypt_decrypt();


int main(int argc, char** argv)
{
    test_get_credentials();
    test_restore_credentials();

    test_encrypt_decrypt();

    return 0;
}



void test_get_credentials() {

    TEST_BEGIN("test_get_credentials");

    sproof::Credentials credentials = sproof::utils::get_credentials();

    ASSERT_EQUAL(true, is_hex(credentials.get_address()));
    ASSERT_EQUAL(42, credentials.get_address().length());
    ASSERT_EQUAL(true, is_hex(credentials.get_public_key()));
    ASSERT_EQUAL(true, is_hex(credentials.get_private_key()));

    int count = 0;
    for(const auto& c : credentials.get_seed())
    {
        if(c == ' ')
            count++;
    }
    ASSERT_EQUAL(11, count);

    TEST_END();
}

void test_restore_credentials() {

    TEST_BEGIN("test_restore_credentials");

    sproof::Credentials c1 = sproof::utils::get_credentials();
    sproof::Credentials c2 = sproof::utils::restore_credentials(c1.get_seed());

    ASSERT_EQUAL(true, c1 == c2);

    TEST_END();

}

void test_encrypt_decrypt() {

    TEST_BEGIN("test_encrypt_decrypt");

    const sproof::Credentials creds = sproof::utils::get_credentials();
    const std::string text{"{\"a\":\"b\",\"c\":\"d\"}"};


    const std::string encrypted = sproof::utils::encrypt(creds.get_public_key(), text);
    const std::string decrypted = sproof::utils::decrypt(creds.get_private_key(), encrypted);

    ASSERT_STRING_EQUAL(text, decrypted);

    TEST_END();

}
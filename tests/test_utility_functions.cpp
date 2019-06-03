
#include "config.h"

#include "sproof-utils.h"

void test_get_salt();
void test_base64_encode();

int main(int argc, char** argv)
{
    test_get_salt();
    test_base64_encode();

    return 0;
}



void test_get_salt() {

    TEST_BEGIN("test_get_salt");

    std::string salt = sproof::utils::get_salt();
    ASSERT_EQUAL(64 + 2, salt.length());

    TEST_END();
}

void test_base64_encode() {

    TEST_BEGIN("test_base64_encode");

    const std::string teststring{"some test text \x01 \x25 \x76"};
    std::string base64 = sproof::utils::base64_encode(teststring);
    std::string result = sproof::utils::base64_decode(base64);

    ASSERT_STRING_EQUAL(teststring, result);

    TEST_END();

}


#include "config.h"

#include "sproof-utils.h"


void test_is_hash();

void test_get_hash_vector();

void test_get_hash_string();

int main(int argc, char** argv)
{

    test_is_hash();
    test_get_hash_vector();
    test_get_hash_string();

    return 0;
}

void test_get_hash_string() {

    TEST_BEGIN("get_hash_string");

    const std::string hash{"a simple teststring"};
    const std::string expected_hash{"0x176af31d906805cca2274f8bbaf0f36b1451020d1489f07bde9728465fca8357"};

    const std::string result = str_tolower(sproof::utils::get_hash(hash));

    std::cout << result << std::endl;
    std::cout << expected_hash << std::endl;

    ASSERT_STRING_EQUAL(expected_hash, result);

    TEST_END();

}

void test_get_hash_vector() {

    TEST_BEGIN("get_hash_vector");

    const std::vector<uint8_t> vec{'s', 'o', 'm', 'e', ' ', 't', 'e', 's', 't', ' ', 'd', 'a', 't', 'a'};
    const std::string expected_hash{"0xcb74f564c8be827dd581f24e3ca4e56985831acc9a6049e366dfa9b484c0f971"};

    const std::string result = str_tolower(sproof::utils::get_hash(vec));

    std::cout << result << std::endl;
    std::cout << expected_hash << std::endl;

    ASSERT_STRING_EQUAL(expected_hash, result);

    TEST_END();

}

void test_is_hash() {

    TEST_BEGIN("is_hash");

    const std::string hash{"0x2343DEADBEEF"};
    const std::string hex_str{"6948F7ac4282439"};
    const std::string no_hash{"345Dblubteststring"};

    ASSERT_EQUAL(true, sproof::utils::is_hash(hash));
    ASSERT_EQUAL(true, sproof::utils::is_hash(hex_str));
    ASSERT_EQUAL(false, sproof::utils::is_hash(no_hash));

    TEST_END();

}

#include "config.h"

#include "sproof-utils.h"


void test_as_hex_vector();

void test_as_hex_string();

void test_as_hex_with_prefix();

void test_remove_hex_prefix();

int main(int argc, char** argv)
{

    test_as_hex_vector();
    test_as_hex_string();
    test_as_hex_with_prefix();
    test_remove_hex_prefix();

    return 0;
}

void test_remove_hex_prefix() {

    TEST_BEGIN("test_remove_hex_prefix");

    const std::string with_prefix = "0x000102030405060708097F80FF";
    const std::string without_prefix = "000102030405060708097F80FF";

    std::string result = sproof::utils::remove_hex_prefix(with_prefix);

    ASSERT_STRING_EQUAL(without_prefix, result);

    result = sproof::utils::remove_hex_prefix(without_prefix);

    ASSERT_STRING_EQUAL(without_prefix, result);

    TEST_END();

}

void test_as_hex_with_prefix() {

    TEST_BEGIN("test_as_hex_with_prefix");

    const std::vector<uint8_t> vec{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 127, 128, 255};
    const std::string result = sproof::utils::as_hex_with_prefix(vec);

    ASSERT_STRING_EQUAL(str_tolower("0x000102030405060708097F80FF"), str_tolower(result));

    TEST_END();
}

void test_as_hex_string() {

    TEST_BEGIN("as_hex_string");

    const std::string str = "012345\x64\x32";
    const std::string result = sproof::utils::as_hex(str);

    ASSERT_STRING_EQUAL(str_tolower("3031323334356432"), str_tolower(result));

    TEST_END();

}

void test_as_hex_vector() {

    TEST_BEGIN("as_hex_vector");

    const std::vector<uint8_t> vec{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 127, 128, 255};
    const std::string result = sproof::utils::as_hex(vec);

    ASSERT_STRING_EQUAL(str_tolower("000102030405060708097F80FF"), str_tolower(result));

    TEST_END();

}

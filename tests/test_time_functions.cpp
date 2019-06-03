
#include "config.h"

#include "sproof-utils.h"


void test_is_in_time_range();

void test_get_unix_time_in_seconds();

int main(int argc, char** argv)
{

    test_get_unix_time_in_seconds();
    test_is_in_time_range();

    return 0;
}


void test_get_unix_time_in_seconds() {

    TEST_BEGIN("test_get_unix_time_in_seconds");

    std::chrono::seconds current_system_time{
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())};

    std::chrono::seconds sproof_time = sproof::utils::unix_time();

    ASSERT_EQUAL(true, sproof_time == current_system_time || (--sproof_time) == current_system_time);

    TEST_END();

}

void test_is_in_time_range() {

    TEST_BEGIN("test_is_in_time_range");

    std::chrono::seconds sproof_time = sproof::utils::unix_time();
    std::chrono::seconds from{sproof_time - std::chrono::seconds{10}};
    std::chrono::seconds until{sproof_time - std::chrono::seconds{5}};

    ASSERT_EQUAL(false, sproof::utils::is_time_in_range(from, until));

    from = sproof_time - std::chrono::seconds{10};
    until = sproof_time + std::chrono::seconds{5};

    ASSERT_EQUAL(true, sproof::utils::is_time_in_range(from, until));

    from = sproof_time + std::chrono::seconds{10};
    until = sproof_time + std::chrono::seconds{15};

    ASSERT_EQUAL(false, sproof::utils::is_time_in_range(from, until));

    TEST_END();
}

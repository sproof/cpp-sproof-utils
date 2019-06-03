
configure_file("config.h.in" ${CMAKE_SOURCE_DIR}/tests/config.h )


set( test_executables
        test_hash
        test_hex_functions
        test_time_functions
        test_utility_functions
        test_crypto_functions)

set(libraries
        cryptopp
        bitcoin-system
        sodium
        crypto
        ssl
        jsoncpp)

include_directories("${PROJECT_SOURCE_DIR}/include")

set(test_sources
        ../src/sproof-utils.cpp
        ../src/credentials.cpp
        ../src/raw_transaction.cpp)


FOREACH( test_name IN ITEMS ${test_executables} )

    add_executable( ${test_name} ${test_name}.cpp ${test_sources} )

    target_link_libraries( ${test_name} ${libraries} )

    add_test( ${test_name}_test ${test_name} )

ENDFOREACH()




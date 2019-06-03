cmake_minimum_required (VERSION 2.6)
project (sproof-utils)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

include( CTest )
add_subdirectory( tests )

include_directories("${PROJECT_SOURCE_DIR}/include")

set(sources ${sources}
        src/sproof-utils.cpp
        src/credentials.cpp
        src/raw_transaction.cpp)

set(headers ${header}
        include/credentials.h
        include/sproof-utils.h
        include/signature.h
        include/raw_transaction.h)


set(libraries
        cryptopp
        bitcoin-system
        sodium
        ssl
        crypto
        jsoncpp)

add_library (sproof-utils SHARED ${sources})

install(TARGETS sproof-utils DESTINATION lib)
install(FILES ${headers} DESTINATION include/sproof-utils)

add_executable(testmain testmain.cpp ${sources})

target_link_libraries (testmain ${libraries})

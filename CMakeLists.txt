cmake_minimum_required(VERSION 3.16)
project(libgsa LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(GSA_BUILD_TESTS "Build libgsa test suite" ON)
option(GSA_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
set(GSA_DIFF_CORECRYPTO "" CACHE STRING
    "Path to libcorecrypto_static.a to enable byte-for-byte SRP differential tests")

find_package(OpenSSL REQUIRED)

# Optional: libplist for the GSA handshake plist layer. The crypto + SRP core
# does NOT need it; only src/gsa_auth.c does.
find_path(PLIST_INCLUDE_DIR NAMES plist/plist.h)
find_library(PLIST_LIBRARY NAMES plist plist-2.0)

add_library(gsa
    src/crypto_openssl.c
    src/srp_openssl.c
)
target_include_directories(gsa PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(gsa PUBLIC OpenSSL::Crypto)

if(PLIST_INCLUDE_DIR AND PLIST_LIBRARY)
    message(STATUS "libgsa: libplist found — building GSA handshake layer (gsa_auth)")
    target_sources(gsa PRIVATE src/gsa_auth.c)
    target_include_directories(gsa PRIVATE ${PLIST_INCLUDE_DIR})
    target_link_libraries(gsa PUBLIC ${PLIST_LIBRARY})
    target_compile_definitions(gsa PUBLIC GSA_HAVE_PLIST=1)
else()
    message(STATUS "libgsa: libplist NOT found — crypto/SRP core only (handshake layer disabled)")
endif()

if(GSA_WARNINGS_AS_ERRORS)
    target_compile_options(gsa PRIVATE -Wall -Wextra -Werror)
else()
    target_compile_options(gsa PRIVATE -Wall -Wextra)
endif()

if(GSA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

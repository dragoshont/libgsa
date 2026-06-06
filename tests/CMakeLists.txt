# libgsa test suite. Vector-based, deterministic, no network/Apple.

add_library(gsa_test_util INTERFACE)
target_include_directories(gsa_test_util INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# Layer 1: primitive vectors (RFC 6070 PBKDF2, RFC 4231 HMAC, NIST AES). GREEN.
add_executable(test_primitives test_primitives.c)
target_link_libraries(test_primitives PRIVATE gsa gsa_test_util)
add_test(NAME primitives COMMAND test_primitives)

# Layer 2: SRP-6a vectors + (optional) corecrypto differential.
# RFC 5054 Appendix B fixed vector. The Apple-variant assertions are marked
# pending until validated, so this test currently reports them as skipped.
add_executable(test_srp test_srp.c)
target_link_libraries(test_srp PRIVATE gsa gsa_test_util)
add_test(NAME srp COMMAND test_srp)

if(GSA_DIFF_CORECRYPTO)
    message(STATUS "libgsa tests: SRP differential vs ${GSA_DIFF_CORECRYPTO}")
    target_compile_definitions(test_srp PRIVATE GSA_DIFF_CORECRYPTO=1)
    target_link_libraries(test_srp PRIVATE ${GSA_DIFF_CORECRYPTO})
endif()

include(FetchContent)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

add_executable(openppp2_tests
    unit/test_application_mode.cpp
    unit/test_firewall_domains.cpp
    unit/test_tap_stub.cpp
    unit/test_proxy_defaults.cpp
    unit/test_socks_address_type.cpp
)

add_executable(openppp2_dns_cache_ttl_tests
    dns_cache_ttl_tests.cpp
    ${PROJECT_SOURCE_DIR}/ppp/net/native/dnsx.cpp
    ${PROJECT_SOURCE_DIR}/common/dnslib/buffer.cpp
    ${PROJECT_SOURCE_DIR}/common/dnslib/message.cpp
    ${PROJECT_SOURCE_DIR}/common/dnslib/qs.cpp
    ${PROJECT_SOURCE_DIR}/common/dnslib/rr.cpp
)

target_link_libraries(openppp2_tests
    PRIVATE
        openppp2_lib
        GTest::gtest_main
)

if(PLATFORM_SYSTEM_WINDOWS)
    target_link_libraries(openppp2_dns_cache_ttl_tests
        PRIVATE
            ws2_32
            crypt32
            ${OPENSSL_SSL_LIBRARY}
            ${OPENSSL_CRYPTO_LIBRARY}
            ${JEMALLOC_LIBRARY}
    )
elseif(APPLE)
    target_link_libraries(openppp2_dns_cache_ttl_tests
        PRIVATE
            libssl.a
            libcrypto.a
            libjemalloc.a
            m
            pthread
    )
elseif(NOT MSVC)
    target_link_libraries(openppp2_dns_cache_ttl_tests
        PRIVATE
            libssl.a
            libcrypto.a
            libjemalloc.a
            m
            atomic
            dl
            pthread
    )
endif()

include(GoogleTest)
gtest_discover_tests(openppp2_tests)
add_test(NAME openppp2_dns_cache_ttl_tests COMMAND openppp2_dns_cache_ttl_tests)

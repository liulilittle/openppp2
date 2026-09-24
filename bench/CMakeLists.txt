# openppp2 UDP 性能微基准 —— 独立 CMake 项目（不改 openppp2 根 CMakeLists.txt）
# 用法: cmake -S bench -B build-bench -DCMAKE_BUILD_TYPE=Release && cmake --build build-bench
# 并发正确性:
#   ASan: cmake -S bench -B build-asan -DENABLE_ASAN=ON
#   TSan: cmake -S bench -B build-tsan -DENABLE_TSAN=ON
# 依赖(apt): cmake libbenchmark-dev libssl-dev libboost-all-dev libjemalloc-dev
cmake_minimum_required(VERSION 3.16)
project(openppp2_bench LANGUAGES CXX)

include(CTest)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(ENABLE_ASAN "Build with AddressSanitizer" OFF)
option(ENABLE_TSAN "Build with ThreadSanitizer" OFF)
option(ENABLE_TUN_GSO_OUTPUT_PROBE "Build the isolated Linux TUN GSO output probe" OFF)

if(ENABLE_ASAN AND ENABLE_TSAN)
    message(FATAL_ERROR "ENABLE_ASAN and ENABLE_TSAN cannot be enabled together")
endif()

get_filename_component(OPENPPP2_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

find_package(OpenSSL REQUIRED)
find_package(benchmark REQUIRED)
find_library(JEMALLOC_LIBRARY NAMES jemalloc)
set(OPENPPP2_BOOST_INCLUDE_DIR "" CACHE PATH "Directory containing boost/version.hpp")

set(OPENPPP2_BENCH_INCLUDES
    "${OPENPPP2_ROOT}"
    "${OPENPPP2_ROOT}/common"
    "${OPENPPP2_ROOT}/common/json/include")

if(NOT OPENPPP2_BOOST_INCLUDE_DIR)
    find_path(_OPENPPP2_BOOST_INCLUDE_DIR boost/version.hpp
        HINTS /usr/include /usr/local/include /opt/homebrew/include)
    set(OPENPPP2_BOOST_INCLUDE_DIR "${_OPENPPP2_BOOST_INCLUDE_DIR}")
endif()
if(NOT EXISTS "${OPENPPP2_BOOST_INCLUDE_DIR}/boost/version.hpp")
    message(FATAL_ERROR "OPENPPP2_BOOST_INCLUDE_DIR must contain boost/version.hpp")
endif()
list(APPEND OPENPPP2_BENCH_INCLUDES "${OPENPPP2_BOOST_INCLUDE_DIR}")

set(PPP_CRYPTO_SRCS
    "${OPENPPP2_ROOT}/ppp/cryptography/Ciphertext.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/EVP.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/rc4.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/digest.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/md5.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp")
file(GLOB PPP_AESNI_IMPL_SRCS "${OPENPPP2_ROOT}/common/aesni/impl/*.cpp")

set(PPP_POOL_SRCS
    "${OPENPPP2_ROOT}/ppp/threading/BufferswapAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferblockAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/Random.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/StringAuxiliary.cpp")

function(ppp_add_bench target)
    cmake_parse_arguments(ARG "" "" "SOURCES" ${ARGN})
    add_executable(${target} ${ARG_SOURCES})
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_include_directories(${target} PRIVATE ${OPENPPP2_BENCH_INCLUDES})
    target_compile_definitions(${target} PRIVATE FUNCTION __SIMD__)
    target_compile_options(${target} PRIVATE
        -O3 -DNDEBUG
        -maes -msse2 -mpclmul
        -Wno-format -Wno-deprecated-declarations
        -Wno-tautological-constant-out-of-range-compare)

    if(ENABLE_ASAN)
        target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address)
    elseif(ENABLE_TSAN)
        target_compile_options(${target} PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=thread)
    endif()

    target_link_libraries(${target} PRIVATE
        benchmark::benchmark OpenSSL::SSL OpenSSL::Crypto pthread)

    if(JEMALLOC_LIBRARY AND NOT ENABLE_ASAN AND NOT ENABLE_TSAN)
        target_link_libraries(${target} PRIVATE ${JEMALLOC_LIBRARY})
    endif()
endfunction()

ppp_add_bench(bm_crypto SOURCES udp/bm_crypto.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})

ppp_add_bench(bm_crypto_chain SOURCES udp/bm_crypto_chain.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    "${OPENPPP2_ROOT}/ppp/cryptography/ssea.cpp"
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})

ppp_add_bench(bm_ssea SOURCES udp/bm_ssea.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    "${OPENPPP2_ROOT}/ppp/cryptography/ssea.cpp"
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})
target_compile_options(bm_ssea PRIVATE -mssse3 -mavx2 -mpopcnt)

ppp_add_bench(bm_endpoint_serialize SOURCES udp/bm_endpoint_serialize.cpp)

ppp_add_bench(bm_packet_codec SOURCES udp/bm_packet_codec.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp support/packet_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/net/packet/IPFrame.cpp"
    "${OPENPPP2_ROOT}/ppp/net/packet/UdpFrame.cpp")

ppp_add_bench(bm_allocator SOURCES udp/bm_allocator.cpp
    support/bench_stubs.cpp support/bench_pool_stub.cpp support/buddy_impl.cpp
    ${PPP_POOL_SRCS})
target_link_libraries(bm_allocator PRIVATE rt)

ppp_add_bench(compat_check SOURCES udp/compat_check.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})

ppp_add_bench(evp_simd_test SOURCES udp/evp_simd_test.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})

ppp_add_bench(allocator_stress SOURCES udp/allocator_stress.cpp
    support/bench_stubs.cpp support/bench_pool_stub.cpp support/buddy_impl.cpp
    ${PPP_POOL_SRCS})
target_link_libraries(allocator_stress PRIVATE rt)

# ---- P0 micro-benchmarks (Phase 2) -------------------------------------------

# Internet checksum — SSE2 SIMD vs scalar, links checksum.cpp directly.
# Must NOT link packet_stubs.cpp (symbol clash with checksum.cpp).
ppp_add_bench(bm_checksum SOURCES udp/bm_checksum.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp support/net_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp")

# RIB/FIB longest-prefix-match lookup — links rib.cpp (needs net_stubs for
# Socket::GetDefaultTTL + StringToAddress).
ppp_add_bench(bm_rib_lpm SOURCES udp/bm_rib_lpm.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp support/net_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/net/native/rib.cpp")

# VMux FEC XOR codec — header-only, no .cpp linkage needed.
ppp_add_bench(bm_vmux_fec SOURCES udp/bm_vmux_fec.cpp)

# VMux ACK Tracker — header-only.
ppp_add_bench(bm_vmux_ack SOURCES udp/bm_vmux_ack.cpp)

# VMux Retransmit Buffer — header-only.
ppp_add_bench(bm_vmux_rtx SOURCES udp/bm_vmux_rtx.cpp)

# VMux Flow Reorder Buffer — header-only.
ppp_add_bench(bm_vmux_reorder SOURCES udp/bm_vmux_reorder.cpp)

# Linux-only raw write(TUN) service benchmark. This intentionally avoids the
# production TapLinux wrapper and Google Benchmark so its measured loop is just
# syscall timing. The only CTest registration is its unprivileged self-test.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(bm_tun_write linux/bm_tun_write.cpp)
    target_compile_features(bm_tun_write PRIVATE cxx_std_17)
    target_compile_options(bm_tun_write PRIVATE -O3 -DNDEBUG)
    target_link_libraries(bm_tun_write PRIVATE pthread)

    # Isolated TCP socket carrier benchmark; it does not link production transport code.
    add_executable(bm_tcp_carrier linux/bm_tcp_carrier.cpp)
    target_compile_features(bm_tcp_carrier PRIVATE cxx_std_17)
    target_compile_options(bm_tcp_carrier PRIVATE -O3 -DNDEBUG)
    target_link_libraries(bm_tcp_carrier PRIVATE pthread)

    # B0/B1 GSO ns-per-payload-byte sweep over the same two-TUN topology as the
    # probe. Only its unprivileged self-test is registered with CTest.
    add_executable(bm_tun_gso linux/bm_tun_gso.cpp)
    target_compile_features(bm_tun_gso PRIVATE cxx_std_17)
    target_compile_options(bm_tun_gso PRIVATE -O3 -DNDEBUG)
    target_link_libraries(bm_tun_gso PRIVATE pthread)

    if(ENABLE_TUN_GSO_OUTPUT_PROBE)
        add_executable(tun_gso_output_probe linux/tun_gso_output_probe.cpp)
        target_include_directories(tun_gso_output_probe PRIVATE "${OPENPPP2_ROOT}")
        target_compile_features(tun_gso_output_probe PRIVATE cxx_std_17)
        target_compile_options(tun_gso_output_probe PRIVATE -O3 -DNDEBUG)
    endif()
endif()

if(BUILD_TESTING)
    add_test(NAME bench_crypto_compatibility COMMAND compat_check)
    add_test(NAME bench_evp_simd_selection COMMAND evp_simd_test)
    add_test(NAME bench_allocator_stress COMMAND allocator_stress)
    add_test(NAME bench_crypto_chain_smoke COMMAND bm_crypto_chain --benchmark_min_time=0.001)
    add_test(NAME bench_ssea_smoke COMMAND bm_ssea --benchmark_min_time=0.001)
    add_test(NAME bench_endpoint_serialize_smoke COMMAND bm_endpoint_serialize --benchmark_min_time=0.001)
    add_test(NAME bench_packet_codec_smoke COMMAND bm_packet_codec --benchmark_min_time=0.001)
    add_test(NAME bench_checksum_smoke COMMAND bm_checksum --benchmark_min_time=0.001)
    add_test(NAME bench_rib_lpm_smoke COMMAND bm_rib_lpm --benchmark_min_time=0.001)
    add_test(NAME bench_vmux_fec_smoke COMMAND bm_vmux_fec --benchmark_min_time=0.001)
    add_test(NAME bench_vmux_ack_smoke COMMAND bm_vmux_ack --benchmark_min_time=0.001)
    add_test(NAME bench_vmux_rtx_smoke COMMAND bm_vmux_rtx --benchmark_min_time=0.001)
    add_test(NAME bench_vmux_reorder_smoke COMMAND bm_vmux_reorder --benchmark_min_time=0.001)
    if(TARGET bm_tun_write)
        add_test(NAME bench_tun_write_distribution_contract COMMAND bm_tun_write --self-test)
        set_tests_properties(bench_tun_write_distribution_contract
            PROPERTIES LABELS "micro;contract" TIMEOUT 30)
    endif()
    if(TARGET bm_tcp_carrier)
        add_test(NAME bench_tcp_carrier_contract COMMAND bm_tcp_carrier --self-test)
        set_tests_properties(bench_tcp_carrier_contract
            PROPERTIES LABELS "micro;contract" TIMEOUT 30)
    endif()
    if(TARGET tun_gso_output_probe)
        add_test(NAME bench_tun_gso_output_probe_contract COMMAND tun_gso_output_probe --self-test)
        set_tests_properties(bench_tun_gso_output_probe_contract
            PROPERTIES LABELS "micro;contract" TIMEOUT 30)
    endif()
    if(TARGET bm_tun_gso)
        add_test(NAME bench_tun_gso_perf_contract COMMAND bm_tun_gso --self-test)
        set_tests_properties(bench_tun_gso_perf_contract
            PROPERTIES LABELS "micro;contract" TIMEOUT 60)
    endif()

    set_tests_properties(
        bench_crypto_compatibility
        bench_evp_simd_selection
        bench_crypto_chain_smoke
        bench_endpoint_serialize_smoke
        bench_packet_codec_smoke
        PROPERTIES LABELS "crypto;correctness" TIMEOUT 30)

    set_tests_properties(
        bench_ssea_smoke
        PROPERTIES LABELS "crypto;ssea" TIMEOUT 60)

    set_tests_properties(
        bench_allocator_stress
        PROPERTIES LABELS "allocator;stress" TIMEOUT 180)

    set_tests_properties(
        bench_checksum_smoke
        bench_rib_lpm_smoke
        bench_vmux_fec_smoke
        bench_vmux_ack_smoke
        bench_vmux_rtx_smoke
        bench_vmux_reorder_smoke
        PROPERTIES LABELS "micro;smoke" TIMEOUT 60)
endif()

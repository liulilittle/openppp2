cmake_minimum_required(VERSION 3.16)
project(openppp2_cpp_tests LANGUAGES CXX)

option(ENABLE_COVERAGE "Enable LLVM coverage instrumentation" OFF)
option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer (cannot be combined with ENABLE_SANITIZERS)" OFF)
option(ENABLE_XTCP_TESTS "Build the pinned XTCP dependency contract tests" OFF)
option(ENABLE_XTCP_P64_PROBES "Build P64 allocation-pressure regression tests" OFF)
option(ENABLE_POLICY_BENCHMARKS "Build offline policy benchmarks outside CTest" OFF)

# Match the runtime library to the provisioned Boost/OpenSSL triplet.  The
# static triplet ships MT libraries; a mismatch fails at link time (LNK2038).
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    option(OPENPPP2_TESTS_STATIC_RUNTIME "Link the static MSVC runtime" ON)
    if(OPENPPP2_TESTS_STATIC_RUNTIME)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
endif()
get_filename_component(OPENPPP2_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
include("${OPENPPP2_ROOT}/cmake/Corocc.cmake")
if(ENABLE_COROCC)
    link_libraries(ppp_context_backend)
endif()
set(XTCP_SOURCE_DIR "${OPENPPP2_ROOT}/third-party/xtcp" CACHE PATH
    "Path to the pinned XTCP source tree")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Boost components are linked by bare target name (boost_context,
# boost_filesystem, ...).  On Windows/vcpkg the compiled libs carry versioned
# names, so map them through the CMake targets provided by the toolchain.
if(NOT TARGET boost_context)
    # Boost.System is header-only; Boost >= 1.89 no longer ships a
    # boost_system CMake component, so only request it when it exists.
    find_package(Boost REQUIRED COMPONENTS context filesystem regex thread)
    find_package(Boost QUIET COMPONENTS system)
    if(TARGET Boost::context)
        add_library(boost_context ALIAS Boost::context)
        if(TARGET Boost::system)
            add_library(boost_system ALIAS Boost::system)
        else()
            add_library(boost_system ALIAS Boost::headers)
        endif()
        add_library(boost_filesystem ALIAS Boost::filesystem)
        add_library(boost_regex ALIAS Boost::regex)
        add_library(boost_thread ALIAS Boost::thread)
    endif()
endif()
set(OPENPPP2_TEST_INCLUDES
    "${OPENPPP2_ROOT}"
    "${OPENPPP2_ROOT}/common"
    "${OPENPPP2_ROOT}/common/dnslib"
    "${OPENPPP2_ROOT}/common/json/include"
)

foreach(_hint /usr/include /usr/local/include /opt/homebrew/include
        "C:/vcpkg/installed/x64-windows-static/include")
    if(EXISTS "${_hint}/boost/version.hpp")
        list(APPEND OPENPPP2_TEST_INCLUDES "${_hint}")
        break()
    endif()
endforeach()

enable_testing()

set(OPENPPP2_AGGREGATOR_LOADER_TEST_SUPPORT
    support/aggregator_loader_test_stubs.cpp
    support/fake_aggligator/common/aggligator/aggligator.cpp
    support/dns_host_wiring_switcher_stub.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/AggregatorLoader.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/SwitcherTimeoutRegistry.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/NetworkOwnership.cpp")

set(OPENPPP2_TRANSPORT_AUTH_BINDING_SOURCES
    "${OPENPPP2_ROOT}/ppp/cryptography/noise/NoisePsk.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/NoisePskAuthenticatedCarrierBinding.cpp")

function(openppp2_add_cpp_test target)
    cmake_parse_arguments(ARG "" "" "SOURCES" ${ARGN})
    add_executable(${target} ${ARG_SOURCES})
    target_compile_features(${target} PRIVATE cxx_std_17)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU"
        AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9
        AND NOT ANDROID)
        target_link_libraries(${target} PRIVATE stdc++fs)
    endif()
    target_include_directories(${target} PRIVATE ${OPENPPP2_TEST_INCLUDES})
    if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        set(_has_stdafx OFF)
        foreach(_src IN LISTS ARG_SOURCES)
            if(_src MATCHES "stdafx[.]cpp$")
                set(_has_stdafx ON)
            endif()
        endforeach()
        if(NOT _has_stdafx)
            # Telemetry's OTLP exporter needs the native process identifier; the
            # recovery journal needs the platform CloseHandle.  Targets that
            # link ppp/stdafx.cpp already define these symbols.
            target_sources(${target} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/support/win32_process_id_stub.cpp")
        endif()
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        # MSVC does not accept GCC-style -Wno-* flags.
        target_compile_options(${target} PRIVATE /W3)
    else()
        target_compile_options(${target} PRIVATE
            -Wno-format
            -Wno-deprecated-declarations
            -Wno-tautological-constant-out-of-range-compare
        )
    endif()
    target_compile_definitions(${target} PRIVATE FUNCTION)
    if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        # Windows headers define min/max macros unless suppressed.
        target_compile_definitions(${target} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    endif()
    if(ENABLE_COVERAGE)
        target_compile_options(${target} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
        target_link_options(${target} PRIVATE -fprofile-instr-generate)
    endif()
    if(ENABLE_SANITIZERS AND ENABLE_TSAN)
        message(FATAL_ERROR "ENABLE_SANITIZERS (ASan/UBSan) and ENABLE_TSAN cannot be combined")
    endif()
    if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(${target} PRIVATE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
    if(ENABLE_TSAN AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_definitions(${target} PRIVATE PPP_COROUTINES_TSAN_ENABLED=1)
        target_compile_options(${target} PRIVATE
            -fsanitize=thread
            -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=thread)
    endif()
    if(target STREQUAL "runtime_snapshot_test" OR target STREQUAL "runtime_stats_json_test" OR target STREQUAL "p2p_replay_window_test" OR target STREQUAL "base64_test" OR target STREQUAL "dns_server_validation_test" OR target STREQUAL "dns_wire_validation_test" OR target STREQUAL "sysctl_validation_test" OR target STREQUAL "dns_redirect_plan_test" OR target STREQUAL "dns_reachability_test" OR target STREQUAL "dns_response_handler_test" OR target STREQUAL "dns_route_dispatcher_test" OR target STREQUAL "dns_udp_relay_test" OR target STREQUAL "dns_host_ports_test" OR target STREQUAL "dns_host_interface_test" OR target STREQUAL "dns_host_wiring_test" OR target STREQUAL "dns_session_context_test" OR target STREQUAL "dns_controller_test" OR target STREQUAL "route_host_ports_test" OR target STREQUAL "route_host_interface_test" OR target STREQUAL "route_state_test" OR target STREQUAL "route_coordinator_test" OR target STREQUAL "network_ownership_test" OR target STREQUAL "network_recovery_journal_test" OR target STREQUAL "linux_route_platform_contract_test" OR target STREQUAL "route_platform_adapters_test" OR target STREQUAL "windows_route_snapshot_test" OR target STREQUAL "windows_ipv6_snapshot_test" OR target STREQUAL "aggregator_loader_test" OR target STREQUAL "fake_ip_pool_test" OR target STREQUAL "dns_fake_ip_response_test" OR target STREQUAL "quic_reject_rate_limit_test" OR target STREQUAL "client_bypass_route_loader_test" OR target STREQUAL "exchanger_static_echo_channel_test" OR target STREQUAL "switcher_timeout_registry_test" OR target STREQUAL "peer_prefix_route_entry_test" OR target STREQUAL "peer_prefix_route_from_json_test" OR target STREQUAL "client_datagram_port_manager_test" OR target STREQUAL "server_datagram_port_manager_test" OR target STREQUAL "static_datagram_port_manager_test" OR target STREQUAL "peer_route_announce_policy_test" OR target STREQUAL "tcp_mss_clamp_test" OR target STREQUAL "icmp_path_mtu_test" OR target STREQUAL "client_bootstrap_policy_test")
        target_link_libraries(${target} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        # Windows network functions (inet_ntop, htonl) used by dnslib and the
        # network recovery path live in these import libraries.
        target_link_libraries(${target} PRIVATE ws2_32 iphlpapi winmm)
    endif()
    add_test(NAME ${target} COMMAND ${target})
    # Watchdog: coroutine/lifecycle deadlocks must fail the test instead of
    # hanging CI forever.
    set_tests_properties(${target} PROPERTIES TIMEOUT 120)
endfunction()

openppp2_add_cpp_test(websocket_buffered_upgrade_test SOURCES websocket_buffered_upgrade_test.cpp)
target_link_libraries(websocket_buffered_upgrade_test PRIVATE boost_system Threads::Threads)

openppp2_add_cpp_test(xtcp_direct_bridge_policy_test SOURCES xtcp_direct_bridge_policy_test.cpp)

openppp2_add_cpp_test(xtcp_upload_budget_test SOURCES xtcp_upload_budget_test.cpp)
target_link_libraries(xtcp_upload_budget_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(spsc_handoff_test SOURCES spsc_handoff_test.cpp)
target_link_libraries(spsc_handoff_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(xtcp_direct_handoff_test SOURCES xtcp_direct_handoff_test.cpp)
target_link_libraries(xtcp_direct_handoff_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(tap_output_lane_test SOURCES tap_output_lane_test.cpp)
target_link_libraries(tap_output_lane_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(tap_lane_envelope_handoff_test SOURCES tap_lane_envelope_handoff_test.cpp)
target_link_libraries(tap_lane_envelope_handoff_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(xtcp_shard_policy_test SOURCES xtcp_shard_policy_test.cpp)

openppp2_add_cpp_test(network_recovery_journal_test
    SOURCES network_recovery_journal_test.cpp
            support/network_recovery_route_stub.cpp
            support/network_recovery_windows_stub.cpp
            "${OPENPPP2_ROOT}/ppp/app/client/NetworkRecoveryJournal.cpp")
openppp2_add_cpp_test(route_snapshot_contract_test SOURCES
    route_snapshot_contract_test.cpp)
openppp2_add_cpp_test(windows_ipv6_snapshot_test SOURCES
    windows_ipv6_snapshot_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/WindowsIPv6Snapshot.cpp")

if(ENABLE_XTCP_TESTS)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR ANDROID)
        message(FATAL_ERROR "ENABLE_XTCP_TESTS is supported only for Linux desktop builds")
    endif()
    if(NOT EXISTS "${XTCP_SOURCE_DIR}/CMakeLists.txt")
        message(FATAL_ERROR
            "XTCP source tree not found at ${XTCP_SOURCE_DIR}; run tools/prepare_xtcp.sh first")
    endif()

    set(XTCP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(XTCP_BUILD_BENCH OFF CACHE BOOL "" FORCE)
    set(XTCP_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
    set(XTCP_BUILD_PLUGINS OFF CACHE BOOL "" FORCE)
    set(XTCP_BUILD_LWIP OFF CACHE BOOL "" FORCE)
    set(XTCP_BUILD_CC_PLUGINS ON CACHE BOOL "" FORCE)
    set(XTCP_CHECKSUM_VALIDATE ON CACHE BOOL "" FORCE)
    add_subdirectory("${XTCP_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/xtcp" EXCLUDE_FROM_ALL)
    if(NOT TARGET xtcp_static)
        message(FATAL_ERROR "XTCP source tree did not define the required xtcp_static target")
    endif()
    if(ENABLE_TSAN)
        target_compile_options(xtcp_static PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
        target_link_options(xtcp_static INTERFACE -fsanitize=thread)
    elseif(ENABLE_SANITIZERS)
        target_compile_options(xtcp_static PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(xtcp_static INTERFACE -fsanitize=address,undefined)
    endif()

    foreach(_xtcp_test
            xtcp_dependency_contract_test
            xtcp_ndi_ownership_test
            xtcp_listener_gate_test)
        openppp2_add_cpp_test(${_xtcp_test} SOURCES ${_xtcp_test}.cpp)
        target_link_libraries(${_xtcp_test} PRIVATE xtcp_static)
    endforeach()

    if(ENABLE_XTCP_P64_PROBES)
        openppp2_add_cpp_test(xtcp_allocation_recovery_test SOURCES xtcp_allocation_recovery_test.cpp)
        target_link_libraries(xtcp_allocation_recovery_test PRIVATE xtcp_static Threads::Threads)
        foreach(_allocation_case delayed resume closed lost repeated-delayed repeated-resume repeated-closed probe fin timewait dsack ecn)
            add_test(NAME xtcp_allocation_recovery_${_allocation_case}
                COMMAND xtcp_allocation_recovery_test ${_allocation_case})
            set_tests_properties(xtcp_allocation_recovery_${_allocation_case} PROPERTIES TIMEOUT 5)
        endforeach()
    endif()

    openppp2_add_cpp_test(xtcp_ooo_frontier_test SOURCES "${XTCP_SOURCE_DIR}/tests/test_ooo_frontier.cpp")
    target_link_libraries(xtcp_ooo_frontier_test PRIVATE xtcp_static)

    foreach(_xtcp_resume_test xtcp_ooo_backpressure_probe xtcp_ooo_resume_contract_test)
        openppp2_add_cpp_test(${_xtcp_resume_test} SOURCES ${_xtcp_resume_test}.cpp)
        target_link_libraries(${_xtcp_resume_test} PRIVATE xtcp_static)
    endforeach()

    openppp2_add_cpp_test(xtcp_runtime_adapter_test SOURCES
        xtcp_runtime_adapter_test.cpp
        "${OPENPPP2_ROOT}/ppp/app/client/xtcp/XtcpNdiBackend.cpp"
        "${OPENPPP2_ROOT}/ppp/app/client/xtcp/XtcpPoolLease.cpp"
        "${OPENPPP2_ROOT}/ppp/app/client/xtcp/XtcpRuntime.cpp")
    target_compile_definitions(xtcp_runtime_adapter_test PRIVATE
        PPP_ENABLE_XTCP=1
        PPP_XTCP_HAS_TIMER_DEADLINE=1
        PPP_XTCP_RUNTIME_TESTING=1)
    target_link_libraries(xtcp_runtime_adapter_test PRIVATE
        xtcp_static Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

    openppp2_add_cpp_test(xtcp_queue_mode_lifecycle_test SOURCES
        xtcp_queue_mode_lifecycle_test.cpp
        "${OPENPPP2_ROOT}/ppp/app/client/xtcp/XtcpNdiBackend.cpp"
        "${OPENPPP2_ROOT}/ppp/app/client/xtcp/XtcpPoolLease.cpp"
        "${OPENPPP2_ROOT}/ppp/app/client/xtcp/XtcpRuntime.cpp")
    target_compile_definitions(xtcp_queue_mode_lifecycle_test PRIVATE
        PPP_ENABLE_XTCP=1
        PPP_XTCP_HAS_TIMER_DEADLINE=1
        PPP_XTCP_RUNTIME_TESTING=1)
    target_link_libraries(xtcp_queue_mode_lifecycle_test PRIVATE
        xtcp_static Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

    openppp2_add_cpp_test(xtcp_ndi_memory_probe SOURCES
        xtcp_ndi_memory_probe.cpp
        "${OPENPPP2_ROOT}/ppp/app/client/xtcp/XtcpNdiBackend.cpp")
    target_compile_definitions(xtcp_ndi_memory_probe PRIVATE PPP_ENABLE_XTCP=1)
    target_link_libraries(xtcp_ndi_memory_probe PRIVATE
        xtcp_static Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

    openppp2_add_cpp_test(xtcp_runtime_bridge_test SOURCES
        xtcp_runtime_bridge_test.cpp
        "${OPENPPP2_ROOT}/ppp/app/client/xtcp/XtcpNdiBackend.cpp"
        "${OPENPPP2_ROOT}/ppp/app/client/xtcp/XtcpPoolLease.cpp"
        "${OPENPPP2_ROOT}/ppp/app/client/xtcp/XtcpRuntime.cpp")
    target_compile_definitions(xtcp_runtime_bridge_test PRIVATE
        PPP_ENABLE_XTCP=1
        PPP_XTCP_HAS_TIMER_DEADLINE=1)
    target_include_directories(xtcp_runtime_bridge_test PRIVATE
        "${XTCP_SOURCE_DIR}/tests")
    target_link_libraries(xtcp_runtime_bridge_test PRIVATE
        xtcp_static Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
    if(ENABLE_XTCP_P64_PROBES)
        foreach(_pressure_case ordinary large split0 split1 split2)
            add_test(NAME xtcp_ingress_pressure_${_pressure_case}
                COMMAND xtcp_runtime_bridge_test --pressure ${_pressure_case})
            set_tests_properties(xtcp_ingress_pressure_${_pressure_case} PROPERTIES TIMEOUT 5)
        endforeach()
    endif()
endif()

openppp2_add_cpp_test(runtime_snapshot_test SOURCES
    runtime_snapshot_test.cpp
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_compile_definitions(runtime_snapshot_test PRIVATE
    OPENPPP2_RUNTIME_FIXTURE_DIR=\"${OPENPPP2_ROOT}/tests/contracts/runtime-snapshot\")
openppp2_add_cpp_test(runtime_stats_json_test SOURCES
    runtime_stats_json_test.cpp
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
openppp2_add_cpp_test(datapath_acceptance_boundary_test SOURCES
    datapath_acceptance_boundary_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/runtime/DatapathAcceptanceBoundary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_link_libraries(datapath_acceptance_boundary_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(runtime_stop_coordinator_test SOURCES
    runtime_stop_coordinator_test.cpp)
openppp2_add_cpp_test(runtime_stop_pipeline_test SOURCES
    runtime_stop_pipeline_test.cpp)
openppp2_add_cpp_test(client_lifecycle_stress_test SOURCES
    client_lifecycle_stress_test.cpp)
openppp2_add_cpp_test(client_bootstrap_policy_test SOURCES
    client_bootstrap_policy_test.cpp)
openppp2_add_cpp_test(tcp_stack_mode_test SOURCES
    tcp_stack_mode_test.cpp)
openppp2_add_cpp_test(client_keepalive_policy_test SOURCES
    client_keepalive_policy_test.cpp)
openppp2_add_cpp_test(client_reconnection_policy_test SOURCES
    client_reconnection_policy_test.cpp)
openppp2_add_cpp_test(session_recovery_state_test SOURCES
    session_recovery_state_test.cpp)
openppp2_add_cpp_test(session_resume_fallback_decision_test SOURCES
    session_resume_fallback_decision_test.cpp)
openppp2_add_cpp_test(session_resume_information_test SOURCES
    session_resume_information_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_link_libraries(session_resume_information_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(transport_auth_information_test SOURCES
    transport_auth_information_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_link_libraries(transport_auth_information_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(noise_psk_handshake_test SOURCES
    noise_psk_handshake_test.cpp
    "${OPENPPP2_ROOT}/ppp/cryptography/noise/NoisePsk.cpp")
target_link_libraries(noise_psk_handshake_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(noise_psk_exporter_test SOURCES
    noise_psk_exporter_test.cpp
    "${OPENPPP2_ROOT}/ppp/cryptography/noise/NoisePsk.cpp")
target_link_libraries(noise_psk_exporter_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(transport_auth_keyring_test SOURCES
    transport_auth_keyring_test.cpp
    "${OPENPPP2_ROOT}/ppp/configurations/TransportAuthConfiguration.cpp")
target_link_libraries(transport_auth_keyring_test PRIVATE OpenSSL::Crypto)
file(GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/transport_auth_configuration_test_stubs.cpp"
    CONTENT [=[
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/threading/Executors.h>

namespace ppp::coroutines {
YieldContext::Anchor YieldContext::Arm() noexcept { return Anchor(); }
bool YieldContext::Suspend(const Anchor&) noexcept { return false; }
bool YieldContext::Anchor::R() const noexcept { return false; }
}

namespace ppp::net::asio::vdns {
IPEndPointVectorPtr servers;
std::atomic<int> ttl{0};
std::atomic<bool> enabled{false};
bool ResolveAsync(
    boost::asio::io_context&,
    const char*,
    int,
    const ppp::vector<boost::asio::ip::udp::endpoint>&,
    const ppp::function<void(const boost::asio::ip::address&)>&) noexcept {
    return false;
}
}

namespace ppp::threading {
std::shared_ptr<boost::asio::io_context> Executors::GetCurrent(bool) noexcept { return nullptr; }
uint64_t Executors::GetTickCount() noexcept { return 0; }
}
]=])
openppp2_add_cpp_test(transport_auth_configuration_test SOURCES
    transport_auth_configuration_test.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/transport_auth_configuration_test_stubs.cpp"
    support/windows_composition_stub.cpp
    support/policy_link_runtime_stub.cpp
    support/socket_platform_guard_stub.cpp
    "${OPENPPP2_ROOT}/ppp/configurations/AppConfiguration.cpp"
    "${OPENPPP2_ROOT}/ppp/configurations/TransportAuthConfiguration.cpp"
    "${OPENPPP2_ROOT}/ppp/app/ApplicationMode.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/StringAuxiliary.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/UriAuxiliary.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/Ciphertext.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/EVP.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/rc4.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/ssea.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/md5.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/digest.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp"
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp"
    "${OPENPPP2_ROOT}/ppp/io/File.cpp"
    "${OPENPPP2_ROOT}/ppp/net/IPEndPoint.cpp"
    "${OPENPPP2_ROOT}/ppp/net/Ipep.cpp"
    "${OPENPPP2_ROOT}/ppp/net/http/HttpClient.cpp"
    "${OPENPPP2_ROOT}/ppp/Random.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/SSL.cpp"
    "${OPENPPP2_ROOT}/ppp/stdafx.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/Thread.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferswapAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferblockAllocator.cpp"
    "${OPENPPP2_ROOT}/common/chnroutes2/chnroutes2.cpp"
    support/chnroutes2_download_link_stubs.cpp
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_compile_options(transport_auth_configuration_test PRIVATE -ffunction-sections -fdata-sections)
target_link_options(transport_auth_configuration_test PRIVATE -Wl,--gc-sections)
target_link_libraries(transport_auth_configuration_test PRIVATE boost_filesystem Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_definitions(transport_auth_configuration_test PRIVATE BUDDY_ALLOC_IMPLEMENTATION PPP_STUB_NO_GETTICKCOUNT PPP_STUB_NO_GETCURRENT)
endif()

# VMUX reliability defaults / JSON round-trip on the real AppConfiguration,
# reusing the transport-auth link fixture.
get_target_property(OPENPPP2_VMUX_CONFIG_SOURCES transport_auth_configuration_test SOURCES)
list(REMOVE_ITEM OPENPPP2_VMUX_CONFIG_SOURCES transport_auth_configuration_test.cpp)
openppp2_add_cpp_test(vmux_reliability_config_test SOURCES
    vmux_reliability_config_test.cpp
    ${OPENPPP2_VMUX_CONFIG_SOURCES})
target_compile_options(vmux_reliability_config_test PRIVATE -ffunction-sections -fdata-sections)
target_link_options(vmux_reliability_config_test PRIVATE -Wl,--gc-sections)
target_link_libraries(vmux_reliability_config_test PRIVATE boost_filesystem Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    # Partial-link fixture: allocator/transport RTTI key functions are not
    # linked, so the vptr check cannot reference their typeinfo.
    target_compile_options(vmux_reliability_config_test PRIVATE -fno-sanitize=vptr)
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_definitions(vmux_reliability_config_test PRIVATE BUDDY_ALLOC_IMPLEMENTATION PPP_STUB_NO_GETTICKCOUNT PPP_STUB_NO_GETCURRENT)
endif()
if(ENABLE_SANITIZERS OR ENABLE_TSAN)
    # Instrumentation can retain allocator entry points that section GC drops
    # in the normal partial-link fixture. Supply their real buddy implementation.
    foreach(_config_test transport_auth_configuration_test vmux_reliability_config_test)
        target_compile_definitions(${_config_test} PRIVATE BUDDY_ALLOC_IMPLEMENTATION)
    endforeach()
endif()
openppp2_add_cpp_test(transport_auth_negotiation_test SOURCES
    transport_auth_negotiation_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/TransportAuthNegotiation.cpp"
    "${OPENPPP2_ROOT}/ppp/configurations/TransportAuthConfiguration.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/noise/NoisePsk.cpp")
target_link_libraries(transport_auth_negotiation_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(client_transport_auth_wiring_policy_test SOURCES
    client_transport_auth_wiring_policy_test.cpp)
target_link_libraries(client_transport_auth_wiring_policy_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(session_resume_handshake_state_test SOURCES
    session_resume_handshake_state_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/SessionResumeAuthenticator.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_link_libraries(session_resume_handshake_state_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(session_resume_authenticator_test SOURCES
    session_resume_authenticator_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/SessionResumeAuthenticator.cpp")
target_link_libraries(session_resume_authenticator_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(session_resume_wss_fault_injection_test SOURCES
    session_resume_wss_fault_injection_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/SessionResumeAuthenticator.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/TlsSessionExporter.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_compile_definitions(session_resume_wss_fault_injection_test PRIVATE
    OPENPPP2_TEST_CERTIFICATE="${OPENPPP2_ROOT}/starrylink.net.pem"
    OPENPPP2_TEST_PRIVATE_KEY="${OPENPPP2_ROOT}/starrylink.net.key")
target_link_libraries(session_resume_wss_fault_injection_test PRIVATE
    Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(session_resume_production_wss_lifecycle_test SOURCES
    session_resume_production_wss_lifecycle_test.cpp
    support/session_resume_production_wss_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/SessionResumeAuthenticator.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/ITransmission.cpp"
    ${OPENPPP2_TRANSPORT_AUTH_BINDING_SOURCES}
    "${OPENPPP2_ROOT}/ppp/transmissions/ITransmissionQoS.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/IWebsocketTransmission.cpp"
    support/qoss_stub.cpp
    "${OPENPPP2_ROOT}/ppp/Random.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/ssea.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/Ciphertext.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/EVP.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/rc4.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/digest.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/md5.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp"
    "${OPENPPP2_ROOT}/ppp/net/Socket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/IPEndPoint.cpp"
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/SSL.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/IAsynchronousWriteIoQueue.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_accept_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_read_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_write_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_close_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_read_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_write_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_close_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket_perform_ssl_handshake.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket_perform_websocket_handshake.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_accept_sslv_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/TlsSessionExporter.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_compile_definitions(session_resume_production_wss_lifecycle_test PRIVATE
    OPENPPP2_TEST_CERTIFICATE="${OPENPPP2_ROOT}/starrylink.net.pem"
    OPENPPP2_TEST_PRIVATE_KEY="${OPENPPP2_ROOT}/starrylink.net.key")
target_link_libraries(session_resume_production_wss_lifecycle_test PRIVATE
    boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
get_target_property(OPENPPP2_PRODUCTION_WSS_TEST_SOURCES
    session_resume_production_wss_lifecycle_test SOURCES)
list(REMOVE_ITEM OPENPPP2_PRODUCTION_WSS_TEST_SOURCES
    session_resume_production_wss_lifecycle_test.cpp)
openppp2_add_cpp_test(transport_auth_lifecycle_test SOURCES
    transport_auth_lifecycle_test.cpp
    ${OPENPPP2_PRODUCTION_WSS_TEST_SOURCES}
    "${OPENPPP2_ROOT}/ppp/transmissions/ITcpipTransmission.cpp")
target_link_libraries(transport_auth_lifecycle_test PRIVATE
    boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    # These partial-link fixtures intentionally stub allocator users without
    # linking the allocator implementation that owns its RTTI key function.
    foreach(_target transport_auth_configuration_test
                    session_resume_production_wss_lifecycle_test
                    transport_auth_lifecycle_test)
        target_compile_options(${_target} PRIVATE -fno-sanitize=vptr)
    endforeach()
endif()
openppp2_add_cpp_test(transport_auth_handshake_capability_test SOURCES
    transport_auth_handshake_capability_test.cpp
    ${OPENPPP2_PRODUCTION_WSS_TEST_SOURCES})
target_compile_definitions(transport_auth_handshake_capability_test PRIVATE
    OPENPPP2_TEST_CERTIFICATE="${OPENPPP2_ROOT}/starrylink.net.pem"
    OPENPPP2_TEST_PRIVATE_KEY="${OPENPPP2_ROOT}/starrylink.net.key")
target_link_libraries(transport_auth_handshake_capability_test PRIVATE
    boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    # Partial-link fixture: allocator/transport RTTI key functions are not
    # linked, so the vptr check cannot reference their typeinfo.
    target_compile_options(transport_auth_handshake_capability_test PRIVATE -fno-sanitize=vptr)
endif()
openppp2_add_cpp_test(session_resume_establish_transaction_wss_test SOURCES
    session_resume_establish_transaction_wss_test.cpp
    support/session_resume_production_wss_test_stubs.cpp
    support/session_resume_information_test_stubs.cpp
    support/peer_prefix_route_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/server/SessionResumeEstablishTransaction.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/SessionResumeAuthenticator.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/ITransmission.cpp"
    ${OPENPPP2_TRANSPORT_AUTH_BINDING_SOURCES}
    "${OPENPPP2_ROOT}/ppp/transmissions/ITransmissionQoS.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/IWebsocketTransmission.cpp"
    support/qoss_stub.cpp
    "${OPENPPP2_ROOT}/ppp/Random.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/ssea.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/Ciphertext.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/EVP.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/rc4.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/digest.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/md5.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp"
    "${OPENPPP2_ROOT}/ppp/net/Socket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/IPEndPoint.cpp"
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/SSL.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/IAsynchronousWriteIoQueue.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_accept_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_read_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_write_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_close_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_read_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_write_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_close_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket_perform_ssl_handshake.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket_perform_websocket_handshake.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_accept_sslv_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/TlsSessionExporter.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_compile_definitions(session_resume_establish_transaction_wss_test PRIVATE
    OPENPPP2_TEST_CERTIFICATE="${OPENPPP2_ROOT}/starrylink.net.pem"
    OPENPPP2_TEST_PRIVATE_KEY="${OPENPPP2_ROOT}/starrylink.net.key")
target_link_libraries(session_resume_establish_transaction_wss_test PRIVATE
    boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    # Partial-link fixture: allocator/transport RTTI key functions are not
    # linked, so the vptr check cannot reference their typeinfo.
    target_compile_options(session_resume_establish_transaction_wss_test PRIVATE -fno-sanitize=vptr)
endif()
openppp2_add_cpp_test(runtime_snapshot_publisher_test SOURCES
    runtime_snapshot_publisher_test.cpp)
openppp2_add_cpp_test(vmux_runtime_state_test SOURCES
    vmux_runtime_state_test.cpp)
openppp2_add_cpp_test(vmux_negotiation_test SOURCES
    vmux_negotiation_test.cpp)
openppp2_add_cpp_test(vmux_reliability_negotiation_test SOURCES
    vmux_reliability_negotiation_test.cpp)
openppp2_add_cpp_test(vmux_ack_tracker_test SOURCES
    vmux_ack_tracker_test.cpp)
openppp2_add_cpp_test(vmux_retransmit_buffer_test SOURCES
    vmux_retransmit_buffer_test.cpp)
openppp2_add_cpp_test(vmux_fec_codec_test SOURCES
    vmux_fec_codec_test.cpp)
openppp2_add_cpp_test(vmux_flow_reorder_test SOURCES
    vmux_flow_reorder_test.cpp)
openppp2_add_cpp_test(vmux_rx_backpressure_test SOURCES
    vmux_rx_backpressure_test.cpp)
openppp2_add_cpp_test(vmux_tx_backpressure_test SOURCES
    vmux_tx_backpressure_test.cpp)
openppp2_add_cpp_test(vmux_flow_context_admission_test SOURCES
    vmux_flow_context_admission_test.cpp)
openppp2_add_cpp_test(vmux_rx_queue_limit_test SOURCES
    vmux_rx_queue_limit_test.cpp)
openppp2_add_cpp_test(peer_route_announce_policy_test SOURCES
    peer_route_announce_policy_test.cpp)
openppp2_add_cpp_test(vmux_link_churn_test SOURCES
    vmux_link_churn_test.cpp)
openppp2_add_cpp_test(vmux_wave0_rtx_release_test SOURCES
    vmux_wave0_rtx_release_test.cpp)
openppp2_add_cpp_test(vmux_wave2_flow_isolation_test SOURCES
    vmux_wave2_flow_isolation_test.cpp)
openppp2_add_cpp_test(vmux_wave3_per_link_rtt_test SOURCES
    vmux_wave3_per_link_rtt_test.cpp)
openppp2_add_cpp_test(vmux_wave4_pto_rtx_test SOURCES
    vmux_wave4_pto_rtx_test.cpp)
openppp2_add_cpp_test(vmux_wave5_control_plane_test SOURCES
    vmux_wave5_control_plane_test.cpp)
openppp2_add_cpp_test(vmux_wave6_property_wrap_test SOURCES
    vmux_wave6_property_wrap_test.cpp)
openppp2_add_cpp_test(vmux_wave6_long_stability_test SOURCES
    vmux_wave6_long_stability_test.cpp)
openppp2_add_cpp_test(vmux_qa001_write_failure_test SOURCES
    vmux_qa001_write_failure_test.cpp)
openppp2_add_cpp_test(vmux_qa001_fec_race_test SOURCES
    vmux_qa001_fec_race_test.cpp)
openppp2_add_cpp_test(vmux_qa001_ack_malicious_test SOURCES
    vmux_qa001_ack_malicious_test.cpp)
openppp2_add_cpp_test(mux_transport_adapter_test SOURCES
    mux_transport_adapter_test.cpp)
target_link_libraries(mux_transport_adapter_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(runtime_readiness_test SOURCES
    runtime_readiness_test.cpp)
openppp2_add_cpp_test(runtime_lifecycle_test SOURCES
    runtime_lifecycle_test.cpp)
openppp2_add_cpp_test(tui_runtime_adapter_test SOURCES
    tui_runtime_adapter_test.cpp)
openppp2_add_cpp_test(p2p_replay_window_test SOURCES p2p_replay_window_test.cpp)
openppp2_add_cpp_test(p2p_control_packet_test SOURCES p2p_control_packet_test.cpp)
openppp2_add_cpp_test(p2p_key_derivation_test SOURCES
    p2p_key_derivation_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PKeyDerivation.cpp")
target_link_libraries(p2p_key_derivation_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_relay_offer_test SOURCES
    p2p_relay_offer_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOffer.cpp")
target_link_libraries(p2p_relay_offer_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_relay_offer_coordinator_test SOURCES
    p2p_relay_offer_coordinator_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/P2PCandidateAdapter.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOffer.cpp")
target_link_libraries(p2p_relay_offer_coordinator_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_relay_offer_consumer_test SOURCES
    p2p_relay_offer_consumer_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferConsumer.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOffer.cpp")
target_link_libraries(p2p_relay_offer_consumer_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_client_offer_session_test SOURCES
    p2p_client_offer_session_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PClientOfferSession.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PControlDatagram.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDataDatagram.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDirectActivationCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDirectDataPath.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferConsumer.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOffer.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PKeyDerivation.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2POfferToken.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PCrypto.cpp")
target_link_libraries(p2p_client_offer_session_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_information_message_test SOURCES
    p2p_information_message_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_link_libraries(p2p_information_message_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_offer_token_test SOURCES
    p2p_offer_token_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDirectActivationCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2POfferToken.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PCrypto.cpp")
target_link_libraries(p2p_offer_token_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_control_state_machine_test SOURCES
    p2p_control_state_machine_test.cpp)
openppp2_add_cpp_test(p2p_data_datagram_test SOURCES
    p2p_data_datagram_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDataDatagram.cpp")
target_link_libraries(p2p_data_datagram_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_channel_lifecycle_test SOURCES
    p2p_channel_lifecycle_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PChannel.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDatagramTransport.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PCrypto.cpp")
target_link_libraries(p2p_channel_lifecycle_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_datagram_transport_test SOURCES
    p2p_datagram_transport_test.cpp)
openppp2_add_cpp_test(ios_p2p_datagram_transport_test SOURCES
    ios_p2p_datagram_transport_test.cpp
    "${OPENPPP2_ROOT}/ios/IosP2PDatagramTransport.cpp")
openppp2_add_cpp_test(p2p_nat_classifier_test SOURCES
    p2p_nat_classifier_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PNatClassifier.cpp")
target_link_libraries(p2p_nat_classifier_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_capability_gate_test SOURCES
    p2p_capability_gate_test.cpp)
target_sources(p2p_capability_gate_test PRIVATE
    "${OPENPPP2_ROOT}/ppp/p2p/P2PSocketProtector.cpp")
target_link_libraries(p2p_capability_gate_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_zero_rtt_cache_test SOURCES
    p2p_zero_rtt_cache_test.cpp)
target_link_libraries(p2p_zero_rtt_cache_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_stun_client_test SOURCES
    p2p_stun_client_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PStunClient.cpp")
target_link_libraries(p2p_stun_client_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_stun_gatherer_test SOURCES
    p2p_stun_gatherer_test.cpp "${OPENPPP2_ROOT}/ppp/p2p/P2PStunClient.cpp")
target_link_libraries(p2p_stun_gatherer_test PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
openppp2_add_cpp_test(p2p_native_socket_stun_test SOURCES
    p2p_native_socket_stun_test.cpp "${OPENPPP2_ROOT}/ppp/p2p/P2PStunClient.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDatagramTransport.cpp")
target_link_libraries(p2p_native_socket_stun_test PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
openppp2_add_cpp_test(p2p_probe_coordinator_test SOURCES
    p2p_probe_coordinator_test.cpp "${OPENPPP2_ROOT}/ppp/p2p/P2PProbeCoordinator.cpp")
openppp2_add_cpp_test(p2p_ingress_limiter_test SOURCES
    p2p_ingress_limiter_test.cpp "${OPENPPP2_ROOT}/ppp/p2p/P2PIngressLimiter.cpp")
target_link_libraries(p2p_ingress_limiter_test PRIVATE Threads::Threads)
set(OPENPPP2_P2P_V2_SOURCES
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferV2.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PV2ControlCodec.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PV2DataCodec.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PV2Channel.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOffer.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PKeyDerivation.cpp")
foreach(_test p2p_v2_offer_test p2p_v2_channel_test)
    openppp2_add_cpp_test(${_test} SOURCES ${_test}.cpp ${OPENPPP2_P2P_V2_SOURCES})
    target_link_libraries(${_test} PRIVATE OpenSSL::Crypto Threads::Threads)
endforeach()
openppp2_add_cpp_test(p2p_v2_noise_test SOURCES p2p_v2_noise_test.cpp
    "${OPENPPP2_ROOT}/ppp/cryptography/noise/NoisePsk.cpp")
target_link_libraries(p2p_v2_noise_test PRIVATE OpenSSL::Crypto Threads::Threads)
openppp2_add_cpp_test(p2p_v2_server_coordination_test SOURCES p2p_v2_server_coordination_test.cpp)
openppp2_add_cpp_test(p2p_v2_integration_test SOURCES p2p_v2_integration_test.cpp
    ${OPENPPP2_P2P_V2_SOURCES}
    "${OPENPPP2_ROOT}/ppp/p2p/P2PProbeCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PIngressLimiter.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDirectDataPath.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PClientOfferSession.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PControlDatagram.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDataDatagram.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDirectActivationCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferConsumer.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2POfferToken.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PCrypto.cpp"
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    support/socket_default_ttl_stub.cpp
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(p2p_v2_integration_test PRIVATE OpenSSL::Crypto Threads::Threads)
# Compile the actual application wiring without starting PPP or requiring the
# native runtime dependency/link graph in this standalone project.
add_library(p2p_v2_app_wiring_compile OBJECT
    "${OPENPPP2_ROOT}/ppp/app/client/VEthernetP2PV2.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/VEthernetExchanger.cpp"
    "${OPENPPP2_ROOT}/ppp/app/server/VirtualEthernetP2PV2.cpp"
    "${OPENPPP2_ROOT}/ppp/app/server/VirtualEthernetSwitcher.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/NoisePskAuthenticatedCarrierBinding.cpp")
target_compile_features(p2p_v2_app_wiring_compile PRIVATE cxx_std_17)
target_include_directories(p2p_v2_app_wiring_compile PRIVATE ${OPENPPP2_TEST_INCLUDES})
target_compile_definitions(p2p_v2_app_wiring_compile PRIVATE FUNCTION)
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(p2p_v2_app_wiring_compile PRIVATE -Wno-deprecated-declarations -Wno-format)
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_definitions(p2p_v2_app_wiring_compile PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
openppp2_add_cpp_test(p2p_coalesce_frames_test SOURCES
    p2p_coalesce_frames_test.cpp)
target_link_libraries(p2p_coalesce_frames_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(tls_session_exporter_test SOURCES
    tls_session_exporter_test.cpp
    "${OPENPPP2_ROOT}/ppp/ssl/TlsSessionExporter.cpp")
target_compile_definitions(tls_session_exporter_test PRIVATE
    OPENPPP2_TEST_CERTIFICATE="${OPENPPP2_ROOT}/starrylink.net.pem"
    OPENPPP2_TEST_PRIVATE_KEY="${OPENPPP2_ROOT}/starrylink.net.key")
target_link_libraries(tls_session_exporter_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(dns_buffer_test SOURCES dns_buffer_test.cpp "${OPENPPP2_ROOT}/common/dnslib/buffer.cpp")
openppp2_add_cpp_test(dns_message_test SOURCES dns_message_test.cpp "${OPENPPP2_ROOT}/common/dnslib/buffer.cpp" "${OPENPPP2_ROOT}/common/dnslib/message.cpp" "${OPENPPP2_ROOT}/common/dnslib/qs.cpp" "${OPENPPP2_ROOT}/common/dnslib/rr.cpp")
openppp2_add_cpp_test(dns_server_validation_test SOURCES dns_server_validation_test.cpp)
openppp2_add_cpp_test(dns_wire_validation_test SOURCES dns_wire_validation_test.cpp)
openppp2_add_cpp_test(base64_test SOURCES base64_test.cpp "${OPENPPP2_ROOT}/common/base64/base64.cpp")
openppp2_add_cpp_test(sysctl_validation_test SOURCES sysctl_validation_test.cpp)
openppp2_add_cpp_test(dns_redirect_plan_test SOURCES
    dns_redirect_plan_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsRedirectPlan.cpp")
openppp2_add_cpp_test(dns_reachability_test SOURCES
    dns_reachability_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsReachabilityParse.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsReachability.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsProviderCatalog.cpp")
openppp2_add_cpp_test(dns_udp_flow_registry_test SOURCES
    dns_udp_flow_registry_test.cpp
    "${OPENPPP2_ROOT}/ppp/dns/DnsUdpFlowRegistry.cpp")
target_link_libraries(dns_udp_flow_registry_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(dns_response_handler_test SOURCES
    dns_response_handler_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsResponseHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
openppp2_add_cpp_test(dns_route_dispatcher_test SOURCES
    dns_route_dispatcher_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsRouteDispatcher.cpp")
openppp2_add_cpp_test(dns_udp_relay_test SOURCES
    dns_udp_relay_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsSessionContext.cpp")
openppp2_add_cpp_test(dns_session_context_test SOURCES
    dns_session_context_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsSessionContext.cpp")
openppp2_add_cpp_test(dns_controller_test SOURCES
    dns_controller_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsController.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsUdpFlowRegistry.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsSessionContext.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsResponseHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(dns_controller_test PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(route_state_test SOURCES
    route_state_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteState.cpp")
openppp2_add_cpp_test(network_ownership_test SOURCES
    network_ownership_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/NetworkOwnership.cpp")
set_tests_properties(network_ownership_test PROPERTIES RUN_SERIAL TRUE)
openppp2_add_cpp_test(client_connection_teardown_state_test SOURCES
    client_connection_teardown_state_test.cpp)
openppp2_add_cpp_test(route_coordinator_test SOURCES
    route_coordinator_test.cpp
    support/network_recovery_windows_stub.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/NetworkRecoveryJournal.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/NetworkOwnership.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteCoordinator_mobile.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/MobileRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/WindowsRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/WindowsRouteSnapshot.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/WindowsRouteSnapshotWin32.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteSpecs.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteState.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/routing/HumanRoutingRouteSpecs.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
if(NOT WIN32)
    target_sources(route_coordinator_test PRIVATE support/network_recovery_route_stub.cpp)
endif()
target_compile_definitions(route_coordinator_test PRIVATE
    OPENPPP2_ROUTE_TEST_MOBILE)
set_tests_properties(route_coordinator_test PROPERTIES RUN_SERIAL TRUE)
if(UNIX AND NOT APPLE)
openppp2_add_cpp_test(linux_route_platform_contract_test SOURCES
    linux_route_platform_contract_test.cpp
    support/linux_route_platform_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/LinuxRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteSpecs.cpp")
openppp2_add_cpp_test(linux_ipv6_contract_test SOURCES
    linux_ipv6_contract_test.cpp)
target_link_libraries(linux_ipv6_contract_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
openppp2_add_cpp_test(windows_ipv6_route_transaction_test SOURCES
    windows_ipv6_route_transaction_test.cpp
    "${OPENPPP2_ROOT}/ppp/ipv6/IPv6RouteTransaction.cpp")
openppp2_add_cpp_test(route_platform_adapters_test SOURCES
    route_platform_adapters_test.cpp
    support/network_recovery_windows_stub.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/WindowsRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/WindowsRouteSnapshot.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/WindowsRouteSnapshotWin32.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/DarwinRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/MobileRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
openppp2_add_cpp_test(windows_route_snapshot_test SOURCES
    windows_route_snapshot_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/WindowsRouteSnapshot.cpp")
# Prefer a full bash (arrays/[[ ]] are required by the compile smoke);
# busybox-style shells such as w64devkit bash fail with "bad substitution".
if(NOT DEFINED OPENPPP2_BASH_PROGRAM)
    find_program(OPENPPP2_BASH_PROGRAM bash
        HINTS "C:/Program Files/Git/bin" "$ENV{ProgramFiles}/Git/bin"
        DOC "Bash interpreter for compile-smoke scripts")
endif()
add_test(
    NAME client_packet_dispatch_compile_test
    COMMAND "${OPENPPP2_BASH_PROGRAM}" "${OPENPPP2_ROOT}/tools/check_dispatch_handler_compiles.sh"
        "${CMAKE_CURRENT_BINARY_DIR}/client_packet_dispatch_compile.o")
set_tests_properties(client_packet_dispatch_compile_test PROPERTIES
    ENVIRONMENT "CXX=g++")
openppp2_add_cpp_test(aggregator_loader_test SOURCES
    aggregator_loader_test.cpp
    support/network_recovery_route_stub.cpp
    support/network_recovery_windows_stub.cpp
    ${OPENPPP2_AGGREGATOR_LOADER_TEST_SUPPORT}
    "${OPENPPP2_ROOT}/ppp/app/client/NetworkRecoveryJournal.cpp")
target_include_directories(aggregator_loader_test BEFORE PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/support/fake_aggligator")
openppp2_add_cpp_test(peer_prefix_route_entry_test SOURCES
    peer_prefix_route_entry_test.cpp
    support/peer_prefix_route_test_stubs.cpp)
openppp2_add_cpp_test(peer_prefix_route_from_json_test SOURCES
    peer_prefix_route_from_json_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
openppp2_add_cpp_test(switcher_timeout_registry_test SOURCES
    switcher_timeout_registry_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/SwitcherTimeoutRegistry.cpp")
openppp2_add_cpp_test(fake_ip_pool_test SOURCES
    fake_ip_pool_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/FakeIpPool.cpp")
openppp2_add_cpp_test(durable_fake_ip_store_test SOURCES
    durable_fake_ip_store_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DurableFakeIpStore.cpp")
target_link_libraries(durable_fake_ip_store_test PRIVATE Threads::Threads)
set_tests_properties(durable_fake_ip_store_test PROPERTIES LABELS "routing-policy;offline")
openppp2_add_cpp_test(policy_fake_ip_async_test SOURCES
    policy_fake_ip_async_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/PolicyFakeIpAsync.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DurableFakeIpStore.cpp")
target_link_libraries(policy_fake_ip_async_test PRIVATE Threads::Threads)
set_tests_properties(policy_fake_ip_async_test PROPERTIES LABELS "routing-policy;offline")
openppp2_add_cpp_test(dns_fake_ip_response_test SOURCES
    dns_fake_ip_response_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsFakeIpResponse.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/buffer.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/message.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/qs.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/rr.cpp")
openppp2_add_cpp_test(quic_reject_rate_limit_test SOURCES
    quic_reject_rate_limit_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/QuicRejectRateLimiter.cpp")
openppp2_add_cpp_test(client_bypass_route_loader_test SOURCES
    client_bypass_route_loader_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp")
openppp2_add_cpp_test(exchanger_static_echo_channel_test SOURCES
    exchanger_static_echo_channel_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp")
openppp2_add_cpp_test(client_datagram_port_manager_test SOURCES
    client_datagram_port_manager_test.cpp
    support/datagram_manager_stubs.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/udp/ClientDatagramPortManager.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/udp/UdpRelayHost.cpp")
openppp2_add_cpp_test(server_datagram_port_manager_test SOURCES
    server_datagram_port_manager_test.cpp
    support/server_datagram_manager_stubs.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/server/udp/ServerDatagramPortManager.cpp"
    "${OPENPPP2_ROOT}/ppp/app/server/udp/ServerUdpRelayHost.cpp")
openppp2_add_cpp_test(static_datagram_port_manager_test SOURCES
    static_datagram_port_manager_test.cpp
    support/static_datagram_manager_stubs.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/server/udp/StaticDatagramPortManager.cpp"
    "${OPENPPP2_ROOT}/ppp/app/server/udp/StaticUdpRelayHost.cpp")
openppp2_add_cpp_test(tcp_mss_clamp_test SOURCES
    tcp_mss_clamp_test.cpp
    support/socket_default_ttl_stub.cpp
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
openppp2_add_cpp_test(icmp_path_mtu_test SOURCES
    icmp_path_mtu_test.cpp
    support/socket_default_ttl_stub.cpp
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
# The client's downstream UDP fast path must emit the same bytes as the frame-object path.
openppp2_add_cpp_test(udp_frame_ipv4_packet_test SOURCES
    udp_frame_ipv4_packet_test.cpp
    support/socket_default_ttl_stub.cpp
    "${OPENPPP2_ROOT}/ppp/net/packet/UdpFrame.cpp"
    "${OPENPPP2_ROOT}/ppp/net/packet/IPFrame.cpp"
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(udp_frame_ipv4_packet_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    # BufferswapAllocator is stubbed in the test, so its typeinfo is not linked.
    target_compile_options(udp_frame_ipv4_packet_test PRIVATE -fno-sanitize=vptr)
endif()
openppp2_add_cpp_test(coroutine_backend_switch_test SOURCES coroutine_backend_switch_test.cpp)
target_link_libraries(coroutine_backend_switch_test PRIVATE boost_context Threads::Threads)
openppp2_add_cpp_test(yield_context_test SOURCES
    yield_context_test.cpp
    support/yield_context_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(yield_context_test PRIVATE boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
foreach(_test yield_context_exception_test yield_context_stack_test yield_context_multi_iocontext_test)
    openppp2_add_cpp_test(${_test} SOURCES
        ${_test}.cpp
        support/yield_context_test_stubs.cpp
        "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
        "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
        "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
        "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
    target_link_libraries(${_test} PRIVATE boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
endforeach()
if(UNIX AND NOT APPLE)
openppp2_add_cpp_test(tun_gso_mergeability_test SOURCES
    tun_gso_mergeability_test.cpp)
openppp2_add_cpp_test(tun_gso_coalescer_test SOURCES
    tun_gso_coalescer_test.cpp)
openppp2_add_cpp_test(tun_gso_ledger_test SOURCES
    tun_gso_ledger_test.cpp)
openppp2_add_cpp_test(tap_vnet_codec_test SOURCES
    tap_vnet_codec_test.cpp)
target_link_libraries(tap_vnet_codec_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
openppp2_add_cpp_test(random_test SOURCES
    random_test.cpp
    support/random_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/Random.cpp")
target_link_libraries(random_test PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(ssea_misaligned_tail_test SOURCES
    ssea_misaligned_tail_test.cpp
    ssea_misaligned_tail_sse.cpp
    ssea_misaligned_tail_avx2.cpp)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64|i[3-6]86|X86)$")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set_source_files_properties(ssea_misaligned_tail_sse.cpp PROPERTIES COMPILE_OPTIONS "-msse3")
        set_source_files_properties(ssea_misaligned_tail_avx2.cpp PROPERTIES COMPILE_OPTIONS "-mavx2")
    elseif(MSVC)
        set_source_files_properties(ssea_misaligned_tail_avx2.cpp PROPERTIES COMPILE_OPTIONS "/arch:AVX2")
    endif()
endif()
openppp2_add_cpp_test(spinlock_test SOURCES
    spinlock_test.cpp
    support/spinlock_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/threading/SpinLock.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(spinlock_test PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
# Keep the bounded contention regression isolated from other CTest jobs;
# external runner load is handled by cooperative acquisition in the test.
set_tests_properties(spinlock_test PROPERTIES RUN_SERIAL TRUE TIMEOUT 120)
openppp2_add_cpp_test(asynchronous_write_io_queue_test SOURCES
    asynchronous_write_io_queue_test.cpp
    support/yield_context_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/net/asio/IAsynchronousWriteIoQueue.cpp"
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(asynchronous_write_io_queue_test PRIVATE boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(post_if_running_test SOURCES
    post_if_running_test.cpp)
target_link_libraries(post_if_running_test PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(shared_buffer_receive_test SOURCES
    shared_buffer_receive_test.cpp)
target_link_libraries(shared_buffer_receive_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(tun_write_error_test SOURCES
    tun_write_error_test.cpp)
openppp2_add_cpp_test(snapshot_map_test SOURCES
    snapshot_map_test.cpp)
target_link_libraries(snapshot_map_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(ciphertext_encrypt_to_test SOURCES
    ciphertext_encrypt_to_test.cpp
    support/yield_context_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/cryptography/Ciphertext.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/EVP.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/rc4.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/digest.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/md5.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    # Exercise the AES-NI backend the production build enables with __SIMD__.
    target_sources(ciphertext_encrypt_to_test PRIVATE
        "${OPENPPP2_ROOT}/common/aesni/impl/simd_aes_128_cfb.cpp"
        "${OPENPPP2_ROOT}/common/aesni/impl/simd_aes_128_gcm.cpp"
        "${OPENPPP2_ROOT}/common/aesni/impl/simd_aes_256_cfb.cpp"
        "${OPENPPP2_ROOT}/common/aesni/impl/simd_aes_256_gcm.cpp")
    target_compile_definitions(ciphertext_encrypt_to_test PRIVATE __SIMD__)
    target_compile_options(ciphertext_encrypt_to_test PRIVATE -maes -msse2 -mpclmul -mssse3 -msse4.1)
endif()
target_link_libraries(ciphertext_encrypt_to_test PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(protector_network_request_test SOURCES
    protector_network_request_test.cpp)
target_link_libraries(protector_network_request_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(transmission_qos_concurrency_test SOURCES
    transmission_qos_concurrency_test.cpp
    support/yield_context_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/transmissions/ITransmissionQoS.cpp"
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(transmission_qos_concurrency_test PRIVATE boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(vdns_request_lifecycle_test SOURCES
    vdns_request_lifecycle_test.cpp)
target_link_libraries(vdns_request_lifecycle_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(mapping_port_connect_reentrancy_test SOURCES
    mapping_port_connect_reentrancy_test.cpp)
target_link_libraries(mapping_port_connect_reentrancy_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(geo_data_reader_test SOURCES
    geo_data_reader_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/routing/GeoDataReader.cpp")
openppp2_add_cpp_test(human_routing_rules_test SOURCES
    human_routing_rules_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/routing/GeoDataReader.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/routing/HumanRoutingRules.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsProviderCatalog.cpp")
target_link_libraries(human_routing_rules_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(tcp_routing_selector_test SOURCES
    tcp_routing_selector_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/routing/TcpRoutingSelector.cpp")
openppp2_add_cpp_test(udp_routing_selector_test SOURCES
    udp_routing_selector_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/routing/UdpRoutingSelector.cpp")
openppp2_add_cpp_test(human_dns_query_policy_test SOURCES
    human_dns_query_policy_test.cpp)
openppp2_add_cpp_test(protocol_sniffer_test SOURCES
    protocol_sniffer_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/routing/ProtocolSniffer.cpp")
openppp2_add_cpp_test(client_underlying_socket_protector_test SOURCES
    client_underlying_socket_protector_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/ClientUnderlyingSocketProtector.cpp")
target_link_libraries(client_underlying_socket_protector_test PRIVATE
    Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(tap_userspace_route_test SOURCES
    tap_userspace_route_test.cpp)
openppp2_add_cpp_test(rinetd_socket_protector_contract_test SOURCES
    rinetd_socket_protector_contract_test.cpp)
set_tests_properties(rinetd_socket_protector_contract_test PROPERTIES
    WORKING_DIRECTORY "${OPENPPP2_ROOT}")
openppp2_add_cpp_test(tcp_domain_sniff_lifecycle_test SOURCES
    tcp_domain_sniff_lifecycle_test.cpp)
set_tests_properties(tcp_domain_sniff_lifecycle_test PROPERTIES
    WORKING_DIRECTORY "${OPENPPP2_ROOT}")
openppp2_add_cpp_test(app_configuration_routing_test SOURCES
    app_configuration_routing_test.cpp)
set_tests_properties(app_configuration_routing_test PROPERTIES
    WORKING_DIRECTORY "${OPENPPP2_ROOT}")

# P0 routing-policy characterization: real parsers and pure decisions, no client
# startup. Reuse the existing partial AppConfiguration link fixture rather than
# maintaining a second copy of its dependency/stub list.
get_target_property(OPENPPP2_POLICY_BASELINE_CONFIG_SOURCES
    transport_auth_configuration_test SOURCES)
list(REMOVE_ITEM OPENPPP2_POLICY_BASELINE_CONFIG_SOURCES
    transport_auth_configuration_test.cpp
    support/policy_link_runtime_stub.cpp
    support/socket_platform_guard_stub.cpp)
openppp2_add_cpp_test(routing_policy_baseline_test SOURCES
    routing_policy_baseline_test.cpp
    support/windows_composition_stub.cpp
    support/policy_link_runtime_stub.cpp
    support/socket_platform_guard_stub.cpp
    ${OPENPPP2_POLICY_BASELINE_CONFIG_SOURCES}
    "${OPENPPP2_ROOT}/ppp/app/client/routing/HumanRoutingRules.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/routing/GeoDataReader.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/routing/TcpRoutingSelector.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/routing/UdpRoutingSelector.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/Rule.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsRedirectPlan.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsProviderCatalog.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsResolver.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsUdpFlowRegistry.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferswapAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferblockAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/net/Firewall.cpp"
    "${OPENPPP2_ROOT}/common/chnroutes2/chnroutes2.cpp")
target_compile_definitions(routing_policy_baseline_test PRIVATE
    OPENPPP2_POLICY_FIXTURE_DIR="${OPENPPP2_ROOT}/tests/contracts/routing-policy/v1"
    BUDDY_ALLOC_IMPLEMENTATION PPP_STUB_NO_GETTICKCOUNT PPP_STUB_NO_GETCURRENT)
target_compile_options(routing_policy_baseline_test PRIVATE -ffunction-sections -fdata-sections)
target_link_options(routing_policy_baseline_test PRIVATE -Wl,--gc-sections)
target_link_libraries(routing_policy_baseline_test PRIVATE
    boost_regex boost_filesystem Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    # Same partial allocator/RTTI boundary as transport_auth_configuration_test.
    target_compile_options(routing_policy_baseline_test PRIVATE -fno-sanitize=vptr)
endif()
set_tests_properties(routing_policy_baseline_test PROPERTIES LABELS "routing-policy;offline")
add_test(NAME routing_policy_baseline_harness_test
    COMMAND routing_policy_baseline_test --self-test)
set_tests_properties(routing_policy_baseline_harness_test PROPERTIES
    TIMEOUT 120 LABELS "routing-policy;offline")
openppp2_add_cpp_test(policy_runtime_guard_test SOURCES
    policy_runtime_guard_test.cpp
    support/windows_composition_stub.cpp
    support/policy_link_runtime_stub.cpp
    support/socket_platform_guard_stub.cpp
    "${OPENPPP2_ROOT}/ppp/threading/BufferswapAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferblockAllocator.cpp"
    "${OPENPPP2_ROOT}/common/chnroutes2/chnroutes2.cpp"
    ${OPENPPP2_POLICY_BASELINE_CONFIG_SOURCES})
target_compile_options(policy_runtime_guard_test PRIVATE -ffunction-sections -fdata-sections)
target_link_options(policy_runtime_guard_test PRIVATE -Wl,--gc-sections)
target_link_libraries(policy_runtime_guard_test PRIVATE
    boost_filesystem Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_definitions(policy_runtime_guard_test PRIVATE BUDDY_ALLOC_IMPLEMENTATION PPP_STUB_NO_GETTICKCOUNT PPP_STUB_NO_GETCURRENT)
elseif(ENABLE_SANITIZERS OR ENABLE_TSAN)
    target_compile_definitions(policy_runtime_guard_test PRIVATE BUDDY_ALLOC_IMPLEMENTATION)
endif()
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(policy_runtime_guard_test PRIVATE -fno-sanitize=vptr)
endif()
set_tests_properties(policy_runtime_guard_test PROPERTIES LABELS "routing-policy;offline")
openppp2_add_cpp_test(policy_configuration_test SOURCES
    policy_configuration_test.cpp
    support/windows_composition_stub.cpp
    support/policy_link_runtime_stub.cpp
    support/socket_platform_guard_stub.cpp
    "${OPENPPP2_ROOT}/ppp/threading/BufferswapAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferblockAllocator.cpp"
    ${OPENPPP2_POLICY_BASELINE_CONFIG_SOURCES})
target_compile_options(policy_configuration_test PRIVATE -ffunction-sections -fdata-sections)
target_compile_definitions(policy_configuration_test PRIVATE BUDDY_ALLOC_IMPLEMENTATION PPP_STUB_NO_GETTICKCOUNT PPP_STUB_NO_GETCURRENT)
target_link_options(policy_configuration_test PRIVATE -Wl,--gc-sections)
target_link_libraries(policy_configuration_test PRIVATE
    boost_filesystem Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(policy_configuration_test PRIVATE -fno-sanitize=vptr)
endif()
set_tests_properties(policy_configuration_test PROPERTIES LABELS "routing-policy;offline")

# P1 has an independent offline core; none of the runtime/transport stubs above
# participate in policy compilation or explanation.
add_library(openppp2_policy_test_core STATIC
    "${OPENPPP2_ROOT}/ppp/app/client/policy/PolicySourceLoader.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/policy/PolicyCompiler.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/policy/PolicyRuntime.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/routing/GeoDataReader.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsProviderCatalog.cpp"
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp"
    support/ppp_test_stubs.cpp)
target_compile_features(openppp2_policy_test_core PUBLIC cxx_std_17)
target_include_directories(openppp2_policy_test_core PUBLIC ${OPENPPP2_TEST_INCLUDES})
target_compile_definitions(openppp2_policy_test_core PRIVATE FUNCTION)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_definitions(openppp2_policy_test_core PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(openppp2_policy_test_core PRIVATE -Wno-deprecated-declarations -Wno-format)
endif()
target_link_libraries(openppp2_policy_test_core PUBLIC Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU"
    AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9
    AND NOT ANDROID)
    target_link_libraries(openppp2_policy_test_core PUBLIC stdc++fs)
endif()
target_sources(client_datagram_port_manager_test PRIVATE support/policy_no_coroutine_stubs.cpp)
target_link_libraries(client_datagram_port_manager_test PRIVATE openppp2_policy_test_core)
if(ENABLE_COVERAGE)
    target_compile_options(openppp2_policy_test_core PRIVATE -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(openppp2_policy_test_core INTERFACE -fprofile-instr-generate)
endif()
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(openppp2_policy_test_core PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(openppp2_policy_test_core INTERFACE -fsanitize=address,undefined)
endif()
if(ENABLE_TSAN AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_definitions(openppp2_policy_test_core PRIVATE PPP_COROUTINES_TSAN_ENABLED=1)
    target_compile_options(openppp2_policy_test_core PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
    target_link_options(openppp2_policy_test_core INTERFACE -fsanitize=thread)
endif()
add_library(openppp2_policy_update_test_core STATIC
    "${OPENPPP2_ROOT}/ppp/app/client/policy/DurablePolicyBundle.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/policy/PolicyUpdateFetcher.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/policy/PolicyUpdateService.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/policy/PolicyStatusFile.cpp")
target_link_libraries(openppp2_policy_update_test_core PUBLIC openppp2_policy_test_core)
target_compile_definitions(openppp2_policy_update_test_core PRIVATE FUNCTION)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_definitions(openppp2_policy_update_test_core PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
target_compile_options(openppp2_policy_update_test_core PRIVATE -ffunction-sections -fdata-sections)
if(ENABLE_COVERAGE)
    target_compile_options(openppp2_policy_update_test_core PRIVATE -fprofile-instr-generate -fcoverage-mapping)
endif()
if(ENABLE_SANITIZERS)
    target_compile_options(openppp2_policy_update_test_core PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()
if(ENABLE_TSAN)
    target_compile_options(openppp2_policy_update_test_core PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
endif()
add_library(openppp2_policy_cli_test_support STATIC
    "${OPENPPP2_ROOT}/ppp/app/ApplicationPolicyCommand.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/policy/LegacyPolicyAdapter.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/policy/LegacyPolicyMigration.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/routing/HumanRoutingRules.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/Rule.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsResolver.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsUdpFlowRegistry.cpp"
    "${OPENPPP2_ROOT}/ppp/net/Firewall.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferswapAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferblockAllocator.cpp"
    support/policy_link_runtime_stub.cpp
    support/socket_platform_guard_stub.cpp
    ${OPENPPP2_POLICY_BASELINE_CONFIG_SOURCES})
target_compile_definitions(openppp2_policy_cli_test_support PRIVATE FUNCTION BUDDY_ALLOC_IMPLEMENTATION)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_definitions(openppp2_policy_cli_test_support PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN PPP_STUB_NO_GETTICKCOUNT PPP_STUB_NO_GETCURRENT)
endif()
target_compile_options(openppp2_policy_cli_test_support PRIVATE -ffunction-sections -fdata-sections)
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(openppp2_policy_cli_test_support PRIVATE -Wno-deprecated-declarations -Wno-format)
endif()
target_link_libraries(openppp2_policy_cli_test_support PUBLIC
    openppp2_policy_update_test_core boost_regex boost_filesystem)
target_link_options(openppp2_policy_cli_test_support INTERFACE -Wl,--gc-sections)
if(ENABLE_COVERAGE)
    target_compile_options(openppp2_policy_cli_test_support PRIVATE -fprofile-instr-generate -fcoverage-mapping)
endif()
if(ENABLE_SANITIZERS)
    target_compile_options(openppp2_policy_cli_test_support PRIVATE -fsanitize=address,undefined -fno-sanitize=vptr -fno-omit-frame-pointer)
endif()
if(ENABLE_TSAN)
    target_compile_options(openppp2_policy_cli_test_support PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
endif()
foreach(_policy_test policy_source_loader_test policy_compiler_test policy_command_test
    policy_entrypoint_test policy_semantic_review_test policy_acceptance_test
    policy_index_property_test policy_cli_contract_test policy_legacy_migration_test policy_parser_robustness_test
    policy_runtime_test policy_runtime_acceptance_test policy_tcp_flow_test
    local_proxy_policy_test udp_direct_flow_policy_test udp_direct_flow_test)
    openppp2_add_cpp_test(${_policy_test} SOURCES ${_policy_test}.cpp)
    if(_policy_test STREQUAL "policy_command_test" OR _policy_test STREQUAL "policy_entrypoint_test"
        OR _policy_test STREQUAL "policy_cli_contract_test" OR _policy_test STREQUAL "policy_legacy_migration_test")
        target_link_libraries(${_policy_test} PRIVATE openppp2_policy_cli_test_support)
        if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
            # These Windows fixtures need stdafx.obj instead of the process-id
            # stub. On ELF platforms use the existing sectioned support library
            # so offline tests do not pull in runtime static initialization.
            target_sources(${_policy_test} PRIVATE "${OPENPPP2_ROOT}/ppp/stdafx.cpp")
            target_compile_definitions(${_policy_test} PRIVATE PPP_STUB_NO_PROCESS_ID)
        endif()
    endif()
    target_link_libraries(${_policy_test} PRIVATE openppp2_policy_test_core)
    set_tests_properties(${_policy_test} PROPERTIES LABELS "routing-policy;offline")
    if(_policy_test STREQUAL "policy_entrypoint_test")
        # main.cpp dispatches the recovery worker before normal bootstrap.  The
        # offline entrypoint fixture must link that implementation as well.
        target_sources(${_policy_test} PRIVATE
            "${CMAKE_CURRENT_LIST_DIR}/support/network_recovery_route_stub.cpp"
            "${CMAKE_CURRENT_LIST_DIR}/support/network_recovery_windows_stub.cpp"
            "${OPENPPP2_ROOT}/ppp/app/client/NetworkRecoveryJournal.cpp")
        target_compile_definitions(${_policy_test} PRIVATE
            OPENPPP2_POLICY_EXAMPLE_CONFIG="${OPENPPP2_ROOT}/tests/contracts/routing-policy/v2/example.json")
    endif()
endforeach()
openppp2_add_cpp_test(proxy_subnet_options_test SOURCES proxy_subnet_options_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/ProxySubnetOptions.cpp")
target_link_libraries(proxy_subnet_options_test PRIVATE openppp2_policy_cli_test_support)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_sources(proxy_subnet_options_test PRIVATE "${OPENPPP2_ROOT}/ppp/stdafx.cpp")
    target_compile_definitions(proxy_subnet_options_test PRIVATE PPP_STUB_NO_PROCESS_ID)
endif()
set_tests_properties(proxy_subnet_options_test PROPERTIES LABELS "offline")
target_compile_definitions(proxy_subnet_options_test PRIVATE OPENPPP2_SOURCE_ROOT="${OPENPPP2_ROOT}")
openppp2_add_cpp_test(policy_dns_transport_test SOURCES
    policy_dns_transport_test.cpp
    support/windows_composition_stub.cpp
    support/policy_link_runtime_stub.cpp
    ${OPENPPP2_POLICY_BASELINE_CONFIG_SOURCES}
    "${OPENPPP2_ROOT}/ppp/app/client/dns/PolicyResolverService.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsSessionContext.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsResolver.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsUdpFlowRegistry.cpp"
    "${OPENPPP2_ROOT}/ppp/net/Socket.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferswapAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferblockAllocator.cpp"
    "${OPENPPP2_ROOT}/common/chnroutes2/chnroutes2.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/buffer.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/message.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/qs.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/rr.cpp")
target_compile_definitions(policy_dns_transport_test PRIVATE BUDDY_ALLOC_IMPLEMENTATION PPP_STUB_NO_GETTICKCOUNT PPP_STUB_NO_SOCKET_CANCEL PPP_STUB_NO_GETCURRENT)
target_compile_options(policy_dns_transport_test PRIVATE -ffunction-sections -fdata-sections)
target_link_options(policy_dns_transport_test PRIVATE -Wl,--gc-sections)
target_link_libraries(policy_dns_transport_test PRIVATE
    openppp2_policy_test_core boost_regex boost_filesystem boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(policy_dns_transport_test PRIVATE -fno-sanitize=vptr)
endif()
set_tests_properties(policy_dns_transport_test PROPERTIES LABELS "routing-policy;offline")
add_executable(policy_offline_cli support/policy_offline_main.cpp)
target_link_libraries(policy_offline_cli PRIVATE openppp2_policy_cli_test_support)
foreach(_policy_extended_test policy_status_file_test policy_update_connectors_test policy_durable_bundle_test
    policy_update_service_test)
    openppp2_add_cpp_test(${_policy_extended_test} SOURCES ${_policy_extended_test}.cpp)
    target_link_libraries(${_policy_extended_test} PRIVATE openppp2_policy_update_test_core)
    set_tests_properties(${_policy_extended_test} PROPERTIES LABELS "routing-policy;offline")
endforeach()
set(_policy_tunnel_logger_source "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetLogger.cpp")
if(ENABLE_SANITIZERS OR ENABLE_TSAN)
    # Sanitizers retain the logger's unrelated runtime dependencies in this
    # partial fixture, which never supplies a logger to the connector.
    set(_policy_tunnel_logger_source support/policy_tunnel_logger_stub.cpp)
endif()
openppp2_add_cpp_test(policy_tunnel_update_connector_test SOURCES
    policy_tunnel_update_connector_test.cpp
    support/windows_composition_stub.cpp
    support/policy_link_runtime_stub.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/policy/PolicyTunnelUpdateConnector.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/PolicyTunnelDnsStream.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsResolver.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/SSL.cpp"
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/io/File.cpp"
    "${OPENPPP2_ROOT}/ppp/stdafx.cpp"
    "${OPENPPP2_ROOT}/ppp/Random.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/Thread.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/EVP.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/rc4.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/md5.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/digest.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/ssea.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp"
    "${OPENPPP2_ROOT}/common/chnroutes2/chnroutes2.cpp"
    support/chnroutes2_download_link_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/dns/DnsUdpFlowRegistry.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferswapAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferblockAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/Timer.cpp"
    "${OPENPPP2_ROOT}/ppp/net/Socket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/IPEndPoint.cpp"
    "${OPENPPP2_ROOT}/ppp/net/Ipep.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/StringAuxiliary.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    support/vdns_resolve_stub.cpp
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetLinklayer.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetTcpipConnection.cpp"
    ${_policy_tunnel_logger_source}
    "${OPENPPP2_ROOT}/ppp/DateTime.cpp"
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/buffer.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/message.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/qs.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/rr.cpp")
target_compile_options(policy_tunnel_update_connector_test PRIVATE -ffunction-sections -fdata-sections)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_definitions(policy_tunnel_update_connector_test PRIVATE PPP_STUB_NO_YIELD_SPAWN PPP_STUB_NO_DURATIONTIME PPP_STUB_NO_SOCKET_CANCEL)
endif()
target_compile_definitions(policy_tunnel_update_connector_test PRIVATE BUDDY_ALLOC_IMPLEMENTATION)
if(NOT WIN32)
    # The production link-layer multicast regression uses its clock and packet
    # allocator even when no transport is opened.
    target_sources(policy_tunnel_update_connector_test PRIVATE support/random_test_stubs.cpp)
endif()
target_link_options(policy_tunnel_update_connector_test PRIVATE -Wl,--gc-sections)
target_link_libraries(policy_tunnel_update_connector_test PRIVATE
    boost_filesystem boost_context openppp2_policy_test_core)
if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    # Partial-link fixture: allocator/transport RTTI key functions are not
    # linked, so the vptr check cannot reference their typeinfo.
    target_compile_options(policy_tunnel_update_connector_test PRIVATE -fno-sanitize=vptr)
endif()
set_tests_properties(policy_tunnel_update_connector_test PROPERTIES LABELS "routing-policy;offline")
openppp2_add_cpp_test(mta_handoff_telemetry_test SOURCES
    mta_handoff_telemetry_test.cpp)

if(ENABLE_POLICY_BENCHMARKS)
    add_executable(policy_offline_benchmark
        "${OPENPPP2_ROOT}/benchmarks/policy/policy_offline_benchmark.cpp")
    target_compile_features(policy_offline_benchmark PRIVATE cxx_std_17)
    target_compile_definitions(policy_offline_benchmark PRIVATE FUNCTION)
    target_link_libraries(policy_offline_benchmark PRIVATE openppp2_policy_test_core)
    get_target_property(_policy_dns_benchmark_sources policy_dns_transport_test SOURCES)
    list(REMOVE_ITEM _policy_dns_benchmark_sources policy_dns_transport_test.cpp)
    add_executable(policy_dns_cache_benchmark
        "${OPENPPP2_ROOT}/benchmarks/policy/policy_dns_cache_benchmark.cpp"
        ${_policy_dns_benchmark_sources})
    target_compile_features(policy_dns_cache_benchmark PRIVATE cxx_std_17)
    target_include_directories(policy_dns_cache_benchmark PRIVATE ${OPENPPP2_TEST_INCLUDES})
    target_compile_definitions(policy_dns_cache_benchmark PRIVATE FUNCTION BUDDY_ALLOC_IMPLEMENTATION)
    target_compile_options(policy_dns_cache_benchmark PRIVATE -ffunction-sections -fdata-sections -Wno-deprecated-declarations -Wno-format)
    target_link_options(policy_dns_cache_benchmark PRIVATE -Wl,--gc-sections)
    target_link_libraries(policy_dns_cache_benchmark PRIVATE openppp2_policy_test_core
        boost_regex boost_filesystem Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
    foreach(_policy_benchmark policy_offline_benchmark policy_dns_cache_benchmark)
        if(ENABLE_COVERAGE)
            target_compile_options(${_policy_benchmark} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
            target_link_options(${_policy_benchmark} PRIVATE -fprofile-instr-generate)
        endif()
        if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
            target_compile_options(${_policy_benchmark} PRIVATE -fsanitize=address,undefined -fno-sanitize=vptr -fno-omit-frame-pointer)
            target_link_options(${_policy_benchmark} PRIVATE -fsanitize=address,undefined)
        endif()
        if(ENABLE_TSAN AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
            target_compile_options(${_policy_benchmark} PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
            target_link_options(${_policy_benchmark} PRIVATE -fsanitize=thread)
        endif()
    endforeach()
endif()

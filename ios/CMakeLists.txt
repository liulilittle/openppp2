cmake_minimum_required(VERSION 3.21)

project(openppp2_ios LANGUAGES C CXX ASM)

option(ENABLE_COROCC "Use the experimental corocc L0 coroutine backend" OFF)
if(ENABLE_COROCC)
    message(WARNING "corocc is unsupported on iOS; using Boost fcontext")
    set(ENABLE_COROCC OFF CACHE BOOL "" FORCE)
endif()

# Production P2P v2 is enabled in iOS artifacts by default. This explicit
# switch keeps the release setting visible and allows an emergency rollback.
option(ENABLE_P2P_V2_PRODUCTION
    "Enable authenticated P2P v2 production capability" ON)

get_filename_component(OPENPPP2_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    if(NOT CMAKE_OSX_SYSROOT)
        set(CMAKE_OSX_SYSROOT iphoneos CACHE STRING "iOS SDK" FORCE)
    endif()
    if(NOT CMAKE_OSX_ARCHITECTURES)
        set(CMAKE_OSX_ARCHITECTURES arm64 CACHE STRING "iOS architectures" FORCE)
    endif()
    if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "15.0" CACHE STRING "Minimum iOS deployment target" FORCE)
    endif()
endif()

set(OPENPPP2_IOS_EXTRA_INCLUDE_DIRS "" CACHE STRING "Extra include directories, separated by semicolons")

set(OPENPPP2_IOS_OUTPUT_DIR "ios")
string(TOLOWER "${CMAKE_OSX_SYSROOT}" OPENPPP2_IOS_SYSROOT_LOWER)
if(OPENPPP2_IOS_SYSROOT_LOWER MATCHES "iphonesimulator")
    set(OPENPPP2_IOS_OUTPUT_DIR "ios-simulator")
endif()

file(GLOB_RECURSE OPENPPP2_COMMON_SOURCES CONFIGURE_DEPENDS
    "${OPENPPP2_ROOT}/common/lwip/my/*.c"
    "${OPENPPP2_ROOT}/common/lwip/core/*.c"
    "${OPENPPP2_ROOT}/common/lwip/api/*.c"
    "${OPENPPP2_ROOT}/common/aggligator/*.cpp"
    "${OPENPPP2_ROOT}/common/base64/*.cpp"
    "${OPENPPP2_ROOT}/common/chnroutes2/*.cpp"
    "${OPENPPP2_ROOT}/common/json/src/*.cpp"
    "${OPENPPP2_ROOT}/common/libtcpip/*.cpp"
    "${OPENPPP2_ROOT}/common/dnslib/*.cpp"
    "${OPENPPP2_ROOT}/common/unix/*.c"
    "${OPENPPP2_ROOT}/common/unix/*.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp"
    "${OPENPPP2_ROOT}/ppp/*.c"
    "${OPENPPP2_ROOT}/ppp/*.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/*.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/ppp/*.cpp")

set(OPENPPP2_BOOST_CONTEXT_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/third_party/boost-context")
if(CMAKE_OSX_ARCHITECTURES MATCHES "x86_64")
    list(APPEND OPENPPP2_COMMON_SOURCES
        "${OPENPPP2_BOOST_CONTEXT_SRC_DIR}/asm/make_x86_64_sysv_macho_gas.S"
        "${OPENPPP2_BOOST_CONTEXT_SRC_DIR}/asm/jump_x86_64_sysv_macho_gas.S"
        "${OPENPPP2_BOOST_CONTEXT_SRC_DIR}/asm/ontop_x86_64_sysv_macho_gas.S")
else()
    list(APPEND OPENPPP2_COMMON_SOURCES
        "${OPENPPP2_BOOST_CONTEXT_SRC_DIR}/asm/make_arm64_aapcs_macho_gas.S"
        "${OPENPPP2_BOOST_CONTEXT_SRC_DIR}/asm/jump_arm64_aapcs_macho_gas.S"
        "${OPENPPP2_BOOST_CONTEXT_SRC_DIR}/asm/ontop_arm64_aapcs_macho_gas.S")
endif()
list(APPEND OPENPPP2_COMMON_SOURCES
    "${OPENPPP2_BOOST_CONTEXT_SRC_DIR}/fcontext.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/boost_context_stack_traits.cpp")

add_library(openppp2_ios STATIC ${OPENPPP2_COMMON_SOURCES})

if(ENABLE_P2P_V2_PRODUCTION)
    target_compile_definitions(openppp2_ios PRIVATE OPENPPP2_P2P_V2_PRODUCTION=1)
else()
    target_compile_definitions(openppp2_ios PRIVATE OPENPPP2_P2P_V2_PRODUCTION=0)
endif()

target_compile_definitions(openppp2_ios PRIVATE
    _IPHONE
    IPHONE
    FUNCTION
    BUDDY_ALLOC_IMPLEMENTATION)

target_compile_options(openppp2_ios PRIVATE
    -fvisibility=hidden
    -Wno-format
    -Wno-inconsistent-missing-override
    -Wno-pointer-bool-conversion
    -Wno-unsequenced
    -Wno-null-dereference
    -Wno-gnu-variable-sized-type-not-at-end
    -Wno-tautological-undefined-compare
    -Wno-deprecated-declarations
    -Wno-shift-count-overflow)

target_include_directories(openppp2_ios PRIVATE
    "${OPENPPP2_ROOT}"
    "${OPENPPP2_ROOT}/common"
    "${OPENPPP2_ROOT}/common/json/include"
    "${OPENPPP2_ROOT}/common/lwip/my"
    "${OPENPPP2_ROOT}/common/lwip/include"
    "/usr/local/include"
    "/usr/local/opt/openssl/include"
    ${OPENPPP2_IOS_EXTRA_INCLUDE_DIRS})

set_target_properties(openppp2_ios PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${OPENPPP2_ROOT}/bin/${OPENPPP2_IOS_OUTPUT_DIR}")

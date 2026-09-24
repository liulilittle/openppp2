CMAKE_MINIMUM_REQUIRED(VERSION 3.0.0) 

# Define the solutions name.
SET(NAME ppp)
PROJECT(${NAME} VERSION 2.1.6.0 LANGUAGES C CXX)# CMAKE_CURRENT_SOURCE_DIR

# C/CXX compiler configurations.
IF(MSVC)
    SET(CMAKE_C_FLAGS "")
    SET(CMAKE_CXX_FLAGS "")
    SET(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} /nologo")
    ADD_COMPILE_OPTIONS(/EHsc)
    ADD_COMPILE_OPTIONS(/MP)
    ADD_COMPILE_OPTIONS(/bigobj)
    ADD_COMPILE_OPTIONS(/wd4244)
    ADD_COMPILE_OPTIONS(/wd4819)
    ADD_COMPILE_OPTIONS(/wd4566)
    ADD_COMPILE_OPTIONS(/wd4309)
    ADD_COMPILE_OPTIONS(/wd4334)
    ADD_COMPILE_OPTIONS(/wd4267)
    ADD_DEFINITIONS(-D_WIN32_WINNT=0x0601)
    ADD_DEFINITIONS(-D_CONSOLE)
    ADD_DEFINITIONS(-DUNICODE)
    ADD_DEFINITIONS(-D_UNICODE)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_DEPRECATE)
    ADD_DEFINITIONS(-D_CRT_NONSTDC_NO_DEPRECATE)
    ADD_DEFINITIONS(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
    ADD_DEFINITIONS(-D_CRT_NON_CONFORMING_SWPRINTFS)
    ADD_DEFINITIONS(-D_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)
    ADD_DEFINITIONS(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
    ADD_DEFINITIONS(-D_SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS)
    ADD_DEFINITIONS(-D__SIMD__)
    ADD_DEFINITIONS(-DJEMALLOC)
    ADD_DEFINITIONS(-DFUNCTION)
    ADD_DEFINITIONS(-DBUDDY_ALLOC_IMPLEMENTATION)
    IF(CMAKE_SIZEOF_VOID_P EQUAL 4)
        ADD_DEFINITIONS(-DWIN32)
    ENDIF()
    STRING(REGEX REPLACE "([/-])M[TD]d?" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    STRING(REGEX REPLACE "([/-])M[TD]d?" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
    STRING(REGEX REPLACE "([/-])M[TD]d?" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    STRING(REGEX REPLACE "([/-])M[TD]d?" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
    SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
    SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
ELSE()
    SET(CMAKE_C_FLAGS "-fPIE -fvisibility=hidden -Wno-format -Wno-implicit-function-declaration")
    SET(CMAKE_CXX_FLAGS "-fPIE -fvisibility=hidden -Wno-format -Wno-inconsistent-missing-override -Wno-pointer-bool-conversion -Wno-unsequenced -Wno-null-dereference -Wno-gnu-variable-sized-type-not-at-end -Wno-tautological-undefined-compare -Wno-deprecated-declarations -Wno-shift-count-overflow")
ENDIF()

# Configure predefined compilation macros.
# ADD_DEFINITIONS(-DANCIL_FD_BUFFER_STRUCT)
# ADD_DEFINITIONS(-DCURLINC_CURL)
# ADD_DEFINITIONS(-DTRANSMISSION_O1)
OPTION(ENABLE_SYSNAT "Enable SYSNAT kernel-bypass traffic control (Linux only)" OFF)
IF(ENABLE_SYSNAT)
    ADD_DEFINITIONS(-DSYSNAT)
ENDIF()

# Diagnostic-only AddressSanitizer build (default OFF). When enabled on a
# non-MSVC toolchain it (1) drops jemalloc so ASan's allocator interceptors are
# actually in effect (jemalloc would otherwise take over malloc/free and hide
# heap errors), and (2) relaxes the fully-static link below so libasan can be
# linked. NEVER ship an ASan build to production; it is for reproducing the
# vmux teardown heap-corruption only.
OPTION(ENABLE_ASAN "Build with AddressSanitizer (diagnostic only; disables jemalloc)" OFF)
OPTION(ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer (diagnostic only)" OFF)
SET(PPP_SANITIZER_FLAGS "")
IF(ENABLE_ASAN)
    SET(PPP_SANITIZER_FLAGS "${PPP_SANITIZER_FLAGS} -fsanitize=address")
ENDIF()
IF(ENABLE_UBSAN)
    SET(PPP_SANITIZER_FLAGS "${PPP_SANITIZER_FLAGS} -fsanitize=undefined")
ENDIF()
IF((ENABLE_ASAN OR ENABLE_UBSAN) AND NOT MSVC)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${PPP_SANITIZER_FLAGS} -fno-omit-frame-pointer -g")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PPP_SANITIZER_FLAGS} -fno-omit-frame-pointer -g")
ENDIF()
IF(NOT ENABLE_ASAN AND NOT ENABLE_UBSAN)
    ADD_DEFINITIONS(-DJEMALLOC)
ENDIF()
ADD_DEFINITIONS(-DFUNCTION)
ADD_DEFINITIONS(-DBUDDY_ALLOC_IMPLEMENTATION)

# This file is shared with liburing and that has to autodetect
# If linux/time_types.h is available or not, it can
# Define UAPI_LINUX_IO_URING_H_SKIP_LINUX_TIME_TYPES_H
# If linux/time_types.h is not available
# ADD_DEFINITIONS(-DUAPI_LINUX_IO_URING_H_SKIP_LINUX_TIME_TYPES_H)

# When compiling with the musl-libc standard library, 
# You need to define the _MUSL__ preprocessor macro to ensure correct compilation.
# https://wiki.musl-libc.org/faq
# ADD_DEFINITIONS(-D__MUSL__)

# When using the musl-libc standard library, the _LARGEFILE64_SOURCE macro is not defined by default on some platforms. 
# If 64-bit functions extended by _LARGEFILE64_SOURCE, such as lseek64, are required, it needs to be explicitly defined.
# ADD_DEFINITIONS(-D_LARGEFILE64_SOURCE)

# ENV.
SET(PLATFORM_DEBUG FALSE)
IF(CMAKE_BUILD_TYPE STREQUAL "Debug" OR BT MATCHES "Debug")
    SET(PLATFORM_DEBUG TRUE)
ENDIF()

SET(PLATFORM_COMPILER_CLANG FALSE)
SET(PLATFORM_SYSTEM_LINUX FALSE)
SET(PLATFORM_SYSTEM_DARWIN FALSE)
SET(PLATFORM_SYSTEM_WINDOWS FALSE)

IF(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    SET(PLATFORM_COMPILER_CLANG TRUE)
ENDIF()

IF(CMAKE_SYSTEM_NAME STREQUAL "Windows" OR CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(PLATFORM_SYSTEM_WINDOWS TRUE)
ELSEIF(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME MATCHES "Darwin")
    SET(PLATFORM_SYSTEM_DARWIN TRUE)
ELSE()
    SET(PLATFORM_SYSTEM_LINUX TRUE)
ENDIF()

IF(PLATFORM_SYSTEM_WINDOWS)
    IF(NOT CMAKE_BUILD_TYPE)
        SET(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    ENDIF()

    IF(NOT CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT CMAKE_BUILD_TYPE STREQUAL "Release")
        MESSAGE(FATAL_ERROR "Windows builds only support Debug or Release.")
    ENDIF()
ENDIF()

# C
IF(PLATFORM_DEBUG)
    IF(MSVC)
        ADD_DEFINITIONS(-D_DEBUG)
    ELSE()
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DEBUG -g3")
    ENDIF()
ELSEIF(NOT MSVC)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
ENDIF()

# C/CXX
IF(PLATFORM_DEBUG)
    IF(MSVC)
        ADD_DEFINITIONS(-D_DEBUG)
    ELSE()
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_DEBUG -g3")
    ENDIF()
ELSEIF(NOT MSVC)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
ENDIF()

IF(MSVC AND NOT PLATFORM_DEBUG)
    ADD_DEFINITIONS(-DNDEBUG)
ENDIF()

# Reduce the display of compiler warnings.
IF(NOT MSVC)
    ADD_COMPILE_OPTIONS(-Wno-deprecated-declarations)
ENDIF()

# When compiling only linux kernel distributions >= 5.10 and later, 
# You can enable this macro to get the new io_uring asynchronous event driver model support.
OPTION(ENABLE_IO_URING "Enable io_uring async event driver for Boost.Asio (Linux kernel >= 5.10)" OFF)
IF(ENABLE_IO_URING AND PLATFORM_SYSTEM_LINUX)
    ADD_DEFINITIONS(-DBOOST_ASIO_HAS_IO_URING=1)
    ADD_DEFINITIONS(-DBOOST_ASIO_DISABLE_EPOLL=1)
ENDIF()

# Check C/CXX compiler supports.
INCLUDE(CheckCXXCompilerFlag)
IF(MSVC)
    SET(COMPILER_SUPPORTS_CXX17 TRUE)
    SET(COMPILER_SUPPORTS_CXX1Z FALSE)
ELSE()
    CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
    CHECK_CXX_COMPILER_FLAG("-std=c++1z" COMPILER_SUPPORTS_CXX1Z)
ENDIF()

# If the current compiler environment is detected to support AES.
OPTION(ENABLE_SIMD "Enable x86/x64 SIMD AES-NI implementation" OFF)

# Enable SSEA SIMD acceleration (SSSE3/SSE4.1/SSE4.2/AVX/AVX2) for the
# ssea-simd codec/transform suite.  Requires ENABLE_SIMD=ON as a prerequisite.
# When OFF, ssea-simd falls back to SSE2-only kernels at runtime regardless
# of the CPU's actual capability, because the higher-level intrinsics are
# gated behind compiler feature macros that are only defined when the
# corresponding -m flags are passed.
OPTION(ENABLE_SSEA_SIMD "Enable SSEA SIMD acceleration (SSSE3+AVX2, requires ENABLE_SIMD)" OFF)

# Optional telemetry/observability facade (default OFF for zero-cost on low-end hardware).
OPTION(PPP_TELEMETRY "Enable optional telemetry/OTel facade (adds non-zero runtime cost)" OFF)
IF(PPP_TELEMETRY)
    ADD_COMPILE_DEFINITIONS(PPP_TELEMETRY=1)
ENDIF()

OPTION(ENABLE_TESTS "Build unit tests (GTest)" OFF)
OPTION(ENABLE_VMUX_CHURN_TEST "Build the root-linked VMUX carrier churn test" OFF)
OPTION(ENABLE_VMUX_RECEIVE_SEMANTICS_TEST "Build the root-linked VMUX receive-semantics test" OFF)
OPTION(ENABLE_COVERAGE "Enable LLVM source coverage instrumentation" OFF)
OPTION(ENABLE_XTCP "Build with the pinned XTCP userspace TCP/IP stack (Linux desktop only)" OFF)
SET(XTCP_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third-party/xtcp" CACHE PATH "Path to the pinned XTCP source tree")
IF(ENABLE_COVERAGE AND NOT MSVC)
    INCLUDE(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Coverage.cmake)
ENDIF()

IF(ENABLE_XTCP)
    IF(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR ANDROID)
        MESSAGE(FATAL_ERROR "ENABLE_XTCP is supported only for Linux desktop builds.")
    ENDIF()
    IF(NOT EXISTS "${XTCP_SOURCE_DIR}/CMakeLists.txt")
        MESSAGE(FATAL_ERROR "XTCP source tree not found at ${XTCP_SOURCE_DIR}; run tools/prepare_xtcp.sh first.")
    ENDIF()

    SET(XTCP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    SET(XTCP_BUILD_BENCH OFF CACHE BOOL "" FORCE)
    SET(XTCP_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
    SET(XTCP_BUILD_PLUGINS OFF CACHE BOOL "" FORCE)
    SET(XTCP_BUILD_LWIP OFF CACHE BOOL "" FORCE)
    SET(XTCP_BUILD_CC_PLUGINS ON CACHE BOOL "" FORCE)
    SET(XTCP_CHECKSUM_VALIDATE ON CACHE BOOL "" FORCE)
    ADD_SUBDIRECTORY("${XTCP_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/third-party/xtcp" EXCLUDE_FROM_ALL)
    IF(NOT TARGET xtcp_static)
        MESSAGE(FATAL_ERROR "XTCP source tree did not define the required xtcp_static target.")
    ENDIF()
ENDIF()

SET(PLATFORM_ARCH_X86 FALSE)
SET(PLATFORM_ARCH_ARM64 FALSE)
IF(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|X86_64|amd64|AMD64|i[3-6]86|x86)$")
    SET(PLATFORM_ARCH_X86 TRUE)
ELSEIF(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|AARCH64|arm64|ARM64)$")
    SET(PLATFORM_ARCH_ARM64 TRUE)
ELSEIF(MSVC AND (CMAKE_SIZEOF_VOID_P EQUAL 8 OR CMAKE_SIZEOF_VOID_P EQUAL 4))
    # MSVC cross-compiling: check _M_ARM64 at compile time
    # For now, assume x86/x64 for MSVC unless explicitly targeting ARM64
    SET(PLATFORM_ARCH_X86 TRUE)
ENDIF()

# For MSVC ARM64 cross-compilation, detect at compile time
IF(MSVC AND NOT PLATFORM_ARCH_X86 AND NOT PLATFORM_ARCH_ARM64)
    # This will be handled by _M_ARM64 in source code
ENDIF()

SET(__SIMD__ FALSE)
IF(PLATFORM_SYSTEM_WINDOWS AND PLATFORM_ARCH_X86)
    SET(__SIMD__ TRUE)
ENDIF()

IF(ENABLE_SIMD)
    IF(PLATFORM_ARCH_X86)
        SET(__SIMD__ TRUE)
    ELSE()
        MESSAGE(WARNING "ENABLE_SIMD was requested on a non-x86/x64 target; SIMD AES-NI will remain disabled.")
    ENDIF()
ENDIF()

IF(__SIMD__)
    # Add compiler flags per toolchain.
    IF(MSVC)
        IF(CMAKE_SIZEOF_VOID_P EQUAL 4)
            ADD_COMPILE_OPTIONS(/arch:SSE2)
        ENDIF()
    ELSE()
        ADD_COMPILE_OPTIONS(-maes -msse2 -mpclmul)
    ENDIF()

    # Add the AES_NI compiler macro.
    ADD_DEFINITIONS(-D__SIMD__)

    # SSEA SIMD acceleration: enable the instruction sets needed by the
    # ssea-simd codec/transform suite so the compiler defines the feature
    # macros (__SSSE3__, __SSE4_1__, __SSE4_2__, __AVX__, __AVX2__,
    # __POPCNT__) that gate the higher-level intrinsics.  Without these
    # flags the runtime CPUID probe detects the level, but the compiled
    # code for that level does not exist, so dispatch falls back to SSE2.
    IF(ENABLE_SSEA_SIMD)
        IF(NOT MSVC AND PLATFORM_ARCH_X86)
            ADD_COMPILE_OPTIONS(-mssse3 -msse4.1 -msse4.2 -mpopcnt -mavx -mavx2)
        ENDIF()
    ENDIF()

    # Additional options for the old version of GCC.
    IF(NOT MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
        ADD_COMPILE_OPTIONS(-march=westmere)
        ADD_COMPILE_OPTIONS(-fno-stack-protector)
    ENDIF()

    # AES is enabled, the source code of AES/128/256/CFB related to the library needs to be compiled.
    FILE(GLOB_RECURSE AES_NI_SOURCE_FILES 
        ${PROJECT_SOURCE_DIR}/common/aesni/impl/*.c 
        ${PROJECT_SOURCE_DIR}/common/aesni/impl/*.cpp)
ENDIF()

# According to the type of operating system to determine whether you need to check whether the compiler supports C/C++17, 
# On the MACOS system, the following check code is invalid, so directly specify the standard version of C/C++, 
# If an error or compilation does not pass, it means that you need to upgrade the LLVM GCC/CLANG compiler installed on MACOS.
IF(PLATFORM_SYSTEM_DARWIN)
    # The mandatory version is C++17.
    SET(CMAKE_CXX_STANDARD 17)

    # Minimum macOS deployment target for backward compatibility (macOS 13 Ventura).
    IF(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
        SET(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "Minimum macOS deployment target")
    ENDIF()

    ADD_DEFINITIONS(-D_GNU_SOURCE)
    ADD_DEFINITIONS(-DBOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED)
ELSE()
    # CXX17
    IF(MSVC)
        SET(CMAKE_CXX_STANDARD 17)
    ELSEIF(COMPILER_SUPPORTS_CXX17)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
    ELSEIF(COMPILER_SUPPORTS_CXX1Z)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1z")
    ELSE()
        MESSAGE(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++ 17 support. Please use a different C++ compiler.")
    ENDIF()
    
    # When the __MUSL__ macro is enabled and compilation errors are encountered, you can add the connector option: -static
    # -rdynamic -Wl,-Bstatic -Wl,-Bdynamic -lstdc++ -lpthread -ldl -lz -lrt
    IF(NOT MSVC)
        IF(ENABLE_ASAN OR ENABLE_UBSAN)
            # Sanitizers need their runtimes dynamically linked; do not force -Bstatic.
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -rdynamic ${PPP_SANITIZER_FLAGS}")
        ELSE()
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -rdynamic -Wl,-Bstatic") 
        ENDIF()
    ENDIF()
ENDIF()

# Set the tripartite library directorys.
SET(THIRD_PARTY_LIBRARY_DIR /root/dev CACHE PATH "Third-party library root directory")

IF(PLATFORM_SYSTEM_WINDOWS)
    SET(OPENSSL_USE_STATIC_LIBS TRUE)

    IF(NOT VCPKG_TARGET_TRIPLET)
        MESSAGE(FATAL_ERROR "VCPKG_TARGET_TRIPLET is required on Windows.")
    ENDIF()

    IF(VCPKG_INSTALLED_DIR)
        SET(VCPKG_DEP_DIR ${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET})
    ELSEIF(VCPKG_ROOT_DIR)
        SET(VCPKG_DEP_DIR ${VCPKG_ROOT_DIR}/installed/${VCPKG_TARGET_TRIPLET})
    ELSEIF(VCPKG_ROOT)
        SET(VCPKG_DEP_DIR ${VCPKG_ROOT}/installed/${VCPKG_TARGET_TRIPLET})
    ENDIF()

    SET(Boost_NO_SYSTEM_PATHS ON)
    SET(Boost_USE_STATIC_LIBS ON)
    SET(Boost_NO_WARN_NEW_VERSIONS ON)
    SET(BOOST_ROOT ${VCPKG_DEP_DIR})
    SET(BOOST_INCLUDEDIR ${VCPKG_DEP_DIR}/include)
    SET(BOOST_LIBRARYDIR ${VCPKG_DEP_DIR}/lib)
    SET(OPENSSL_ROOT_DIR ${VCPKG_DEP_DIR})

    FIND_PACKAGE(Boost REQUIRED COMPONENTS system filesystem regex thread coroutine context)
    FIND_PACKAGE(OpenSSL REQUIRED)
    FIND_PATH(JEMALLOC_INCLUDE_DIR NAMES jemalloc/jemalloc.h HINTS ${VCPKG_DEP_DIR}/include NO_DEFAULT_PATH)
    FIND_LIBRARY(JEMALLOC_LIBRARY NAMES jemalloc_s jemalloc libjemalloc HINTS ${VCPKG_DEP_DIR}/lib ${VCPKG_DEP_DIR}/debug/lib NO_DEFAULT_PATH)

    IF(NOT JEMALLOC_INCLUDE_DIR OR NOT JEMALLOC_LIBRARY)
        MESSAGE(FATAL_ERROR "Could not locate jemalloc from the active vcpkg installation for ${VCPKG_TARGET_TRIPLET}.")
    ENDIF()
ENDIF()

# Set the compiled header file search directorys.
INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/common
    ${PROJECT_SOURCE_DIR}/common/json/include
    ${PROJECT_SOURCE_DIR}/common/lwip/my
    ${PROJECT_SOURCE_DIR}/common/lwip/include
)

IF(NOT PLATFORM_SYSTEM_WINDOWS)
    INCLUDE_DIRECTORIES(
        ${THIRD_PARTY_LIBRARY_DIR}/boost
        ${THIRD_PARTY_LIBRARY_DIR}/jemalloc/include
        ${THIRD_PARTY_LIBRARY_DIR}/openssl/include
    )
ENDIF()

# Set the third library connection directory to searchs.
IF(NOT PLATFORM_SYSTEM_WINDOWS)
    LINK_DIRECTORIES(
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib
        ${THIRD_PARTY_LIBRARY_DIR}/jemalloc/lib
        ${THIRD_PARTY_LIBRARY_DIR}/openssl

        # ${THIRD_PARTY_LIBRARY_DIR}/liburing/src
        # ${THIRD_PARTY_LIBRARY_DIR}/curl/lib/.libs
    )
ENDIF()

# Set the compiled source file search directorys.
IF(MSVC)
    FILE(GLOB_RECURSE PLATFORM_SOURCE_FILES 
        ${PROJECT_SOURCE_DIR}/windows/*.c 
        ${PROJECT_SOURCE_DIR}/windows/*.cpp)
ELSEIF(PLATFORM_SYSTEM_DARWIN)
    FILE(GLOB_RECURSE PLATFORM_SOURCE_FILES 
        ${PROJECT_SOURCE_DIR}/darwin/*.c 
        ${PROJECT_SOURCE_DIR}/darwin/*.cpp)
ELSE()
    FILE(GLOB_RECURSE PLATFORM_SOURCE_FILES 
        ${PROJECT_SOURCE_DIR}/linux/*.c 
        ${PROJECT_SOURCE_DIR}/linux/*.cpp)
ENDIF()

# List of common cpp source files compilations for ppp/unix cmake solution projects.
#
# NOTE: Do NOT pass a bare filename such as "${PROJECT_SOURCE_DIR}/main.cpp" to
# FILE(GLOB_RECURSE ...). CMake interprets the last path component as a name
# pattern and walks the entire tree, which means any stray main.cpp sitting
# inside a vendored directory (e.g. third-party/boost/doc/html/boost_asio/
# example/**/main.cpp) gets silently added to this target. The Boost asio
# examples include C++20 coroutine code that cannot be built under -std=c++17
# and blew up the Linux CI build. main.cpp is added explicitly below.
FILE(GLOB_RECURSE SOURCE_FILES 
    ${PROJECT_SOURCE_DIR}/common/lwip/my/*.c 
    ${PROJECT_SOURCE_DIR}/common/lwip/core/*.c 
    ${PROJECT_SOURCE_DIR}/common/lwip/api/*.c 
    # ${PROJECT_SOURCE_DIR}/common/lwip/netif/*.c

    ${PROJECT_SOURCE_DIR}/common/aggligator/*.cpp 
    ${PROJECT_SOURCE_DIR}/common/base64/*.cpp 
    ${PROJECT_SOURCE_DIR}/common/chnroutes2/*.cpp 
    ${PROJECT_SOURCE_DIR}/common/json/src/*.cpp 
    ${PROJECT_SOURCE_DIR}/common/libtcpip/*.cpp 
    ${PROJECT_SOURCE_DIR}/common/dnslib/*.cpp 
    ${PROJECT_SOURCE_DIR}/common/aesni/aes.cpp

    ${PROJECT_SOURCE_DIR}/ppp/*.c 
    ${PROJECT_SOURCE_DIR}/ppp/*.cpp)

FILE(GLOB PPP_P2P_SOURCE_FILES ${PROJECT_SOURCE_DIR}/ppp/p2p/*.cpp)
LIST(APPEND SOURCE_FILES ${PPP_P2P_SOURCE_FILES})

LIST(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/main.cpp)

IF(PLATFORM_SYSTEM_WINDOWS)
    LIST(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/resource.rc)
ENDIF()

IF(__SIMD__)
    LIST(APPEND SOURCE_FILES ${AES_NI_SOURCE_FILES})
ENDIF()

IF(NOT MSVC)
    FILE(GLOB_RECURSE UNIX_SOURCE_FILES 
        ${PROJECT_SOURCE_DIR}/common/unix/*.c 
        ${PROJECT_SOURCE_DIR}/common/unix/*.cpp)
    LIST(APPEND SOURCE_FILES ${UNIX_SOURCE_FILES})
ENDIF()

# openppp2_sysnat.c requires libbpf headers; only compile it when SYSNAT is enabled.
LIST(REMOVE_ITEM PLATFORM_SOURCE_FILES
    ${PROJECT_SOURCE_DIR}/linux/ppp/tap/openppp2_sysnat.c)
IF(ENABLE_SYSNAT)
    LIST(APPEND PLATFORM_SOURCE_FILES
        ${PROJECT_SOURCE_DIR}/linux/ppp/tap/openppp2_sysnat.c)
ENDIF()

SET(PPP_MAIN_SOURCE ${PROJECT_SOURCE_DIR}/main.cpp)
SET(PPP_LIBRARY_SOURCES ${SOURCE_FILES} ${PLATFORM_SOURCE_FILES})
LIST(REMOVE_ITEM PPP_LIBRARY_SOURCES ${PPP_MAIN_SOURCE})
IF(PLATFORM_SYSTEM_WINDOWS)
    LIST(REMOVE_ITEM PPP_LIBRARY_SOURCES ${PROJECT_SOURCE_DIR}/resource.rc)
ENDIF()

ADD_LIBRARY(openppp2_lib STATIC ${PPP_LIBRARY_SOURCES})
IF(ENABLE_XTCP)
    TARGET_LINK_LIBRARIES(openppp2_lib xtcp_static)
    TARGET_COMPILE_DEFINITIONS(openppp2_lib PRIVATE
        PPP_ENABLE_XTCP=1
        PPP_XTCP_RUNTIME_WIRED=1
        PPP_XTCP_HAS_TIMER_DEADLINE=1)
ENDIF()

SET(PPP_EXECUTABLE_SOURCES ${PPP_MAIN_SOURCE})
IF(PLATFORM_SYSTEM_WINDOWS)
    LIST(APPEND PPP_EXECUTABLE_SOURCES ${PROJECT_SOURCE_DIR}/resource.rc)
ENDIF()

ADD_EXECUTABLE(${NAME} ${PPP_EXECUTABLE_SOURCES})

# Set the compilation output files path.
IF(NOT PPP_OUTPUT_DIR)
    IF(PLATFORM_SYSTEM_WINDOWS)
        SET(PPP_OUTPUT_DIR ${PROJECT_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})
    ELSE()
        SET(PPP_OUTPUT_DIR ${PROJECT_SOURCE_DIR}/bin)
    ENDIF()
ENDIF()
SET(EXECUTABLE_OUTPUT_PATH ${PPP_OUTPUT_DIR})

# Set up library connections to dependent libraries.
IF(PLATFORM_SYSTEM_WINDOWS)
    INCLUDE_DIRECTORIES(
        ${Boost_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${JEMALLOC_INCLUDE_DIR})

    SET_TARGET_PROPERTIES(${NAME} PROPERTIES LINK_FLAGS "/MANIFESTUAC:level='requireAdministrator' /SUBSYSTEM:CONSOLE")

    # PPP stays an executable; only the third-party dependencies are static.
    TARGET_LINK_LIBRARIES(openppp2_lib
        ws2_32
        iphlpapi
        setupapi
        ole32
        oleaut32
        wbemuuid
        advapi32
        userenv
        crypt32
        bcrypt
        ncrypt
        dnsapi

        ${Boost_LIBRARIES}
        ${OPENSSL_SSL_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${JEMALLOC_LIBRARY})

    TARGET_LINK_LIBRARIES(${NAME} openppp2_lib)
ELSEIF(PLATFORM_SYSTEM_DARWIN)
    SET(BUILD_SHARED_LIBS ON) # System

    # ASan diagnostic build drops jemalloc so the sanitizer's allocator
    # interceptors are in effect; default build links jemalloc as before.
    IF(ENABLE_ASAN OR ENABLE_UBSAN)
        SET(PPP_DARWIN_ALLOC_LIB "")
    ELSE()
        SET(PPP_DARWIN_ALLOC_LIB ${THIRD_PARTY_LIBRARY_DIR}/jemalloc/lib/libjemalloc.a)
    ENDIF()

    TARGET_LINK_LIBRARIES(openppp2_lib
        ${THIRD_PARTY_LIBRARY_DIR}/openssl/libssl.a 
        ${THIRD_PARTY_LIBRARY_DIR}/openssl/libcrypto.a 
        ${PPP_DARWIN_ALLOC_LIB}

        dl
        pthread

        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_system.a
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_coroutine.a 
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_thread.a 
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_context.a 
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_regex.a 
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_filesystem.a
        "-framework Security"
        "-framework CoreFoundation")

    TARGET_LINK_LIBRARIES(${NAME} openppp2_lib)
ELSEIF(PLATFORM_COMPILER_CLANG)
    SET(BUILD_SHARED_LIBS ON)

    SET(PPP_CLANG_LINK_LIBS
        libssl.a
        libcrypto.a
        atomic
        dl
        pthread
        libboost_system.a
        libboost_coroutine.a
        libboost_thread.a
        libboost_context.a
        libboost_regex.a
        libboost_filesystem.a)
    IF(NOT ENABLE_ASAN AND NOT ENABLE_UBSAN)
        LIST(APPEND PPP_CLANG_LINK_LIBS libjemalloc.a)
    ENDIF()
    LIST(APPEND PPP_CLANG_LINK_LIBS z zstd)
    IF(ENABLE_IO_URING)
        LIST(APPEND PPP_CLANG_LINK_LIBS uring)
    ENDIF()
    IF(ENABLE_SYSNAT)
        LIST(APPEND PPP_CLANG_LINK_LIBS bpf)
    ENDIF()
    TARGET_LINK_LIBRARIES(openppp2_lib ${PPP_CLANG_LINK_LIBS})
    TARGET_LINK_LIBRARIES(${NAME} openppp2_lib)
ELSEIF(NOT MSVC)
    IF(ENABLE_ASAN OR ENABLE_UBSAN)
        # ASan variant: drop libc.a (no full-static libc) and libjemalloc.a (let
        # ASan's allocator intercept malloc/free). Diagnostic build only.
        SET(PPP_LINUX_LINK_LIBS
            libssl.a
            libcrypto.a
            m
            unwind
            atomic
            stdc++
            rt
            dl
            pthread
            libboost_system.a
            libboost_coroutine.a
            libboost_thread.a
            libboost_context.a
            libboost_regex.a
            libboost_filesystem.a)
    ELSE()
        SET(PPP_LINUX_LINK_LIBS
            libc.a
            libssl.a
            libcrypto.a
            libjemalloc.a
            m
            unwind
            atomic
            stdc++
            rt
            dl
            pthread
            libboost_system.a
            libboost_coroutine.a
            libboost_thread.a
            libboost_context.a
            libboost_regex.a
            libboost_filesystem.a)
    ENDIF()
    IF(ENABLE_IO_URING)
        LIST(APPEND PPP_LINUX_LINK_LIBS uring)
    ENDIF()
    IF(ENABLE_SYSNAT)
        LIST(APPEND PPP_LINUX_LINK_LIBS bpf)
    ENDIF()
    TARGET_LINK_LIBRARIES(openppp2_lib ${PPP_LINUX_LINK_LIBS} z zstd)
    TARGET_LINK_LIBRARIES(${NAME} openppp2_lib)
ENDIF()

IF(ENABLE_VMUX_CHURN_TEST)
    ENABLE_TESTING()
    ADD_EXECUTABLE(vmux_net_churn_integration_test
        tests/cpp/vmux_net_churn_integration_test.cpp)
    TARGET_LINK_LIBRARIES(vmux_net_churn_integration_test openppp2_lib)
    IF(PLATFORM_SYSTEM_LINUX)
        TARGET_LINK_OPTIONS(vmux_net_churn_integration_test PRIVATE
            "-Wl,--exclude-libs,ALL")
    ENDIF()
    ADD_TEST(NAME vmux_net_churn_integration_test COMMAND vmux_net_churn_integration_test)
ENDIF()


IF(ENABLE_VMUX_RECEIVE_SEMANTICS_TEST)
    ENABLE_TESTING()
    ADD_EXECUTABLE(vmux_receive_semantics_test
        tests/cpp/vmux_receive_semantics_test.cpp)
    TARGET_LINK_LIBRARIES(vmux_receive_semantics_test openppp2_lib)
    IF(PLATFORM_SYSTEM_LINUX)
        TARGET_LINK_OPTIONS(vmux_receive_semantics_test PRIVATE
            "-Wl,--exclude-libs,ALL")
    ENDIF()
    ADD_TEST(NAME vmux_receive_semantics_test COMMAND vmux_receive_semantics_test)
ENDIF()

IF(ENABLE_TESTS)
    ENABLE_TESTING()
    ADD_SUBDIRECTORY(tests)
ENDIF()

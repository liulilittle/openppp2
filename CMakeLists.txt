CMAKE_MINIMUM_REQUIRED(VERSION 3.0.0) 

# Define the solutions name.
SET(NAME ppp)
PROJECT(${NAME} C CXX) # CMAKE_CURRENT_SOURCE_DIR

# C/CXX compiler configurations.
SET(CMAKE_C_FLAGS "-fPIE -fvisibility=hidden -Wno-format -Wno-implicit-function-declaration")
SET(CMAKE_CXX_FLAGS "-fPIE -fvisibility=hidden -Wno-format -Wno-inconsistent-missing-override -Wno-pointer-bool-conversion -Wno-unsequenced -Wno-null-dereference -Wno-gnu-variable-sized-type-not-at-end -Wno-tautological-undefined-compare -Wno-deprecated-declarations -Wno-shift-count-overflow")

# Configure predefined compilation macros.
# ADD_DEFINITIONS(-DANCIL_FD_BUFFER_STRUCT)
# ADD_DEFINITIONS(-DCURLINC_CURL)
# ADD_DEFINITIONS(-DTRANSMISSION_O1)
ADD_DEFINITIONS(-DJEMALLOC)
ADD_DEFINITIONS(-DBUDDY_ALLOC_IMPLEMENTATION)

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

IF(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    SET(PLATFORM_COMPILER_CLANG TRUE)
ENDIF()

IF(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME MATCHES "Darwin")
    SET(PLATFORM_SYSTEM_DARWIN TRUE)
ELSE()
    SET(PLATFORM_SYSTEM_LINUX TRUE)
ENDIF()

# C
IF(PLATFORM_DEBUG)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DEBUG -g3")
ELSE()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
ENDIF()

# C/CXX
IF(PLATFORM_DEBUG)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_DEBUG -g3")
ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
ENDIF()

# When compiling only linux kernel distributions >= 5.10 and later, 
# You can enable this macro to get the new io_uring asynchronous event driver model support.
# IF(PLATFORM_SYSTEM_LINUX) 
#     ADD_DEFINITIONS(-DBOOST_ASIO_HAS_IO_URING=1)
#     ADD_DEFINITIONS(-DBOOST_ASIO_DISABLE_EPOLL=1)
# ENDIF()

# Check C/CXX compiler supports.
INCLUDE(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
CHECK_CXX_COMPILER_FLAG("-std=c++1z" COMPILER_SUPPORTS_CXX1Z)

# If the current compiler environment is detected to support AES.
SET(__SIMD__ FALSE)
IF(__SIMD__)
    # Add in the compiler flag section.
    ADD_COMPILE_OPTIONS(-maes -msse2 -mpclmul)

    # Add the AES_NI compiler macro.
    ADD_DEFINITIONS(-D__SIMD__)

    # Additional options for the old version of GCC.
    IF(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
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

    ADD_DEFINITIONS(-D_GNU_SOURCE)
    ADD_DEFINITIONS(-DBOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED)
ELSE()
    # CXX17
    IF(COMPILER_SUPPORTS_CXX17)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
    ELSEIF(COMPILER_SUPPORTS_CXX1Z)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1z")
    ELSE()
        MESSAGE(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++ 17 support. Please use a different C++ compiler.")
    ENDIF()
    
    # When the __MUSL__ macro is enabled and compilation errors are encountered, you can add the connector option: -static
    # -rdynamic -Wl,-Bstatic -Wl,-Bdynamic -lstdc++ -lpthread -ldl -lz -lrt
    SET(CMAKE_EXE_LINKER_FLAGS "-static-libstdc++ -rdynamic -Wl,-Bstatic") 
ENDIF()

# Set the tripartite library directorys.
SET(THIRD_PARTY_LIBRARY_DIR /root/dev)

# Set the compiled header file search directorys.
INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/common
    ${PROJECT_SOURCE_DIR}/common/json/include
    ${PROJECT_SOURCE_DIR}/common/lwip/my
    ${PROJECT_SOURCE_DIR}/common/lwip/include

    ${THIRD_PARTY_LIBRARY_DIR}/boost
    ${THIRD_PARTY_LIBRARY_DIR}/jemalloc/include
    ${THIRD_PARTY_LIBRARY_DIR}/openssl/include

    # ${THIRD_PARTY_LIBRARY_DIR}/curl/include
)

# Set the third library connection directory to searchs.
LINK_DIRECTORIES(
    ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib
    ${THIRD_PARTY_LIBRARY_DIR}/jemalloc/lib
    ${THIRD_PARTY_LIBRARY_DIR}/openssl

    # ${THIRD_PARTY_LIBRARY_DIR}/curl/lib/.libs
)

# Set the compiled source file search directorys.
IF(PLATFORM_SYSTEM_DARWIN)
    FILE(GLOB_RECURSE PLATFORM_SOURCE_FILES 
        ${PROJECT_SOURCE_DIR}/darwin/*.c 
        ${PROJECT_SOURCE_DIR}/darwin/*.cpp)
ELSE()
    FILE(GLOB_RECURSE PLATFORM_SOURCE_FILES 
        ${PROJECT_SOURCE_DIR}/linux/*.c 
        ${PROJECT_SOURCE_DIR}/linux/*.cpp)
ENDIF()

# List of common cpp source files compilations for ppp/unix cmake solution projects.
FILE(GLOB_RECURSE SOURCE_FILES 
    ${PROJECT_SOURCE_DIR}/main.cpp 
    
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
    ${PROJECT_SOURCE_DIR}/common/unix/*.c 
    ${PROJECT_SOURCE_DIR}/common/unix/*.cpp 
    ${PROJECT_SOURCE_DIR}/common/aesni/aes.cpp

    ${PROJECT_SOURCE_DIR}/ppp/*.c 
    ${PROJECT_SOURCE_DIR}/ppp/*.cpp)

# Add the compiled output binary files.
ADD_EXECUTABLE(${NAME} ${SOURCE_FILES} ${PLATFORM_SOURCE_FILES} ${AES_NI_SOURCE_FILES})

# Set the compilation output files path.
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# Set up library connections to dependent libraries.
IF(PLATFORM_SYSTEM_DARWIN)
    SET(BUILD_SHARED_LIBS ON) # System

    TARGET_LINK_LIBRARIES(${NAME} 
        ${THIRD_PARTY_LIBRARY_DIR}/openssl/libssl.a 
        ${THIRD_PARTY_LIBRARY_DIR}/openssl/libcrypto.a 
        ${THIRD_PARTY_LIBRARY_DIR}/jemalloc/lib/libjemalloc.a

        dl
        pthread

        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_system.a
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_coroutine.a 
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_thread.a 
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_context.a 
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_regex.a 
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_filesystem.a) 
ELSEIF(PLATFORM_COMPILER_CLANG)
    SET(BUILD_SHARED_LIBS ON)

    TARGET_LINK_LIBRARIES(${NAME}
        libssl.a 
        libcrypto.a 
        libjemalloc.a
        # liburing.a

        atomic
        dl
        pthread

        libboost_system.a
        libboost_coroutine.a 
        libboost_thread.a 
        libboost_context.a
        libboost_regex.a 
        libboost_filesystem.a) 
ELSE()
    TARGET_LINK_LIBRARIES(${NAME} 
        libc.a
        libssl.a 
        libcrypto.a 
        libjemalloc.a
        # liburing.a

        atomic
        dl
        pthread

        libboost_system.a
        libboost_coroutine.a 
        libboost_thread.a 
        libboost_context.a 
        libboost_regex.a
        libboost_filesystem.a) 
ENDIF()
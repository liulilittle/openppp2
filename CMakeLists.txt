CMAKE_MINIMUM_REQUIRED(VERSION 3.0.0) 

# Define the solutions name.
SET(NAME ppp)
PROJECT(${NAME} C CXX) # CMAKE_CURRENT_SOURCE_DIR

# C/CXX compiler configurations.
SET(CMAKE_C_FLAGS "-fPIC -fvisibility=hidden -Wno-format -Wno-implicit-function-declaration")
SET(CMAKE_CXX_FLAGS "-fPIC -fvisibility=hidden -Wno-format -Wno-inconsistent-missing-override -Wno-pointer-bool-conversion -Wno-unsequenced -Wno-null-dereference -Wno-gnu-variable-sized-type-not-at-end -Wno-tautological-undefined-compare")

# Configure predefined compilation macros.
# ADD_DEFINITIONS(-DANCIL_FD_BUFFER_STRUCT)
# ADD_DEFINITIONS(-DCURLINC_CURL)
# ADD_DEFINITIONS(-DTRANSMISSION_O1)
ADD_DEFINITIONS(-DJEMALLOC)
ADD_DEFINITIONS(-DBUDDY_ALLOC_IMPLEMENTATION)

# C
IF(BT MATCHES "Debug" OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DEBUG -g3")
ELSE()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
ENDIF()

# C/CXX
IF(BT MATCHES "Debug" OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_DEBUG -g3")
ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
ENDIF()

# -rdynamic -Wl,-Bstatic -Wl,-Bdynamic -lstdc++ -lpthread -ldl -lz -lrt
SET(CMAKE_EXE_LINKER_FLAGS "-static-libstdc++ -rdynamic -Wl,-Bstatic") 

# Check C/CXX compiler supports.
INCLUDE(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
CHECK_CXX_COMPILER_FLAG("-std=c++1z" COMPILER_SUPPORTS_CXX1Z)

# CXX17
IF(COMPILER_SUPPORTS_CXX17)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
ELSEIF(COMPILER_SUPPORTS_CXX1Z)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1z")
ELSE()
    MESSAGE(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++ 17 support. Please use a different C++ compiler.")
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
FILE(GLOB_RECURSE SOURCE_FILES 
    ${PROJECT_SOURCE_DIR}/main.cpp 
    
    ${PROJECT_SOURCE_DIR}/common/lwip/my/*.c 
    ${PROJECT_SOURCE_DIR}/common/lwip/core/*.c 
    ${PROJECT_SOURCE_DIR}/common/lwip/api/*.c 
    # ${PROJECT_SOURCE_DIR}/common/lwip/netif/*.c

    ${PROJECT_SOURCE_DIR}/common/base64/*.cpp 
    ${PROJECT_SOURCE_DIR}/common/chnroutes2/*.cpp 
    ${PROJECT_SOURCE_DIR}/common/json/src/*.cpp 
    ${PROJECT_SOURCE_DIR}/common/libtcpip/*.cpp 

    ${PROJECT_SOURCE_DIR}/linux/*.c 
    ${PROJECT_SOURCE_DIR}/linux/*.cpp 
    ${PROJECT_SOURCE_DIR}/ppp/*.c 
    ${PROJECT_SOURCE_DIR}/ppp/*.cpp)

# Add the compiled output binary files.
ADD_EXECUTABLE(${NAME} ${SOURCE_FILES})

# Set the compilation output files path.
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# Set up library connections to dependent libraries.
IF (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    SET(BUILD_SHARED_LIBS ON)

    TARGET_LINK_LIBRARIES(${NAME} 
        libssl.a 
        libcrypto.a 
        libjemalloc.a

        dl
        pthread

        libboost_system.a
        libboost_coroutine.a 
        libboost_thread.a 
        libboost_context.a 
        libboost_filesystem.a) 
ELSE()
    TARGET_LINK_LIBRARIES(${NAME} 
        libc.a
        libssl.a 
        libcrypto.a 
        libjemalloc.a

        dl
        pthread

        libboost_system.a
        libboost_coroutine.a 
        libboost_thread.a 
        libboost_context.a 
        libboost_filesystem.a) 
ENDIF()
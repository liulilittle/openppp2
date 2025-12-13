#!/bin/bash

# Copyright  : Copyright (C) 2017 ~ 2035 SupersocksR ORG. All rights reserved.
# Description: PPP PRIVATE NETWORK™ 1 LINUX BUILD SCRIPT CROSS.(X) 1.0.0 VERSION.
# Author     : Kyou.
# Date-Time  : 2024/03/28

PPP_THIRD_PARTY_LIBRARY_DIR() {
    THIRD_PARTY_LIBRARY_DIR=$1
    PLATFORM=$2

    THIRD_PARTY_LIBRARY_PATH="$THIRD_PARTY_LIBRARY_DIR"_"$PLATFORM"
    if [ -d $THIRD_PARTY_LIBRARY_PATH ]; then
        echo $THIRD_PARTY_LIBRARY_PATH
        return
    fi

    THIRD_PARTY_LIBRARY_PATH="$THIRD_PARTY_LIBRARY_DIR"/"$PLATFORM"
    if [ -d $THIRD_PARTY_LIBRARY_PATH ]; then
        echo $THIRD_PARTY_LIBRARY_PATH
        return
    fi

    THIRD_PARTY_LIBRARY_PATH="$THIRD_PARTY_LIBRARY_DIR"
    if [ -d $THIRD_PARTY_LIBRARY_PATH ]; then
        echo $THIRD_PARTY_LIBRARY_PATH
        return
    fi
}

PPP_build() {
    PLATFORM=$2
    if [ -z "$PLATFORM" ]; then
        PLATFORM="amd64"
    fi

    THIRD_PARTY_LIBRARY_DIR=$(PPP_THIRD_PARTY_LIBRARY_DIR $1 $PLATFORM)
    if [ -z "$THIRD_PARTY_LIBRARY_DIR" ]; then
        return
    fi
    
    rm -rf build/
    mkdir -p build/
    cp -rf ./CMakeLists.txt ./build
    sed -i 's/SET(THIRD_PARTY_LIBRARY_DIR \/root\/dev)/SET(THIRD_PARTY_LIBRARY_DIR $ENV{THIRD_PARTY_LIBRARY_DIR})/' ./CMakeLists.txt
    cd build/

    ncpu=$(nproc)
    PLATFORM_LD=$3
    PLATFORM_CC=$4
    PLATFORM_CXX=$5
    export THIRD_PARTY_LIBRARY_DIR=$THIRD_PARTY_LIBRARY_DIR

    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=$PLATFORM_CC -DCMAKE_CXX_COMPILER=$PLATFORM_CXX -DCMAKE_LINKER=$PLATFORM_LD
    make -j $ncpu
    cd ../bin
    
    ARTIFACT_NAME=openppp2-linux-$PLATFORM.zip
    rm -rf $ARTIFACT_NAME
    zip -r $ARTIFACT_NAME ppp
    unset THIRD_PARTY_LIBRARY_DIR

    rm -rf ppp
    cd ../
    rm -rf ./CMakeLists.txt
    cd build/
    mv ./CMakeLists.txt ../
    cd ../
    rm -rf build/
}

apt-get update -y
apt-get install git build-essential lrzsz zip unzip libkrb5-dev libicu-dev screen iftop openssl libssl-dev libunwind8 iftop net-tools gcc-multilib gdb clang cmake curl wget autoconf -y
apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu -y
apt-get install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf -y
apt-get install gcc-powerpc64le-linux-gnu g++-powerpc64le-linux-gnu -y
apt-get install gcc-s390x-linux-gnu g++-s390x-linux-gnu -y
apt-get install gcc-riscv64-linux-gnu g++-riscv64-linux-gnu -y
apt-get install gcc-mipsel-linux-gnu g++-mipsel-linux-gnu -y

THIRD_PARTY_LIBRARY_ROOT=$1
if [ -z "$THIRD_PARTY_LIBRARY_ROOT" ] || [ ! -d "$THIRD_PARTY_LIBRARY_ROOT" ]; then
    THIRD_PARTY_LIBRARY_ROOT="/root/dev"
fi

PPP_build "$THIRD_PARTY_LIBRARY_ROOT" "aarch64" "aarch64-linux-gnu-ld" "aarch64-linux-gnu-gcc" "aarch64-linux-gnu-g++"
PPP_build "$THIRD_PARTY_LIBRARY_ROOT" "armv7l" "arm-linux-gnueabihf-ld" "arm-linux-gnueabihf-gcc" "arm-linux-gnueabihf-g++"
PPP_build "$THIRD_PARTY_LIBRARY_ROOT" "mipsel" "mipsel-linux-gnu-ld" "mipsel-linux-gnu-gcc" "mipsel-linux-gnu-g++"
PPP_build "$THIRD_PARTY_LIBRARY_ROOT" "ppc64el" "powerpc64le-linux-gnu-ld" "powerpc64le-linux-gnu-gcc" "powerpc64le-linux-gnu-g++"
PPP_build "$THIRD_PARTY_LIBRARY_ROOT" "riscv64" "riscv64-linux-gnu-ld" "riscv64-linux-gnu-gcc" "riscv64-linux-gnu-g++"
PPP_build "$THIRD_PARTY_LIBRARY_ROOT" "s390x" "s390x-linux-gnu-ld" "s390x-linux-gnu-gcc" "s390x-linux-gnu-g++"
PPP_build "$THIRD_PARTY_LIBRARY_ROOT" "amd64" "ld" "gcc" "g++"

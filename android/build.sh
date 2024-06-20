#! /bin/bash
 
# Copyright  : Copyright (C) 2017 ~ 2035 SupersocksR ORG. All rights reserved.
# Description: PPP PRIVATE NETWORK™ 2 ANDROID BUILD SCRIPT.(X) 1.0.0 VERSION.
# Author     : Kyou.
# Date-Time  : 2024/02/07

PPP_SCRIPT_NAME=$(basename "$0")

PPP_help() {
    echo "Copyright (C) 2017 ~ 2035 SupersocksR ORG. All rights reserved."
    echo "PPP PRIVATE NETWORK™ 2 ANDROID BUILD SCRIPT.(X) 1.0.0 VERSION."
    echo 
    echo "Usage:"
    echo "    ./$PPP_SCRIPT_NAME all"
    echo "    ./$PPP_SCRIPT_NAME x86"
    echo "    ./$PPP_SCRIPT_NAME x64"
    echo "    ./$PPP_SCRIPT_NAME arm"
    echo "    ./$PPP_SCRIPT_NAME arm64"
}

PPP_build() {
    mkdir -p build/
    cd build/
    export PPP_ANDROID_ABI=$1
    cmake .. \
        -DCMAKE_BUILD_TYPE=RELEASE \
        -DCMAKE_TOOLCHAIN_FILE=$NDK_ROOT/build/cmake/android.toolchain.cmake \
        -DCMAKE_SYSTEM_NAME=Android \
        -DANDROID_ABI=$2 \
        -DANDROID_NATIVE_API_LEVEL=21 \
        -DANDROID_STL=c++_static \
        $OTHER_ARGS
    make -j $(lscpu | grep "^CPU(s):" | awk '{print $2}')
    cd ..
}

PPP_OPERATE_TYPE=$1
PPP_OPERATE_TYPE=${PPP_OPERATE_TYPE,,}

if [[ $PPP_OPERATE_TYPE == "x86" ]]; then
    PPP_build "x86" "x86"
elif [[ $PPP_OPERATE_TYPE == "x64" ]]; then
    PPP_build "x64" "x86_64"
elif [[ $PPP_OPERATE_TYPE == "arm" ]]; then
    PPP_build "armv7a" "armeabi-v7a"
elif [[ $PPP_OPERATE_TYPE == "arm64" ]]; then
    PPP_build "aarch64" "arm64-v8a"
elif [[ $PPP_OPERATE_TYPE == "all" ]]; then
    PPP_build "x86" "x86"
    PPP_build "x64" "x86_64"
    PPP_build "armv7a" "armeabi-v7a"
    PPP_build "aarch64" "arm64-v8a"
else
    PPP_help
fi

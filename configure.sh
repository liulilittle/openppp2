#!/bin/sh
echo -e "Please make sure that perl has been installed alongside other build essentials.\n"
echo -e "The sum of compile time is depend on your CPUs.\n"
echo -e "Default compile threads is set to 4"
echo -e "Now starts to compile the libboost-dev"
THREADS=4
REPO_ROOT=$(pwd)
mkdir $REPO_ROOT/libs
cd $REPO_ROOT/depends/boost
./bootstrap.sh --prefix=$REPO_ROOT/libs
./b2 install --prefix=$REPO_ROOT/libs --without-python --without-graph --without-mpi --without-math -j$THREADS link=static
cd $REPO_ROOT/depends/jemalloc
./configure --prefix=$REPO_ROOT/libs
make -j$THREADS
make install
cd $REPO_ROOT/depends/openssl
./Configure --prefix=$REPO_ROOT/libs
make -j$THREADS
make install
cd $REPO_ROOT
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$THREADS

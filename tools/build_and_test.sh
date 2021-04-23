#!/bin/sh -l

cd /github/workspace
mkdir -p dist/usr/local/lib64
rm -rf cloudhsm-util
cp -rp cloudhsm cloudhsm-util
ls

cd cloudhsm-util
mkdir build
cd build
cmake --version
cmake .. -DENABLE_SHARED=on -DCMAKE_BUILD_TYPE=Release -DTARGET_RPATH="/usr/local/lib64"
make
cp ./Release/libcloudhsmpkcs11util.* /github/workspace/dist/usr/local/lib64
ls /github/workspace/dist
ls /github/workspace/dist/usr
ls /github/workspace/dist/usr/local
ls /github/workspace/dist/usr/local/lib64

cd /github/workspace/dist
cp -rf usr /
ls -l /usr/local/*
ls -l /usr/local/go/bin

env
cd /github/workspace/cloudhsm-util
LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib64:/usr/local/lib" /usr/local/go/bin/go mod download
echo "---- go test start ----"
LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib64:/usr/lib" /usr/local/go/bin/go test
echo "---- go test end ----"


#!/bin/sh

ls /usr/lib/pkcs11

cd /github/workspace
mkdir -p dist/usr/local/lib
rm -rf cloudhsm-util
cp -rp cloudhsm cloudhsm-util
ls

cd cloudhsm-util

ls -l /usr/local/go/bin

env
cd /github/workspace/cloudhsm-util
go mod download
echo "---- go test start ----"
LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib:/usr/lib/pkcs11" /usr/local/go/bin/go test
echo "---- go test end ----"


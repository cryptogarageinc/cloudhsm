# cloudhsm

## usage

### functions

* common
  * Pkcs11Initialize
  * Pkcs11InitializeWithContext
  * Pkcs11OpenSession
  * Pkcs11OpenSessionWithContext
  * Pkcs11GetSessionInfo
  * Pkcs11FinalizeAndCloseSession
  * Pkcs11CloseSession
  * Pkcs11Finalize
  * SetLogger
  * SetContextLogger
* CloudHSM SDK3 (with key handle)
  * GenerateSignature
  * VerifySignature
  * GetPubkey
  * GenerateSignatureWithContext
  * VerifySignatureWithContext
  * GetPubkeyWithContext
* CloudHSM SDK5 (with label)
  * GenerateSignatureWithLabel
  * VerifySignatureWithLabel
  * GetPubkeyWithLabel

## build

### re-generate from swig

```sh
mkdir build
cd build
cmake ..
make
cd ..
./gen_swig.sh
```

### build and install

```
cd cloudhsm
git checkout develop
mkdir build
cd build
cmake .. -D ENABLE_SHARED=on
make
sudo make install
```

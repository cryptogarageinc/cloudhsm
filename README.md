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

## develop

### re-generate from swig

```sh
./gen_swig.sh
```

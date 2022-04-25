
#ifndef AWS_CLOUDHSM_PKCS11_SIGN_H
#define AWS_CLOUDHSM_PKCS11_SIGN_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include "common.h"

#define MAX_PUBKEY_LENGTH    256
#define MAX_SIGNATURE_LENGTH 256

CK_RV generate_signature(void *context,
                         CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE key,
                         CK_MECHANISM_TYPE mechanism,
                         CK_BYTE_PTR data,
                         CK_ULONG data_length,
                         CK_BYTE_PTR signature,
                         CK_ULONG_PTR signature_length);
CK_RV verify_signature(void *context,
                       CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE key,
                       CK_MECHANISM_TYPE mechanism,
                       CK_BYTE_PTR data,
                       CK_ULONG data_length,
                       CK_BYTE_PTR signature,
                       CK_ULONG signature_length);
CK_RV generate_ec_keypair(void *context,
                          CK_SESSION_HANDLE session,
                          CK_BYTE_PTR named_curve_oid,
                          CK_ULONG named_curve_oid_len,
                          CK_OBJECT_HANDLE_PTR public_key,
                          CK_OBJECT_HANDLE_PTR private_key);

// ADD
CK_RV get_ec_pubkey(void *context,
                    CK_SESSION_HANDLE session,
                    CK_OBJECT_HANDLE key,
                    CK_BYTE_PTR pubkey,
                    CK_ULONG_PTR pubkey_length);

#ifdef __cplusplus
}
#endif

#endif

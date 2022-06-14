/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "sign.h"
#include <string.h>
#include "attributes.h"
#include "internal.h"

static CK_BBOOL true_val = TRUE;
/* static CK_BBOOL false_val = FALSE; */

CK_RV generate_signature(void *context,
                         CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE key,
                         CK_MECHANISM_TYPE mechanism,
                         CK_BYTE_PTR data,
                         CK_ULONG data_length,
                         CK_BYTE_PTR signature,
                         CK_ULONG_PTR signature_length)
{
    CK_RV rv;
    CK_MECHANISM mech;
    Pkcs11Context *ctx = (Pkcs11Context *)context;

    if (!context) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((data == NULL) || (signature == NULL) || (signature_length == NULL)) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "BadArg. IN:pData[%p], pSig[%p], pSigLen[%p]",
                 data, signature, signature_length);
        return CKR_ARGUMENTS_BAD;
    }
    if (!funcs) {
        return CKR_FUNCTION_FAILED;
    }

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_SignInit(session, &mech, key);
    if (rv != CKR_OK) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "SignInit.ERR[%#lx]. IN:session[%lu], mechanism[%#lx]",
                 rv, session, mechanism);
        return rv;
    }

    rv = funcs->C_Sign(session, data, data_length, signature, signature_length);
    if (rv == CKR_OK) {
        snprintf(ctx->message, sizeof(ctx->message) - 1,
                 "Sign.OK. IN:session[%lu], dataLen[%lu] OUT:sigLen[%lu]",
                 session, data_length, *signature_length);
    }
    else {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "Sign.ERR[%#lx]. IN:session[%lu], dataLen[%lu]",
                 rv, session, data_length);
    }
    return rv;
}

CK_RV verify_signature(void *context,
                       CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE key,
                       CK_MECHANISM_TYPE mechanism,
                       CK_BYTE_PTR data,
                       CK_ULONG data_length,
                       CK_BYTE_PTR signature,
                       CK_ULONG signature_length)
{
    CK_RV rv;
    CK_MECHANISM mech;
    Pkcs11Context *ctx = (Pkcs11Context *)context;

    if (!context) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!funcs) {
        return CKR_FUNCTION_FAILED;
    }

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_VerifyInit(session, &mech, key);
    if (rv != CKR_OK) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "VerifyInit.ERR[%#lx]. IN:session[%lu], mechanism[%#lx], pk[%lu]",
                 rv, session, mechanism, key);
        return rv;
    }

    rv = funcs->C_Verify(session, data, data_length, signature, signature_length);
    if (rv == CKR_OK) {
        snprintf(ctx->message, sizeof(ctx->message) - 1,
                 "Verify.OK. IN:session[%lu], pk[%lu], dataLen[%lu], sigLen[%lu]",
                 session, key, data_length, signature_length);
    }
    else {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "Verify.ERR[%#lx]. IN:session[%lu], pk[%lu], dataLen[%lu], sigLen[%lu]",
                 rv, session, key, data_length, signature_length);
    }
    return rv;
}

/**
 * Generate an EC key pair suitable for signing data and verifying signatures.
 * @param context context.
 * @param session Valid PKCS11 session.
 * @param named_curve_oid Curve to use when generating key pair. Valid curves are listed here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html
 * @param named_curve_oid_len Length of the OID
 * @param public_key_label the public key label.
 * @param private_key_label the private key label.
 * @param public_key Pointer where the public key handle will be stored.
 * @param private_key Pointer where the private key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_ec_keypair(void *context,
                          CK_SESSION_HANDLE session,
                          CK_BYTE_PTR named_curve_oid,
                          CK_ULONG named_curve_oid_len,
                          const char* public_key_label,
                          const char* private_key_label,
                          CK_OBJECT_HANDLE_PTR public_key,
                          CK_OBJECT_HANDLE_PTR private_key)
{
    CK_RV rv;
    CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
    Pkcs11Context *ctx = (Pkcs11Context *)context;
    CK_BYTE_PTR pk_label_ptr = (unsigned char*)public_key_label;
    CK_ULONG pk_label_len = strlen(public_key_label);
    CK_BYTE_PTR sk_label_ptr = (unsigned char*)private_key_label;
    CK_ULONG sk_label_len = strlen(private_key_label);

    CK_ATTRIBUTE public_key_template[] = {
        {CKA_VERIFY,    &true_val,       sizeof(CK_BBOOL)},
        {CKA_EC_PARAMS, named_curve_oid, named_curve_oid_len},
        {CKA_TOKEN,     &true_val,       sizeof(CK_BBOOL)},
        {CKA_LABEL,     pk_label_ptr,    pk_label_len},
    };

    CK_ATTRIBUTE private_key_template[] = {
        {CKA_SIGN,    &true_val,    sizeof(CK_BBOOL)},
        {CKA_PRIVATE, &true_val,    sizeof(CK_BBOOL)},
        {CKA_TOKEN,   &true_val,    sizeof(CK_BBOOL)},
        {CKA_LABEL,   sk_label_ptr, sk_label_len},
    };

    if (!context) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((public_key == NULL) || (private_key == NULL)) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "BadArg. IN:pPk[%p], pSk[%p]", public_key, private_key);
        return CKR_ARGUMENTS_BAD;
    }
    if (!funcs) {
        return CKR_FUNCTION_FAILED;
    }

    rv = funcs->C_GenerateKeyPair(session,
                                  &mech,
                                  public_key_template, sizeof(public_key_template) / sizeof(CK_ATTRIBUTE),
                                  private_key_template, sizeof(private_key_template) / sizeof(CK_ATTRIBUTE),
                                  public_key,
                                  private_key);
    if (rv == CKR_OK) {
        snprintf(ctx->message, sizeof(ctx->message) - 1,
                 "GenKeyPair.OK. IN:session[%lu], OUT:pk[%lu]", session, *public_key);
    }
    else {
        char *hex_str = NULL;
        if (bytes_to_new_hexstring(named_curve_oid, named_curve_oid_len, &hex_str) == 0) {
            snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                     "GenKeyPair.ERR[%#lx]. IN:session[%lu], namedCurvePid[%s]",
                     rv, session, hex_str);
            free(hex_str);
        }
        else {
            snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                     "GenKeyPair.ERR[%#lx]. IN:session[%lu]", rv, session);
        }
    }
    return rv;
}

/**
 * Get an EC pubkey.
 * @param context context.
 * @param session Valid PKCS11 session.
 * @param key Pointer where the public key handle will be stored.
 * @param pubkey Pointer where the public key byte array.
 * @param pubkey_length public key byte array length.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV get_ec_pubkey(void *context,
                    CK_SESSION_HANDLE session,
                    CK_OBJECT_HANDLE key,
                    CK_BYTE_PTR pubkey,
                    CK_ULONG_PTR pubkey_length)
{
    CK_RV rv;
    size_t size = 0;
    uint8_t *buffer = NULL;
    size_t buffer_size = 0;
    Pkcs11Context *ctx = (Pkcs11Context *)context;

    if (!context) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((pubkey == NULL) || (pubkey_length == NULL)) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "BadArg. IN:pPk[%p], pPkLen[%p]", pubkey, pubkey_length);
        return CKR_ARGUMENTS_BAD;
    }
    if (!funcs) {
        return CKR_FUNCTION_FAILED;
    }

    buffer_size = *pubkey_length;

    rv = attributes_get(session, key, CKA_EC_POINT, NULL, &size);
    if (rv != CKR_OK) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "GetArg.ERR[%#lx]. IN:session[%lu], key[%lu]", rv, session, key);
        return rv;
    }

    if (buffer_size < size) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "low pkLen. IN:pkLen[%lu], needLen[%lu]", size, buffer_size);
        return CKR_ARGUMENTS_BAD;
    }

    buffer = (uint8_t *)malloc(size);
    if (buffer == NULL) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "malloc.ERR. IN:pkLen[%lu]", size);
        return CKR_HOST_MEMORY;
    }

    memset(buffer, 0, size);
    rv = attributes_get(session, key, CKA_EC_POINT, buffer, &size);
    if (rv == CKR_OK) {
        memcpy(pubkey, buffer, size);
        *pubkey_length = (CK_ULONG)size;
        snprintf(ctx->message, sizeof(ctx->message) - 1,
                 "GetArg.OK. IN:session[%lu], key[%lu]", session, key);
    }
    else {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "GetArg.ERR[%#lx]. IN:session[%lu], key[%lu]", rv, session, key);
    }
    memset(buffer, 0, size);
    free(buffer);

    return rv;
}

CK_RV generate_signature_with_label(void *context,
                         CK_SESSION_HANDLE session,
                         const char* private_key_label,
                         CK_MECHANISM_TYPE mechanism,
                         CK_BYTE_PTR data,
                         CK_ULONG data_length,
                         CK_BYTE_PTR signature,
                         CK_ULONG_PTR signature_length)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key_handle = 0;
    rv = find_key_handle_with_label(context, session, private_key_label, &key_handle);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = generate_signature(context, session, key_handle, mechanism,
            data, data_length, signature, signature_length);
    return rv;
}

CK_RV verify_signature_with_label(void *context,
                       CK_SESSION_HANDLE session,
                       const char* public_key_label,
                       CK_MECHANISM_TYPE mechanism,
                       CK_BYTE_PTR data,
                       CK_ULONG data_length,
                       CK_BYTE_PTR signature,
                       CK_ULONG signature_length)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key_handle = 0;
    rv = find_key_handle_with_label(context, session, public_key_label, &key_handle);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = verify_signature(context, session, key_handle, mechanism,
            data, data_length, signature, signature_length);
    return rv;
}

/**
 * Get an EC pubkey with label.
 * @param context context.
 * @param session Valid PKCS11 session.
 * @param public_key_label the public key label.
 * @param pubkey Pointer where the public key byte array.
 * @param pubkey_length public key byte array length.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV get_ec_pubkey_with_label(void *context,
                    CK_SESSION_HANDLE session,
                    const char* public_key_label,
                    CK_BYTE_PTR pubkey,
                    CK_ULONG_PTR pubkey_length)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key_handle = 0;
    rv = find_key_handle_with_label(context, session, public_key_label, &key_handle);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = get_ec_pubkey(context, session, key_handle, pubkey, pubkey_length);
    return rv;
}

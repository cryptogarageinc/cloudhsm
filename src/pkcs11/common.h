/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#ifndef __C_SAMPLES_H__
#define __C_SAMPLES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <cryptoki.h>
#include <cloudhsm_pkcs11_vendor_defs.h>

CK_RV pkcs11_initialize(void *context, char *library_path);

CK_RV pkcs11_open_session(void *context, const CK_UTF8CHAR_PTR pin, CK_SESSION_HANDLE_PTR session);

CK_RV pkcs11_get_session_info(CK_SESSION_HANDLE session, CK_ULONG* slotID,
        CK_ULONG* state, CK_ULONG* flags, CK_ULONG* ulDeviceError);

void pkcs11_finalize_session(CK_SESSION_HANDLE session);
void pkcs11_close_session(CK_SESSION_HANDLE session);
void pkcs11_finalize();

int bytes_to_new_hexstring(char *bytes, size_t bytes_len, char **hex);

unsigned int get_ck_ulong_size();

CK_RV pkcs11_create_context(void **context);
void pkcs11_free_context(void *context);
CK_RV pkcs11_get_last_error_message(void *context, char **str);
CK_RV pkcs11_get_last_message(void *context, char **str);

#ifdef __cplusplus
}
#endif

#endif

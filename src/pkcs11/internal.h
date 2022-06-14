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
#ifndef AWS_CLOUDHSM_PKCS11_INTERNA_H
#define AWS_CLOUDHSM_PKCS11_INTERNA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <cryptoki.h>

extern CK_FUNCTION_LIST *funcs;

typedef struct _Pkcs11Context {
    char error_message[128];
    char message[128];
} Pkcs11Context;

// find_objects
CK_RV find_key_handle_with_label(void *context,
                                 CK_SESSION_HANDLE session,
                                 const char* label,
                                 CK_OBJECT_HANDLE_PTR key_handle);

#ifdef __cplusplus
}
#endif

#endif

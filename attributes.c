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

/**
 * @file
 *
 * @author Nabil S. Al-Ramli
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "common.h"
#include "attributes.h"
#include "internal.h"

/**
 * Get single object attribute.
 *
 * @returns CK_RV Value returned by the PKCS#11 library. This will indicate
 *   success or failure.
 */
CK_RV attributes_get(
        /** [in] Valid PKCS11 session. */
        CK_SESSION_HANDLE session,
        /** [in] The object handle. */
        CK_OBJECT_HANDLE object,
        /** [in] The attribute type. */
        CK_ATTRIBUTE_TYPE type,
        /** [out] The output buffer. Set to NULL to get the required buffer
         *    size in buf_len. */
        uint8_t *buf,
        /** [in, out] The size of buf. */
        CK_ULONG_PTR buf_len ) {
    CK_ATTRIBUTE attr[] = { { type, NULL_PTR, (CK_ULONG)0 } };
    CK_RV rv = CKR_OK;

    if (CK_INVALID_HANDLE == session) {
        return CKR_ARGUMENTS_BAD;
    }

    if (CK_INVALID_HANDLE == object) {
        return CKR_ARGUMENTS_BAD;
    }

    if (NULL == buf_len) {
        return CKR_ARGUMENTS_BAD;
    }

    if (buf) {
        /* this assumes that buf_len is sufficiently large,
         * set buf to NULL to get the required size
         */
        attr[0].pValue = (CK_BYTE_PTR)buf;
        attr[0].ulValueLen = (CK_ULONG) *buf_len;
        rv = funcs->C_GetAttributeValue(
            session,
            object,
            (CK_ATTRIBUTE_PTR)&attr[0].type,
            (CK_ULONG)1 );
    } else {
        rv = funcs->C_GetAttributeValue(
                session,
                object,
                (CK_ATTRIBUTE_PTR)&attr[0].type,
                (CK_ULONG)1 );
        if (rv == CKR_OK) {
            *buf_len = (size_t)attr[0].ulValueLen;
        }
    }

    return rv;
}

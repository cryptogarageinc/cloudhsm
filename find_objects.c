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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "common.h"
#include "internal.h"

/**
 * Find keys that match a passed CK_ATTRIBUTE template.
 * Memory will be allocated in a passed pointer, and reallocated as more keys
 * are found. The number of found keys is returned through the count parameter.
 * @param hSession
 * @param template
 * @param hObject
 * @param count
 * @return
 */
CK_RV find_by_attr(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *template, CK_ULONG attr_count, CK_ULONG *count,
                   CK_OBJECT_HANDLE_PTR *hObject) {
    CK_RV rv;

    if (NULL == hObject || NULL == template || NULL == count) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = funcs->C_FindObjectsInit(hSession, template, attr_count);
    if (rv != CKR_OK) {
        // fprintf(stderr, "Can't initialize search\n");
        return rv;
    }

    CK_ULONG max_objects = 25;
    bool searching = 1;
    *count = 0;
    while (searching) {
        CK_ULONG found = 0;
        *hObject = realloc(*hObject, (*count + max_objects) * sizeof(CK_OBJECT_HANDLE));
        if (NULL == *hObject) {
            // fprintf(stderr, "Could not allocate memory for objects\n");
            free(*hObject);
            *hObject = NULL;
            funcs->C_FindObjectsFinal(hSession);
            return CKR_HOST_MEMORY;
        }

        CK_OBJECT_HANDLE_PTR loc = *hObject;
        rv = funcs->C_FindObjects(hSession, &loc[*count], max_objects, &found);
        if (rv != CKR_OK) {
            // fprintf(stderr, "Can't run search\n");
            free(*hObject);
            *hObject = NULL;
            funcs->C_FindObjectsFinal(hSession);
            return rv;
        }

        (*count) += found;

        if (0 == found)
            searching = 0;
    }

    rv = funcs->C_FindObjectsFinal(hSession);
    if (rv != CKR_OK) {
        // fprintf(stderr, "Can't finalize search\n");
        free(*hObject);
        *hObject = NULL;
    }
    return rv;
}

CK_RV find_key_handle_with_label(void *context,
                                 CK_SESSION_HANDLE session,
                                 const char* label,
                                 CK_OBJECT_HANDLE_PTR key_handle)
{
    CK_RV rv;
    Pkcs11Context *ctx = (Pkcs11Context *)context;

    if (session == 0 || label == NULL || key_handle == NULL) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "BadArg. IN:sess[%lu], label[%p], pHdl[%p]",
                 session, label, key_handle);
        return CKR_ARGUMENTS_BAD;
    }

    CK_BYTE_PTR key_label = (unsigned char*)label;
    CK_ULONG label_len = strlen(label);
    CK_ULONG count = 0;
    CK_OBJECT_HANDLE *found_objects = NULL;
    CK_ATTRIBUTE attr[] = {
            {CKA_LABEL, key_label, label_len},
    };

    rv = find_by_attr(session, attr, 1, &count, &found_objects);
    if (CKR_OK != rv) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "find_by_attr.ERR[%#lx]. IN:sess[%lu], label[%s]",
                 rv, session, label);
        return rv;
    }

    if (count == 1) {
        *key_handle = found_objects[0];
    }
    free(found_objects);
    found_objects = NULL;

    if (count == 0) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "find_key_handle not found. IN:sess[%lu], label[%s]",
                 session, label);
        return CKR_DATA_LEN_RANGE;
    }
    if (count != 1) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "multiple key found. IN:sess[%lu], label[%s]",
                 session, label);
        return CKR_DATA_LEN_RANGE;
    }
    return CKR_OK;
}

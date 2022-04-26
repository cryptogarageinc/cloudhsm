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
#include <memory.h>
#include <stdlib.h>

#include "common.h"
#include "internal.h"

#if 0
#ifdef _WIN32
#define DEFAULT_PKCS11_LIBRARY_PATH "C:\\Program Files\\Amazon\\CloudHSM\\lib\\cloudhsm_pkcs11.dll"
#else
#define DEFAULT_PKCS11_LIBRARY_PATH "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
#endif
#endif

/**
 * Converts a byte array to a hex string.
 * This function will allocate the appropriate memory for the hex string.
 * If a valid pointer is passed, that pointer will be reallocated. This
 * allows the caller to reuse the same pointer through multiple calls.
 * @param bytes
 * @param bytes_len
 * @param hex
 * @return
 */
int bytes_to_new_hexstring(char *bytes, size_t bytes_len, char **hex_array) {
    if (!bytes || !hex_array) {
        return -1;
    }

    char *tmp = realloc(*hex_array, bytes_len * 2 + 1);
    if (!tmp) {
        if (*hex_array) {
            free(*hex_array);
        }
        return -1;
    }
    *hex_array = tmp;
    memset(*hex_array, 0, bytes_len * 2 + 1);

    char values[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    for (size_t i = 0, j = 0; i < bytes_len; i++, j += 2) {
        *((*hex_array) + j) = values[bytes[i] >> 4 & 0x0f];
        *((*hex_array) + j + 1) = values[bytes[i] & 0x0f];
    }

    return 0;
}

unsigned int get_ck_ulong_size() {
    return sizeof(CK_ULONG);
}
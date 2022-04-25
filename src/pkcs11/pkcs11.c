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
#include <stdlib.h>
#include <string.h>

// Header file needed to load shared libraries
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "common.h"
#include "internal.h"

CK_FUNCTION_LIST *funcs = NULL;

/**
 * Load the available PKCS#11 functions into our global function list.
 * @param library_path
 * @return
 */
#ifdef _WIN32
CK_RV pkcs11_load_functions(char *library_path) {
    CK_RV rv;
    CK_RV(*pFunc)();
    HINSTANCE hinstLib; 
      
    hinstLib = LoadLibrary(TEXT(library_path));
    if (hinstLib == NULL) {
        fprintf(stderr, "%s could not loaded. Check file exists.\n", library_path);
        return CKR_GENERAL_ERROR;
    }
      
    pFunc = (CK_RV (*)()) (intptr_t) GetProcAddress(hinstLib, "C_GetFunctionList"); 
    if (pFunc == NULL) {
        fprintf(stderr, "C_GetFunctionList() not found in module %s\n", library_path);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
      
    rv = pFunc(&funcs);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetFunctionList() did not initialize correctly\n");
        return rv;
    }
      
    return CKR_OK;
}
#else
CK_RV pkcs11_load_functions(char *library_path) {
    CK_RV rv;
    CK_RV(*pFunc)();
    void *d;

    d = dlopen(library_path, RTLD_NOW | RTLD_GLOBAL);
    if (d == NULL) {
        printf("%s not found in linklist of LD_LIBRARY_PATH\n", library_path);
        return CKR_GENERAL_ERROR;
    }

    pFunc = (CK_RV (*)()) dlsym(d, "C_GetFunctionList");
    if (pFunc == NULL) {
        printf("C_GetFunctionList() not found in module %s\n", library_path);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rv = pFunc(&funcs);
    if (rv != CKR_OK) {
        printf("C_GetFunctionList() did not initialize correctly\n");
        return rv;
    }

    return CKR_OK;
}
#endif

/**
 * Initialize the PKCS#11 library.
 * This loads the function list and initializes PKCS#11 with our flags.
 * @param context
 * @param library_path
 * @return
 */
CK_RV pkcs11_initialize(void *context, char *library_path) {
    CK_RV rv;
    Pkcs11Context *ctx = (Pkcs11Context *)context;

    if (!context) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!library_path) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "BadArg. IN:pLibPath[%p]", library_path);
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_load_functions(library_path);
    if (rv != CKR_OK) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "LoadFunc.ERR[%#lx]. IN:libPath[%s]", rv, library_path);
        return rv;
    }

    CK_C_INITIALIZE_ARGS args;
    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcs->C_Initialize(&args);
    if (rv != CKR_OK) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "Init.ERR[%#lx]. IN:libPath[%s]", rv, library_path);
    }
    else {
        snprintf(ctx->message, sizeof(ctx->message) - 1,
                 "Init.OK. IN:libPath[%s]", library_path);
    }

    return rv;
}

/**
 * Find a slot with an available token.
 * At this time CloudHSM only provides a token on Slot 0. So slot_id
 * only needs space for a single slot and we only call C_GetSlotList once.
 * @param id
 * @param slot_id
 * @return
 */
static CK_RV pkcs11_get_slot(CK_SLOT_ID *slot_id) {
    CK_RV rv;
    CK_ULONG slot_count;

    if (!slot_id) {
        return CKR_ARGUMENTS_BAD;
    }

    slot_count = 1;
    rv = funcs->C_GetSlotList(CK_TRUE, slot_id, &slot_count);
    if (rv != CKR_OK) {
        return rv;
    }

    return rv;
}

/**
 * Open and login to a session using a given pin.
 * @param context
 * @param pin
 * @param session
 * @return
 */
CK_RV pkcs11_open_session(void *context, const CK_UTF8CHAR_PTR pin,
        CK_SESSION_HANDLE_PTR session) {
    CK_RV rv;
    CK_SLOT_ID slot_id;
    Pkcs11Context *ctx = (Pkcs11Context *)context;

    if (!context) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!pin || !session) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "BadArg. IN:pPin[%p], pSession[%p]", pin, session);
        return CKR_ARGUMENTS_BAD;
    }

    if (!funcs) {
        return CKR_FUNCTION_FAILED;
    }

    rv = pkcs11_get_slot(&slot_id);
    if (rv != CKR_OK) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "GetSlot.ERR[%#lx]. slot_id[%lu]", rv, slot_id);
        return rv;
    }

    rv = funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL, NULL, session);
    if (rv != CKR_OK) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "OpenSession.ERR[%#lx]. slot_id[%lu]", rv, slot_id);
        return rv;
    }

    rv = funcs->C_Login(*session, CKU_USER, pin, (CK_ULONG) strlen(pin));
    if (rv == CKR_USER_ALREADY_LOGGED_IN) {
        /* Ignore the error if the session used the cache. */
        rv = CKR_OK;
        snprintf(ctx->message, sizeof(ctx->message) - 1,
                 "userAlreadyLoggedIn. slot_id[%lu] OUT:session[%lu]", slot_id, *session);
    }
    else if (rv != CKR_OK) {
        snprintf(ctx->error_message, sizeof(ctx->error_message) - 1,
                 "Login.ERR[%#lx]. session[%lu]", rv, *session);
        funcs->C_CloseSession(*session);
        *session = 0;
    } else {
        snprintf(ctx->message, sizeof(ctx->message) - 1,
                 "OK. slot_id[%lu] OUT:session[%lu]", slot_id, *session);
    }

    return rv;
}

/**
 * Get a session information.
 * @param session
 * @param slotID
 * @param state
 * @param flags
 * @param ulDeviceError
 * @return
 */
CK_RV pkcs11_get_session_info(CK_SESSION_HANDLE session, CK_ULONG* slotID,
        CK_ULONG* state, CK_ULONG* flags, CK_ULONG* ulDeviceError) {
    CK_RV rv;
    struct CK_SESSION_INFO info;
    memset(&info, 0, sizeof(info));

    if (!funcs) {
        return CKR_FUNCTION_FAILED;
    }

    rv = funcs->C_GetSessionInfo(session, &info);
    if (rv == CKR_OK) {
        if (slotID != NULL) {
            memcpy(slotID, &info.slotID, sizeof(info.slotID));
        }
        if (state != NULL) {
            memcpy(state, &info.state, sizeof(info.state));
        }
        if (flags != NULL) {
            memcpy(flags, &info.flags, sizeof(info.flags));
        }
        if (ulDeviceError != NULL) {
            memcpy(ulDeviceError, &info.ulDeviceError,
                   sizeof(info.ulDeviceError));
        }
    }
    return rv;
}

/**
 * Logout and finalize the PKCS#11 session.
 * @param session
 */
void pkcs11_finalize_session(CK_SESSION_HANDLE session) {
    if (!funcs) {
        printf("functions not loaded.");
        return;
    }

    funcs->C_Logout(session);
    funcs->C_CloseSession(session);
    funcs->C_Finalize(NULL);
    fflush(stdout);
}

/**
 * Logout the PKCS#11 session.
 * @param session
 */
void pkcs11_close_session(CK_SESSION_HANDLE session) {
    if (!funcs) {
        printf("functions not loaded.");
        return;
    }

    funcs->C_Logout(session);
    funcs->C_CloseSession(session);
    fflush(stdout);
}

/**
 * Finalize the PKCS#11.
 */
void pkcs11_finalize() {
    if (!funcs) {
        printf("functions not loaded.");
        return;
    }

    funcs->C_Finalize(NULL);
    fflush(stdout);
}

CK_RV pkcs11_create_context(void **context) {
    if (context == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    Pkcs11Context *ctx = (Pkcs11Context *)malloc(sizeof(Pkcs11Context));
    if (ctx == NULL) {
        return CKR_HOST_MEMORY;
    }
    memset(ctx, 0, sizeof(Pkcs11Context));
    *context = (void *)ctx;
    return CKR_OK;
}

void pkcs11_free_context(void *context) {
    if (context != NULL) {
        memset(context, 0, sizeof(Pkcs11Context));
        free(context);
    }
}

CK_RV pkcs11_get_last_error_message(void *context, char **str) {
    if (!context || !str) {
        return CKR_ARGUMENTS_BAD;
    }
    Pkcs11Context *ctx = (Pkcs11Context *)context;
    *str = (char *)malloc(strlen(ctx->error_message) + 1);
    if (*str == NULL) {
        return CKR_HOST_MEMORY;
    }
    strcpy(*str, ctx->error_message);
    return CKR_OK;
}

CK_RV pkcs11_get_last_message(void *context, char **str) {
    if (!context || !str) {
        return CKR_ARGUMENTS_BAD;
    }
    Pkcs11Context *ctx = (Pkcs11Context *)context;
    *str = (char *)malloc(strlen(ctx->message) + 1);
    if (*str == NULL) {
        return CKR_HOST_MEMORY;
    }
    strcpy(*str, ctx->message);
    return CKR_OK;
}

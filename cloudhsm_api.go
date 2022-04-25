package cloudhsm

import (
	"fmt"
	"unsafe"
)

// LogLevel ...
type LogLevel string

const (
	LogError LogLevel = "error"
	LogWarn  LogLevel = "warn"
	LogInfo  LogLevel = "info"
)

// LogFunc ...
type LogFunc func(level LogLevel, message string)

// SetLogger ...
func SetLogger(logger LogFunc) {
	logFunc = logger
}

// Pkcs11Initialize ...
func Pkcs11Initialize(path string) (err error) {
	context, err := createContext()
	if err != nil {
		return err
	}
	defer freeContext(context)

	rv := Pkcs11_initialize(context, path)
	err = convertRVtoByte(rv)
	if err == nil {
		fmt.Printf("call Pkcs11Initialize:%s\n", getMessage(context))
		logging(LogInfo, "Pkcs11Initialize", getMessage(context))
	} else {
		logging(LogError, "Pkcs11Initialize", getErrorMessage(context))
	}
	return
}

// Pkcs11OpenSession ...
func Pkcs11OpenSession(pin string) (sessionHandler uint64, err error) {
	context, err := createContext()
	if err != nil {
		return sessionHandler, err
	}
	defer freeContext(context)

	pinPtr := SwigcptrCK_UTF8CHAR_PTR(uintptr(unsafe.Pointer(&pin)))
	session := uint64(0)
	sessionHandlePtr := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
	sessionPtr := SwigcptrCK_SESSION_HANDLE_PTR(uintptr(unsafe.Pointer(&sessionHandlePtr)))

	rv := Pkcs11_open_session(context, pinPtr, sessionPtr)
	err = convertRVtoByte(rv)
	if err == nil {
		sessionHandler = session
		logging(LogInfo, "Pkcs11OpenSession", getMessage(context))
	} else {
		logging(LogError, "Pkcs11OpenSession", getErrorMessage(context))
	}
	return sessionHandler, err
}

// SessionInfo ...
type SessionInfo struct {
	// SlotID
	SlotID uint64
	// State
	State uint64
	// Flags
	Flags uint64
	// DeviceError
	DeviceError uint64
}

// Pkcs11GetSessionInfo ...
func Pkcs11GetSessionInfo(session uint64) (info *SessionInfo, err error) {
	sessionPtr := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))

	data := SessionInfo{}
	slotIdPtr := uintptr(unsafe.Pointer(&data.SlotID))
	statePtr := uintptr(unsafe.Pointer(&data.State))
	flagsPtr := uintptr(unsafe.Pointer(&data.Flags))
	deviceErrorPtr := uintptr(unsafe.Pointer(&data.DeviceError))
	slotIdPtrObj := SwigcptrCK_ULONG_PTR(uintptr(unsafe.Pointer(&slotIdPtr)))
	statePtrObj := SwigcptrCK_ULONG_PTR(uintptr(unsafe.Pointer(&statePtr)))
	flagsPtrObj := SwigcptrCK_ULONG_PTR(uintptr(unsafe.Pointer(&flagsPtr)))
	deviceErrorPtrObj := SwigcptrCK_ULONG_PTR(uintptr(unsafe.Pointer(&deviceErrorPtr)))

	rv := Pkcs11_get_session_info(sessionPtr, slotIdPtrObj, statePtrObj, flagsPtrObj, deviceErrorPtrObj)
	err = convertRVtoByte(rv)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

// Pkcs11FinalizeAndCloseSession ...
func Pkcs11FinalizeAndCloseSession(session uint64) {
	if session == uint64(0) {
		// for disable Go-Compiler optimization
		sessionObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
		Pkcs11_finalize_session(sessionObj)
	} else {
		sessionObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
		Pkcs11_finalize_session(sessionObj)
	}
	return
}

// Pkcs11CloseSession ...
func Pkcs11CloseSession(session uint64) {
	if session == uint64(0) {
		// for disable Go-Compiler optimization
		sessionObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
		Pkcs11_close_session(sessionObj)
	} else {
		sessionObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
		Pkcs11_close_session(sessionObj)
	}
	return
}

// Pkcs11Finalize ...
func Pkcs11Finalize() {
	Pkcs11_finalize()
	return
}

// GenerateSignature ...
func GenerateSignature(sessionHandle uint64, privkey uint64, mechType uint64, data []byte) (signature [64]byte, err error) {
	context, err := createContext()
	if err != nil {
		return signature, err
	}
	defer freeContext(context)

	sessionHandleObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&sessionHandle)))
	privkeyObj := SwigcptrCK_OBJECT_HANDLE(uintptr(unsafe.Pointer(&privkey)))
	mechTypeObj := SwigcptrCK_MECHANISM_TYPE(uintptr(unsafe.Pointer(&mechType)))

	dataPtr := uintptr(unsafe.Pointer(&data[0]))
	dataObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&dataPtr)))

	dataLen := uint64(len(data))
	dataLenObj := SwigcptrCK_ULONG(unsafe.Pointer(&dataLen))

	sigPtr := uintptr(unsafe.Pointer(&signature[0]))
	sigObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&sigPtr)))

	// 64 bytes signature
	written := uint64(64)
	sigLen := uintptr(unsafe.Pointer(&written))
	sigLenPtrObj := SwigcptrCK_ULONG_PTR(uintptr(unsafe.Pointer(&sigLen)))

	rv := Generate_signature(
		context,
		sessionHandleObj,
		privkeyObj,
		mechTypeObj,
		dataObj,
		dataLenObj,
		sigObj,
		sigLenPtrObj)

	err = convertRVtoByte(rv)
	if err == nil {
		logging(LogInfo, "GenerateSignature", getMessage(context))
	} else {
		logging(LogError, "GenerateSignature", getErrorMessage(context))
	}
	return
}

// VerifySignature ...
func VerifySignature(sessionHandle uint64, pubkey uint64, mechType uint64, data []byte, signature []byte) (err error) {
	context, err := createContext()
	if err != nil {
		return err
	}
	defer freeContext(context)

	sessionHandleObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&sessionHandle)))
	pubkeyObj := SwigcptrCK_OBJECT_HANDLE(uintptr(unsafe.Pointer(&pubkey)))
	mechTypeObj := SwigcptrCK_MECHANISM_TYPE(uintptr(unsafe.Pointer(&mechType)))

	dataPtr := uintptr(unsafe.Pointer(&data[0]))
	dataObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&dataPtr)))

	dataLen := uint64(len(data))
	dataLenObj := SwigcptrCK_ULONG(uintptr(unsafe.Pointer(&dataLen)))

	sigPtr := uintptr(unsafe.Pointer(&signature[0]))
	sigObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&sigPtr)))

	sigLen := uint64(len(signature))
	sigLenObj := SwigcptrCK_ULONG(uintptr(unsafe.Pointer(&sigLen)))

	rv := Verify_signature(
		context,
		sessionHandleObj,
		pubkeyObj,
		mechTypeObj,
		dataObj,
		dataLenObj,
		sigObj,
		sigLenObj)
	err = convertRVtoByte(rv)
	if err == nil {
		logging(LogInfo, "VerifySignature", getMessage(context))
	} else {
		logging(LogError, "VerifySignature", getErrorMessage(context))
	}
	return err
}

// GetPubkey ...
func GetPubkey(sessionHandle uint64, pubkey uint64) (pubkeyBytes []byte, err error) {
	context, err := createContext()
	if err != nil {
		return pubkeyBytes, err
	}
	defer freeContext(context)

	sessionHandleObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&sessionHandle)))
	pubkeyObj := SwigcptrCK_OBJECT_HANDLE(uintptr(unsafe.Pointer(&pubkey)))

	var data [256]byte
	dataPtr := uintptr(unsafe.Pointer(&data[0]))
	dataObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&dataPtr)))

	written := uint64(256)
	dataLen := uintptr(unsafe.Pointer(&written))
	dataLenPtrObj := SwigcptrCK_ULONG_PTR(uintptr(unsafe.Pointer(&dataLen)))

	rv := Get_ec_pubkey(
		context,
		sessionHandleObj,
		pubkeyObj,
		dataObj,
		dataLenPtrObj)

	err = convertRVtoByte(rv)
	if err == nil {
		pubkeyBytes = data[:written]
		logging(LogInfo, "GetPubkey", getMessage(context))
	} else {
		logging(LogError, "GetPubkey", getErrorMessage(context))
	}
	return pubkeyBytes, err
}

// GenerateKeyPair ...
func GenerateKeyPair(sessionHandle uint64, namedCurveOid []byte) (pubkey uint64, privkey uint64, err error) {
	context, err := createContext()
	if err != nil {
		return pubkey, privkey, err
	}
	defer freeContext(context)

	sessionHandleObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&sessionHandle)))

	dataPtr := uintptr(unsafe.Pointer(&namedCurveOid[0]))
	dataObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&dataPtr)))

	dataLen := uint64(len(namedCurveOid))
	dataLenObj := SwigcptrCK_ULONG(uintptr(unsafe.Pointer(&dataLen)))

	outPubkey := uint64(0)
	outPubkeyHandlePtr := SwigcptrCK_OBJECT_HANDLE(uintptr(unsafe.Pointer(&outPubkey)))
	outPubkeyPtr := SwigcptrCK_OBJECT_HANDLE_PTR(uintptr(unsafe.Pointer(&outPubkeyHandlePtr)))

	outPrivkey := uint64(0)
	outPrivkeyHandlePtr := SwigcptrCK_OBJECT_HANDLE(uintptr(unsafe.Pointer(&outPrivkey)))
	outPrivkeyPtr := SwigcptrCK_OBJECT_HANDLE_PTR(uintptr(unsafe.Pointer(&outPrivkeyHandlePtr)))

	rv := Generate_ec_keypair(
		context,
		sessionHandleObj,
		dataObj,
		dataLenObj,
		outPubkeyPtr,
		outPrivkeyPtr)

	err = convertRVtoByte(rv)
	if err == nil {
		pubkey = outPubkey
		privkey = outPrivkey
		logging(LogInfo, "GenerateKeyPair", getMessage(context))
	} else {
		logging(LogError, "GenerateKeyPair", getErrorMessage(context))
	}
	return pubkey, privkey, err
}

// private ---------------------------------------------------------------------

var (
	logFunc  LogFunc
	errorMap map[uint64]string
)

func init() {
	errorMap = make(map[uint64]string)
	errorMap[CKR_CANCEL] = "CKR_CANCEL"
	errorMap[CKR_HOST_MEMORY] = "CKR_HOST_MEMORY"
	errorMap[CKR_SLOT_ID_INVALID] = "CKR_SLOT_ID_INVALID"
	errorMap[CKR_GENERAL_ERROR] = "CKR_GENERAL_ERROR"
	errorMap[CKR_FUNCTION_FAILED] = "CKR_FUNCTION_FAILED"
	errorMap[CKR_ARGUMENTS_BAD] = "CKR_ARGUMENTS_BAD"
	errorMap[CKR_NO_EVENT] = "CKR_NO_EVENT"
	errorMap[CKR_NEED_TO_CREATE_THREADS] = "CKR_NEED_TO_CREATE_THREADS"
	errorMap[CKR_CANT_LOCK] = "CKR_CANT_LOCK"
	errorMap[CKR_ATTRIBUTE_READ_ONLY] = "CKR_ATTRIBUTE_READ_ONLY"
	errorMap[CKR_ATTRIBUTE_SENSITIVE] = "CKR_ATTRIBUTE_SENSITIVE"
	errorMap[CKR_ATTRIBUTE_TYPE_INVALID] = "CKR_ATTRIBUTE_TYPE_INVALID"
	errorMap[CKR_ATTRIBUTE_VALUE_INVALID] = "CKR_ATTRIBUTE_VALUE_INVALID"
	errorMap[CKR_ACTION_PROHIBITED] = "CKR_ACTION_PROHIBITED"
	errorMap[CKR_DATA_INVALID] = "CKR_DATA_INVALID"
	errorMap[CKR_DATA_LEN_RANGE] = "CKR_DATA_LEN_RANGE"
	errorMap[CKR_DEVICE_ERROR] = "CKR_DEVICE_ERROR"
	errorMap[CKR_DEVICE_MEMORY] = "CKR_DEVICE_MEMORY"
	errorMap[CKR_DEVICE_REMOVED] = "CKR_DEVICE_REMOVED"
	errorMap[CKR_ENCRYPTED_DATA_INVALID] = "CKR_ENCRYPTED_DATA_INVALID"
	errorMap[CKR_ENCRYPTED_DATA_LEN_RANGE] = "CKR_ENCRYPTED_DATA_LEN_RANGE"
	errorMap[CKR_FUNCTION_CANCELED] = "CKR_FUNCTION_CANCELED"
	errorMap[CKR_FUNCTION_NOT_PARALLEL] = "CKR_FUNCTION_NOT_PARALLEL"
	errorMap[CKR_FUNCTION_NOT_SUPPORTED] = "CKR_FUNCTION_NOT_SUPPORTED"
	errorMap[CKR_KEY_HANDLE_INVALID] = "CKR_KEY_HANDLE_INVALID"
	errorMap[CKR_KEY_SIZE_RANGE] = "CKR_KEY_SIZE_RANGE"
	errorMap[CKR_KEY_TYPE_INCONSISTENT] = "CKR_KEY_TYPE_INCONSISTENT"
	errorMap[CKR_KEY_NOT_NEEDED] = "CKR_KEY_NOT_NEEDED"
	errorMap[CKR_KEY_CHANGED] = "CKR_KEY_CHANGED"
	errorMap[CKR_KEY_NEEDED] = "CKR_KEY_NEEDED"
	errorMap[CKR_KEY_INDIGESTIBLE] = "CKR_KEY_INDIGESTIBLE"
	errorMap[CKR_KEY_FUNCTION_NOT_PERMITTED] = "CKR_KEY_FUNCTION_NOT_PERMITTED"
	errorMap[CKR_KEY_NOT_WRAPPABLE] = "CKR_KEY_NOT_WRAPPABLE"
	errorMap[CKR_KEY_UNEXTRACTABLE] = "CKR_KEY_UNEXTRACTABLE"
	errorMap[CKR_MECHANISM_INVALID] = "CKR_MECHANISM_INVALID"
	errorMap[CKR_MECHANISM_PARAM_INVALID] = "CKR_MECHANISM_PARAM_INVALID"
	errorMap[CKR_OBJECT_HANDLE_INVALID] = "CKR_OBJECT_HANDLE_INVALID"
	errorMap[CKR_OPERATION_ACTIVE] = "CKR_OPERATION_ACTIVE"
	errorMap[CKR_OPERATION_NOT_INITIALIZED] = "CKR_OPERATION_NOT_INITIALIZED"
	errorMap[CKR_PIN_INCORRECT] = "CKR_PIN_INCORRECT"
	errorMap[CKR_PIN_INVALID] = "CKR_PIN_INVALID"
	errorMap[CKR_PIN_LEN_RANGE] = "CKR_PIN_LEN_RANGE"
	errorMap[CKR_PIN_EXPIRED] = "CKR_PIN_EXPIRED"
	errorMap[CKR_PIN_LOCKED] = "CKR_PIN_LOCKED"
	errorMap[CKR_SESSION_CLOSED] = "CKR_SESSION_CLOSED"
	errorMap[CKR_SESSION_COUNT] = "CKR_SESSION_COUNT"
	errorMap[CKR_SESSION_HANDLE_INVALID] = "CKR_SESSION_HANDLE_INVALID"
	errorMap[CKR_SESSION_PARALLEL_NOT_SUPPORTED] = "CKR_SESSION_PARALLEL_NOT_SUPPORTED"
	errorMap[CKR_SESSION_READ_ONLY] = "CKR_SESSION_READ_ONLY"
	errorMap[CKR_SESSION_EXISTS] = "CKR_SESSION_EXISTS"
	errorMap[CKR_SESSION_READ_ONLY_EXISTS] = "CKR_SESSION_READ_ONLY_EXISTS"
	errorMap[CKR_SESSION_READ_WRITE_SO_EXISTS] = "CKR_SESSION_READ_WRITE_SO_EXISTS"
	errorMap[CKR_SIGNATURE_INVALID] = "CKR_SIGNATURE_INVALID"
	errorMap[CKR_SIGNATURE_LEN_RANGE] = "CKR_SIGNATURE_LEN_RANGE"
	errorMap[CKR_TEMPLATE_INCOMPLETE] = "CKR_TEMPLATE_INCOMPLETE"
	errorMap[CKR_TEMPLATE_INCONSISTENT] = "CKR_TEMPLATE_INCONSISTENT"
	errorMap[CKR_TOKEN_NOT_PRESENT] = "CKR_TOKEN_NOT_PRESENT"
	errorMap[CKR_TOKEN_NOT_RECOGNIZED] = "CKR_TOKEN_NOT_RECOGNIZED"
	errorMap[CKR_TOKEN_WRITE_PROTECTED] = "CKR_TOKEN_WRITE_PROTECTED"
	errorMap[CKR_UNWRAPPING_KEY_HANDLE_INVALID] = "CKR_UNWRAPPING_KEY_HANDLE_INVALID"
	errorMap[CKR_UNWRAPPING_KEY_SIZE_RANGE] = "CKR_UNWRAPPING_KEY_SIZE_RANGE"
	errorMap[CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT] = "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"
	errorMap[CKR_USER_ALREADY_LOGGED_IN] = "CKR_USER_ALREADY_LOGGED_IN"
	errorMap[CKR_USER_NOT_LOGGED_IN] = "CKR_USER_NOT_LOGGED_IN"
	errorMap[CKR_USER_PIN_NOT_INITIALIZED] = "CKR_USER_PIN_NOT_INITIALIZED"
	errorMap[CKR_USER_TYPE_INVALID] = "CKR_USER_TYPE_INVALID"
	errorMap[CKR_USER_ANOTHER_ALREADY_LOGGED_IN] = "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"
	errorMap[CKR_USER_TOO_MANY_TYPES] = "CKR_USER_TOO_MANY_TYPES"
	errorMap[CKR_WRAPPED_KEY_INVALID] = "CKR_WRAPPED_KEY_INVALID"
	errorMap[CKR_WRAPPED_KEY_LEN_RANGE] = "CKR_WRAPPED_KEY_LEN_RANGE"
	errorMap[CKR_WRAPPING_KEY_HANDLE_INVALID] = "CKR_WRAPPING_KEY_HANDLE_INVALID"
	errorMap[CKR_WRAPPING_KEY_SIZE_RANGE] = "CKR_WRAPPING_KEY_SIZE_RANGE"
	errorMap[CKR_WRAPPING_KEY_TYPE_INCONSISTENT] = "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"
	errorMap[CKR_RANDOM_SEED_NOT_SUPPORTED] = "CKR_RANDOM_SEED_NOT_SUPPORTED"
	errorMap[CKR_RANDOM_NO_RNG] = "CKR_RANDOM_NO_RNG"
	errorMap[CKR_DOMAIN_PARAMS_INVALID] = "CKR_DOMAIN_PARAMS_INVALID"
	errorMap[CKR_CURVE_NOT_SUPPORTED] = "CKR_CURVE_NOT_SUPPORTED"
	errorMap[CKR_BUFFER_TOO_SMALL] = "CKR_BUFFER_TOO_SMALL"
	errorMap[CKR_SAVED_STATE_INVALID] = "CKR_SAVED_STATE_INVALID"
	errorMap[CKR_INFORMATION_SENSITIVE] = "CKR_INFORMATION_SENSITIVE"
	errorMap[CKR_STATE_UNSAVEABLE] = "CKR_STATE_UNSAVEABLE"
	errorMap[CKR_CRYPTOKI_NOT_INITIALIZED] = "CKR_CRYPTOKI_NOT_INITIALIZED"
	errorMap[CKR_CRYPTOKI_ALREADY_INITIALIZED] = "CKR_CRYPTOKI_ALREADY_INITIALIZED"
	errorMap[CKR_MUTEX_BAD] = "CKR_MUTEX_BAD"
	errorMap[CKR_MUTEX_NOT_LOCKED] = "CKR_MUTEX_NOT_LOCKED"
	errorMap[CKR_NEW_PIN_MODE] = "CKR_NEW_PIN_MODE"
	errorMap[CKR_NEXT_OTP] = "CKR_NEXT_OTP"
	errorMap[CKR_EXCEEDED_MAX_ITERATIONS] = "CKR_EXCEEDED_MAX_ITERATIONS"
	errorMap[CKR_FIPS_SELF_TEST_FAILED] = "CKR_FIPS_SELF_TEST_FAILED"
	errorMap[CKR_LIBRARY_LOAD_FAILED] = "CKR_LIBRARY_LOAD_FAILED"
	errorMap[CKR_PIN_TOO_WEAK] = "CKR_PIN_TOO_WEAK"
	errorMap[CKR_PUBLIC_KEY_INVALID] = "CKR_PUBLIC_KEY_INVALID"
	errorMap[CKR_FUNCTION_REJECTED] = "CKR_FUNCTION_REJECTED"
	errorMap[CKR_VENDOR_DEFINED] = "CKR_VENDOR_DEFINED"
}

func logging(level LogLevel, funcName, message string) {
	if logFunc != nil && message != "" {
		logFunc(level, funcName+":"+message)
	}
}

func createContext() (context uintptr, err error) {
	ret := Pkcs11_create_context(&context)
	return context, convertRVtoByte(ret)
}

func freeContext(context uintptr) {
	Pkcs11_free_context(context)
}

func getErrorMessage(context uintptr) (msg string) {
	rv := Pkcs11_get_last_error_message(context, &msg)
	err := convertRVtoByte(rv)
	if err != nil {
		logging(LogError, "getErrorMessage", err.Error())
		return ""
	}
	return msg
}

func getMessage(context uintptr) (msg string) {
	rv := Pkcs11_get_last_message(context, &msg)
	err := convertRVtoByte(rv)
	if err != nil {
		logging(LogError, "getMessage", err.Error())
		return ""
	}
	return msg
}

func convertRVtoByte(rv CK_RV) (err error) {
	retCode := *(*uint64)(unsafe.Pointer(rv.Swigcptr()))
	if retCode == uint64(0) {
		return nil
	} else if errStr, ok := errorMap[retCode]; ok {
		err = fmt.Errorf("cloudhsm Error: errorCode=[%#x](%s)", retCode, errStr)
	} else {
		err = fmt.Errorf("cloudhsm Error: errorCode=[%#x]", retCode)
	}
	return err
}

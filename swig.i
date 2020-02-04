%module cloudhsm
%{
#include "src/pkcs11/common.h"
#include "src/pkcs11/sign.h"
%}
%insert(cgo_comment_typedefs) %{
#cgo CPPFLAGS: -I${SRCDIR}/include/pkcs11/v2.40
#cgo LDFLAGS: -L${SRCDIR}/build/Release -L/usr/local/lib -L/usr/local/lib64 -lcloudhsmpkcs11util -ldl
%}
%include "src/pkcs11/common.h"
%include "src/pkcs11/sign.h"
%go_import("fmt", "unsafe")
%insert(go_wrapper) %{

const CKR_CANCEL = 0x00000001
const CKR_HOST_MEMORY = 0x00000002
const CKR_SLOT_ID_INVALID = 0x00000003

const CKR_GENERAL_ERROR = 0x00000005
const CKR_FUNCTION_FAILED = 0x00000006

const CKR_ARGUMENTS_BAD = 0x00000007
const CKR_NO_EVENT = 0x00000008
const CKR_NEED_TO_CREATE_THREADS = 0x00000009
const CKR_CANT_LOCK = 0x0000000A

const CKR_ATTRIBUTE_READ_ONLY = 0x00000010
const CKR_ATTRIBUTE_SENSITIVE = 0x00000011
const CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012
const CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013

const CKR_ACTION_PROHIBITED = 0x0000001B

const CKR_DATA_INVALID = 0x00000020
const CKR_DATA_LEN_RANGE = 0x00000021
const CKR_DEVICE_ERROR = 0x00000030
const CKR_DEVICE_MEMORY = 0x00000031
const CKR_DEVICE_REMOVED = 0x00000032
const CKR_ENCRYPTED_DATA_INVALID = 0x00000040
const CKR_ENCRYPTED_DATA_LEN_RANGE = 0x00000041
const CKR_FUNCTION_CANCELED = 0x00000050
const CKR_FUNCTION_NOT_PARALLEL = 0x00000051

const CKR_FUNCTION_NOT_SUPPORTED = 0x00000054

const CKR_KEY_HANDLE_INVALID = 0x00000060

const CKR_KEY_SIZE_RANGE = 0x00000062
const CKR_KEY_TYPE_INCONSISTENT = 0x00000063

const CKR_KEY_NOT_NEEDED = 0x00000064
const CKR_KEY_CHANGED = 0x00000065
const CKR_KEY_NEEDED = 0x00000066
const CKR_KEY_INDIGESTIBLE = 0x00000067
const CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068
const CKR_KEY_NOT_WRAPPABLE = 0x00000069
const CKR_KEY_UNEXTRACTABLE = 0x0000006A

const CKR_MECHANISM_INVALID = 0x00000070
const CKR_MECHANISM_PARAM_INVALID = 0x00000071

const CKR_OBJECT_HANDLE_INVALID = 0x00000082
const CKR_OPERATION_ACTIVE = 0x00000090
const CKR_OPERATION_NOT_INITIALIZED = 0x00000091
const CKR_PIN_INCORRECT = 0x000000A0
const CKR_PIN_INVALID = 0x000000A1
const CKR_PIN_LEN_RANGE = 0x000000A2

const CKR_PIN_EXPIRED = 0x000000A3
const CKR_PIN_LOCKED = 0x000000A4

const CKR_SESSION_CLOSED = 0x000000B0
const CKR_SESSION_COUNT = 0x000000B1
const CKR_SESSION_HANDLE_INVALID = 0x000000B3
const CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4
const CKR_SESSION_READ_ONLY = 0x000000B5
const CKR_SESSION_EXISTS = 0x000000B6

const CKR_SESSION_READ_ONLY_EXISTS = 0x000000B7
const CKR_SESSION_READ_WRITE_SO_EXISTS = 0x000000B8

const CKR_SIGNATURE_INVALID = 0x000000C0
const CKR_SIGNATURE_LEN_RANGE = 0x000000C1
const CKR_TEMPLATE_INCOMPLETE = 0x000000D0
const CKR_TEMPLATE_INCONSISTENT = 0x000000D1
const CKR_TOKEN_NOT_PRESENT = 0x000000E0
const CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1
const CKR_TOKEN_WRITE_PROTECTED = 0x000000E2
const CKR_UNWRAPPING_KEY_HANDLE_INVALID = 0x000000F0
const CKR_UNWRAPPING_KEY_SIZE_RANGE = 0x000000F1
const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2
const CKR_USER_ALREADY_LOGGED_IN = 0x00000100
const CKR_USER_NOT_LOGGED_IN = 0x00000101
const CKR_USER_PIN_NOT_INITIALIZED = 0x00000102
const CKR_USER_TYPE_INVALID = 0x00000103

const CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104
const CKR_USER_TOO_MANY_TYPES = 0x00000105

const CKR_WRAPPED_KEY_INVALID = 0x00000110
const CKR_WRAPPED_KEY_LEN_RANGE = 0x00000112
const CKR_WRAPPING_KEY_HANDLE_INVALID = 0x00000113
const CKR_WRAPPING_KEY_SIZE_RANGE = 0x00000114
const CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115
const CKR_RANDOM_SEED_NOT_SUPPORTED = 0x00000120

const CKR_RANDOM_NO_RNG = 0x00000121

const CKR_DOMAIN_PARAMS_INVALID = 0x00000130

const CKR_CURVE_NOT_SUPPORTED = 0x00000140

const CKR_BUFFER_TOO_SMALL = 0x00000150
const CKR_SAVED_STATE_INVALID = 0x00000160
const CKR_INFORMATION_SENSITIVE = 0x00000170
const CKR_STATE_UNSAVEABLE = 0x00000180

const CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190
const CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
const CKR_MUTEX_BAD = 0x000001A0
const CKR_MUTEX_NOT_LOCKED = 0x000001A1

const CKR_NEW_PIN_MODE = 0x000001B0
const CKR_NEXT_OTP = 0x000001B1

const CKR_EXCEEDED_MAX_ITERATIONS = 0x000001B5
const CKR_FIPS_SELF_TEST_FAILED = 0x000001B6
const CKR_LIBRARY_LOAD_FAILED = 0x000001B7
const CKR_PIN_TOO_WEAK = 0x000001B8
const CKR_PUBLIC_KEY_INVALID = 0x000001B9

const CKR_FUNCTION_REJECTED = 0x00000200

const CKR_VENDOR_DEFINED = 0x80000000

func convertRVtoByte(rv CK_RV) (err error) {
	retCode := *(*uint64)(unsafe.Pointer(rv.Swigcptr()))
	if retCode == uint64(0) {
		return nil
	} else {
		err = fmt.Errorf("cloudhsm Error: errorCode=[%#x]", retCode)
	}
	return
}

func Pkcs11Initialize(path string) (err error) {
	rv := Pkcs11_initialize(path)
	err = convertRVtoByte(rv)
	return
}

func Pkcs11OpenSession(pin string) (sessionHandler uint64, err error) {
	pinPtr := SwigcptrCK_UTF8CHAR_PTR(uintptr(unsafe.Pointer(&pin)))
	session := uint64(0)
	sessionHandlePtr := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
	sessionPtr := SwigcptrCK_SESSION_HANDLE_PTR(uintptr(unsafe.Pointer(&sessionHandlePtr)))

	rv := Pkcs11_open_session(pinPtr, sessionPtr)
	err = convertRVtoByte(rv)
	if err == nil {
		sessionHandler = session
	}
	return
}

func Pkcs11FinalizeSession(session uint64) {
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

func Pkcs11Finalize() {
	Pkcs11_finalize()
	return
}

func GenerateSignature(sessionHandle uint64, privkey uint64, mechType uint64, data []byte) (signature [64]byte, err error) {
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
		sessionHandleObj,
		privkeyObj,
		mechTypeObj,
		dataObj,
		dataLenObj,
		sigObj,
		sigLenPtrObj)

	err = convertRVtoByte(rv)
	return
}

func VerifySignature(sessionHandle uint64, pubkey uint64, mechType uint64, data []byte, signature []byte) (err error) {
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
		sessionHandleObj,
		pubkeyObj,
		mechTypeObj,
		dataObj,
		dataLenObj,
		sigObj,
		sigLenObj)
	err = convertRVtoByte(rv)
	return
}

func GetPubkey(sessionHandle uint64, pubkey uint64) (pubkeyBytes []byte, err error) {
	sessionHandleObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&sessionHandle)))
	pubkeyObj := SwigcptrCK_OBJECT_HANDLE(uintptr(unsafe.Pointer(&pubkey)))

	var data [256]byte
	dataPtr := uintptr(unsafe.Pointer(&data[0]))
	dataObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&dataPtr)))

	written := uint64(256)
	dataLen := uintptr(unsafe.Pointer(&written))
	dataLenPtrObj := SwigcptrCK_ULONG_PTR(uintptr(unsafe.Pointer(&dataLen)))

	rv := Get_ec_pubkey(
		sessionHandleObj,
		pubkeyObj,
		dataObj,
		dataLenPtrObj)

	err = convertRVtoByte(rv)
	if err == nil {
		pubkeyBytes = data[:written]
	}
	return
}

func GenerateKeyPair(sessionHandle uint64, namedCurveOid []byte) (pubkey uint64, privkey uint64, err error) {
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
		sessionHandleObj,
		dataObj,
		dataLenObj,
		outPubkeyPtr,
		outPrivkeyPtr)

	err = convertRVtoByte(rv)
	if err == nil {
		pubkey = outPubkey
		privkey = outPrivkey
	}
	return
}
%}

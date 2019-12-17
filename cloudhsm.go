/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.0
 *
 * This file is not intended to be easily readable and contains a number of
 * coding conventions designed to improve portability and efficiency. Do not make
 * changes to this file unless you know what you are doing--modify the SWIG
 * interface file instead.
 * ----------------------------------------------------------------------------- */

// source: swig.i

package cloudhsm

/*
#define intgo swig_intgo
typedef void *swig_voidp;

#include <stdint.h>


typedef int intgo;
typedef unsigned int uintgo;



typedef struct { char *p; intgo n; } _gostring_;
typedef struct { void* array; intgo len; intgo cap; } _goslice_;



#cgo CPPFLAGS: -I${SRCDIR}/include/pkcs11/v2.40
#cgo LDFLAGS: -L${SRCDIR}/build/Release -L/usr/local/lib -L/usr/local/lib64 -lcloudhsmpkcs11 -ldl

typedef _gostring_ swig_type_1;
typedef _gostring_ swig_type_2;
typedef _gostring_ swig_type_3;
typedef _gostring_ swig_type_4;
typedef _gostring_ swig_type_5;
typedef _gostring_ swig_type_6;
typedef long long swig_type_7;
typedef _gostring_ swig_type_8;
typedef long long swig_type_9;
extern void _wrap_Swig_free_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1);
extern uintptr_t _wrap_Swig_malloc_cloudhsm_b0a9e67ce62a216d(swig_intgo arg1);
extern void _wrap_funcs_set_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1);
extern uintptr_t _wrap_funcs_get_cloudhsm_b0a9e67ce62a216d(void);
extern void _wrap_true_val_set_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1);
extern uintptr_t _wrap_true_val_get_cloudhsm_b0a9e67ce62a216d(void);
extern void _wrap_false_val_set_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1);
extern uintptr_t _wrap_false_val_get_cloudhsm_b0a9e67ce62a216d(void);
extern uintptr_t _wrap_pkcs11_initialize_cloudhsm_b0a9e67ce62a216d(swig_type_1 arg1);
extern uintptr_t _wrap_pkcs11_open_session_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1, uintptr_t arg2);
extern uintptr_t _wrap_pkcs11_get_slot_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1);
extern void _wrap_pkcs11_finalize_session_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1);
extern void _wrap_pkcs_arguments_pin_set_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1, swig_type_2 arg2);
extern swig_type_3 _wrap_pkcs_arguments_pin_get_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1);
extern void _wrap_pkcs_arguments_library_set_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1, swig_type_4 arg2);
extern swig_type_5 _wrap_pkcs_arguments_library_get_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1);
extern uintptr_t _wrap_new_pkcs_arguments_cloudhsm_b0a9e67ce62a216d(void);
extern void _wrap_delete_pkcs_arguments_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1);
extern swig_intgo _wrap_get_pkcs_args_cloudhsm_b0a9e67ce62a216d(swig_intgo arg1, swig_voidp arg2, uintptr_t arg3);
extern swig_intgo _wrap_bytes_to_new_hexstring_cloudhsm_b0a9e67ce62a216d(swig_type_6 arg1, swig_type_7 arg2, swig_voidp arg3);
extern swig_intgo _wrap_print_bytes_as_hex_cloudhsm_b0a9e67ce62a216d(swig_type_8 arg1, swig_type_9 arg2);
extern uintptr_t _wrap_generate_signature_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6, uintptr_t arg7);
extern uintptr_t _wrap_verify_signature_cloudhsm_b0a9e67ce62a216d(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6, uintptr_t arg7);
#undef intgo
*/
import "C"

import "unsafe"
import _ "runtime/cgo"
import "sync"


type _ unsafe.Pointer



var Swig_escape_always_false bool
var Swig_escape_val interface{}


type _swig_fnptr *byte
type _swig_memberptr *byte


type _ sync.Mutex


type swig_gostring struct { p uintptr; n int }
func swigCopyString(s string) string {
  p := *(*swig_gostring)(unsafe.Pointer(&s))
  r := string((*[0x7fffffff]byte)(unsafe.Pointer(p.p))[:p.n])
  Swig_free(p.p)
  return r
}

func Swig_free(arg1 uintptr) {
	_swig_i_0 := arg1
	C._wrap_Swig_free_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0))
}

func Swig_malloc(arg1 int) (_swig_ret uintptr) {
	var swig_r uintptr
	_swig_i_0 := arg1
	swig_r = (uintptr)(C._wrap_Swig_malloc_cloudhsm_b0a9e67ce62a216d(C.swig_intgo(_swig_i_0)))
	return swig_r
}

const MAX_SIGNATURE_LENGTH int = 256
func SetFuncs(arg1 CK_FUNCTION_LIST) {
	_swig_i_0 := arg1.Swigcptr()
	C._wrap_funcs_set_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0))
}

func GetFuncs() (_swig_ret CK_FUNCTION_LIST) {
	var swig_r CK_FUNCTION_LIST
	swig_r = (CK_FUNCTION_LIST)(SwigcptrCK_FUNCTION_LIST(C._wrap_funcs_get_cloudhsm_b0a9e67ce62a216d()))
	return swig_r
}

func SetTrue_val(arg1 CK_BBOOL) {
	_swig_i_0 := arg1.Swigcptr()
	C._wrap_true_val_set_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0))
}

func GetTrue_val() (_swig_ret CK_BBOOL) {
	var swig_r CK_BBOOL
	swig_r = (CK_BBOOL)(SwigcptrCK_BBOOL(C._wrap_true_val_get_cloudhsm_b0a9e67ce62a216d()))
	return swig_r
}

func SetFalse_val(arg1 CK_BBOOL) {
	_swig_i_0 := arg1.Swigcptr()
	C._wrap_false_val_set_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0))
}

func GetFalse_val() (_swig_ret CK_BBOOL) {
	var swig_r CK_BBOOL
	swig_r = (CK_BBOOL)(SwigcptrCK_BBOOL(C._wrap_false_val_get_cloudhsm_b0a9e67ce62a216d()))
	return swig_r
}

func Pkcs11_initialize(arg1 string) (_swig_ret CK_RV) {
	var swig_r CK_RV
	_swig_i_0 := arg1
	swig_r = (CK_RV)(SwigcptrCK_RV(C._wrap_pkcs11_initialize_cloudhsm_b0a9e67ce62a216d(*(*C.swig_type_1)(unsafe.Pointer(&_swig_i_0)))))
	if Swig_escape_always_false {
		Swig_escape_val = arg1
	}
	return swig_r
}

func Pkcs11_open_session(arg1 CK_UTF8CHAR_PTR, arg2 CK_SESSION_HANDLE_PTR) (_swig_ret CK_RV) {
	var swig_r CK_RV
	_swig_i_0 := arg1.Swigcptr()
	_swig_i_1 := arg2.Swigcptr()
	swig_r = (CK_RV)(SwigcptrCK_RV(C._wrap_pkcs11_open_session_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0), C.uintptr_t(_swig_i_1))))
	return swig_r
}

func Pkcs11_get_slot(arg1 CK_SLOT_ID) (_swig_ret CK_RV) {
	var swig_r CK_RV
	_swig_i_0 := arg1.Swigcptr()
	swig_r = (CK_RV)(SwigcptrCK_RV(C._wrap_pkcs11_get_slot_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0))))
	return swig_r
}

func Pkcs11_finalize_session(arg1 CK_SESSION_HANDLE) {
	_swig_i_0 := arg1.Swigcptr()
	C._wrap_pkcs11_finalize_session_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0))
}

type SwigcptrPkcs_arguments uintptr

func (p SwigcptrPkcs_arguments) Swigcptr() uintptr {
	return (uintptr)(p)
}

func (p SwigcptrPkcs_arguments) SwigIsPkcs_arguments() {
}

func (arg1 SwigcptrPkcs_arguments) SetPin(arg2 string) {
	_swig_i_0 := arg1
	_swig_i_1 := arg2
	C._wrap_pkcs_arguments_pin_set_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0), *(*C.swig_type_2)(unsafe.Pointer(&_swig_i_1)))
	if Swig_escape_always_false {
		Swig_escape_val = arg2
	}
}

func (arg1 SwigcptrPkcs_arguments) GetPin() (_swig_ret string) {
	var swig_r string
	_swig_i_0 := arg1
	swig_r_p := C._wrap_pkcs_arguments_pin_get_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0))
	swig_r = *(*string)(unsafe.Pointer(&swig_r_p))
	var swig_r_1 string
 swig_r_1 = swigCopyString(swig_r) 
	return swig_r_1
}

func (arg1 SwigcptrPkcs_arguments) SetLibrary(arg2 string) {
	_swig_i_0 := arg1
	_swig_i_1 := arg2
	C._wrap_pkcs_arguments_library_set_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0), *(*C.swig_type_4)(unsafe.Pointer(&_swig_i_1)))
	if Swig_escape_always_false {
		Swig_escape_val = arg2
	}
}

func (arg1 SwigcptrPkcs_arguments) GetLibrary() (_swig_ret string) {
	var swig_r string
	_swig_i_0 := arg1
	swig_r_p := C._wrap_pkcs_arguments_library_get_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0))
	swig_r = *(*string)(unsafe.Pointer(&swig_r_p))
	var swig_r_1 string
 swig_r_1 = swigCopyString(swig_r) 
	return swig_r_1
}

func NewPkcs_arguments() (_swig_ret Pkcs_arguments) {
	var swig_r Pkcs_arguments
	swig_r = (Pkcs_arguments)(SwigcptrPkcs_arguments(C._wrap_new_pkcs_arguments_cloudhsm_b0a9e67ce62a216d()))
	return swig_r
}

func DeletePkcs_arguments(arg1 Pkcs_arguments) {
	_swig_i_0 := arg1.Swigcptr()
	C._wrap_delete_pkcs_arguments_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0))
}

type Pkcs_arguments interface {
	Swigcptr() uintptr
	SwigIsPkcs_arguments()
	SetPin(arg2 string)
	GetPin() (_swig_ret string)
	SetLibrary(arg2 string)
	GetLibrary() (_swig_ret string)
}

func Get_pkcs_args(arg1 int, arg2 *string, arg3 Pkcs_arguments) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1
	_swig_i_1 := arg2
	_swig_i_2 := arg3.Swigcptr()
	swig_r = (int)(C._wrap_get_pkcs_args_cloudhsm_b0a9e67ce62a216d(C.swig_intgo(_swig_i_0), C.swig_voidp(_swig_i_1), C.uintptr_t(_swig_i_2)))
	return swig_r
}

func Bytes_to_new_hexstring(arg1 string, arg2 int64, arg3 **byte) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1
	_swig_i_1 := arg2
	_swig_i_2 := arg3
	swig_r = (int)(C._wrap_bytes_to_new_hexstring_cloudhsm_b0a9e67ce62a216d(*(*C.swig_type_6)(unsafe.Pointer(&_swig_i_0)), C.swig_type_7(_swig_i_1), C.swig_voidp(_swig_i_2)))
	if Swig_escape_always_false {
		Swig_escape_val = arg1
	}
	return swig_r
}

func Print_bytes_as_hex(arg1 string, arg2 int64) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1
	_swig_i_1 := arg2
	swig_r = (int)(C._wrap_print_bytes_as_hex_cloudhsm_b0a9e67ce62a216d(*(*C.swig_type_8)(unsafe.Pointer(&_swig_i_0)), C.swig_type_9(_swig_i_1)))
	if Swig_escape_always_false {
		Swig_escape_val = arg1
	}
	return swig_r
}

func Generate_signature(arg1 CK_SESSION_HANDLE, arg2 CK_OBJECT_HANDLE, arg3 CK_MECHANISM_TYPE, arg4 CK_BYTE_PTR, arg5 CK_ULONG, arg6 CK_BYTE_PTR, arg7 CK_ULONG_PTR) (_swig_ret CK_RV) {
	var swig_r CK_RV
	_swig_i_0 := arg1.Swigcptr()
	_swig_i_1 := arg2.Swigcptr()
	_swig_i_2 := arg3.Swigcptr()
	_swig_i_3 := arg4.Swigcptr()
	_swig_i_4 := arg5.Swigcptr()
	_swig_i_5 := arg6.Swigcptr()
	_swig_i_6 := arg7.Swigcptr()
	swig_r = (CK_RV)(SwigcptrCK_RV(C._wrap_generate_signature_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0), C.uintptr_t(_swig_i_1), C.uintptr_t(_swig_i_2), C.uintptr_t(_swig_i_3), C.uintptr_t(_swig_i_4), C.uintptr_t(_swig_i_5), C.uintptr_t(_swig_i_6))))
	return swig_r
}

func Verify_signature(arg1 CK_SESSION_HANDLE, arg2 CK_OBJECT_HANDLE, arg3 CK_MECHANISM_TYPE, arg4 CK_BYTE_PTR, arg5 CK_ULONG, arg6 CK_BYTE_PTR, arg7 CK_ULONG) (_swig_ret CK_RV) {
	var swig_r CK_RV
	_swig_i_0 := arg1.Swigcptr()
	_swig_i_1 := arg2.Swigcptr()
	_swig_i_2 := arg3.Swigcptr()
	_swig_i_3 := arg4.Swigcptr()
	_swig_i_4 := arg5.Swigcptr()
	_swig_i_5 := arg6.Swigcptr()
	_swig_i_6 := arg7.Swigcptr()
	swig_r = (CK_RV)(SwigcptrCK_RV(C._wrap_verify_signature_cloudhsm_b0a9e67ce62a216d(C.uintptr_t(_swig_i_0), C.uintptr_t(_swig_i_1), C.uintptr_t(_swig_i_2), C.uintptr_t(_swig_i_3), C.uintptr_t(_swig_i_4), C.uintptr_t(_swig_i_5), C.uintptr_t(_swig_i_6))))
	return swig_r
}


func convertRVtoByte(rv CK_RV) byte {
        return *(*byte)(unsafe.Pointer(rv.Swigcptr()))
}

func Pkcs11Initialize(path string) byte {
        rv := Pkcs11_initialize(path)
        return convertRVtoByte(rv)
}

func Pkcs11OpenSession(pin string) (sessionHandler SwigcptrCK_SESSION_HANDLE, ret byte) {
        pinPtr := SwigcptrCK_UTF8CHAR_PTR(uintptr(unsafe.Pointer(&pin)))
        session := uint64(0)
        sessionHandler = SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
        sessionPtr := SwigcptrCK_SESSION_HANDLE_PTR(uintptr(unsafe.Pointer(&sessionHandler)))

        rv := Pkcs11_open_session(pinPtr, sessionPtr)
        ret = convertRVtoByte(rv)
        return
}

func Pkcs11FinalizeSession(session CK_SESSION_HANDLE) {
        Pkcs11_finalize_session(session)
}

func GenerateSignature(sessionHandle CK_SESSION_HANDLE, privkey uint64, mechType uint64, data []byte) (signature [64]byte, ret byte) {
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
                sessionHandle,
                privkeyObj,
                mechTypeObj,
                dataObj,
                dataLenObj,
                sigObj,
                sigLenPtrObj)

        ret = convertRVtoByte(rv)
        return
}

func VerifySignature(sessionHandle CK_SESSION_HANDLE, pubkey uint64, mechType uint64, data []byte, signature []byte) byte {
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
                sessionHandle,
                pubkeyObj,
                mechTypeObj,
                dataObj,
                dataLenObj,
                sigObj,
                sigLenObj)
        return convertRVtoByte(rv)
}


type SwigcptrCK_SESSION_HANDLE_PTR uintptr
type CK_SESSION_HANDLE_PTR interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_SESSION_HANDLE_PTR) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_MECHANISM_TYPE uintptr
type CK_MECHANISM_TYPE interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_MECHANISM_TYPE) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_RV uintptr
type CK_RV interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_RV) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_UTF8CHAR_PTR uintptr
type CK_UTF8CHAR_PTR interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_UTF8CHAR_PTR) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_SLOT_ID uintptr
type CK_SLOT_ID interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_SLOT_ID) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_BBOOL uintptr
type CK_BBOOL interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_BBOOL) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_SESSION_HANDLE uintptr
type CK_SESSION_HANDLE interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_SESSION_HANDLE) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_OBJECT_HANDLE uintptr
type CK_OBJECT_HANDLE interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_OBJECT_HANDLE) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_BYTE_PTR uintptr
type CK_BYTE_PTR interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_BYTE_PTR) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_ULONG uintptr
type CK_ULONG interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_ULONG) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_FUNCTION_LIST uintptr
type CK_FUNCTION_LIST interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_FUNCTION_LIST) Swigcptr() uintptr {
	return uintptr(p)
}

type SwigcptrCK_ULONG_PTR uintptr
type CK_ULONG_PTR interface {
	Swigcptr() uintptr;
}
func (p SwigcptrCK_ULONG_PTR) Swigcptr() uintptr {
	return uintptr(p)
}


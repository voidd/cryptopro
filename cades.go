package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/reader -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lcades -lrdrsup
#include "sgn_cades.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

// SignMessageCadesBes - Sign message using simple Crypto-Pro function. Return signed message
func SignMessageCadesBes(certContext *CertContext, detached bool, data []byte) ([]byte, error) {
	dwFlag := C.uint(0)
	if detached {
		dwFlag = C.CMSG_DETACHED_FLAG
	}

	cMsg := (*C.uchar)(C.CBytes(data))
	defer C.free(unsafe.Pointer(cMsg))

	cOut := C.malloc(C.sizeof_char * 102400)
	defer C.free(unsafe.Pointer(cOut))

	size := C.int(len(data))

	errorCode := C.sign_message_cades_bes(*certContext.pCertContext, dwFlag, cMsg, (*C.char)(cOut), &size)
	out := C.GoBytes(cOut, size)

	if errorCode != 0 {
		return nil, errors.New(string(out))
	}

	return out, nil
}

func SignMessageCadesXlt(certContext *CertContext, data []byte) ([]byte, error) {
	cMsg := (*C.uchar)(C.CBytes(data))
	defer C.free(unsafe.Pointer(cMsg))

	cOut := C.malloc(C.sizeof_char * 102400)
	defer C.free(unsafe.Pointer(cOut))

	size := C.int(len(data))

	errorCode := C.sign_message_cades_xlt(*certContext.pCertContext, cMsg, (*C.char)(cOut), &size)
	out := C.GoBytes(cOut, size)

	if errorCode != 0 {
		return nil, errors.New(string(out))
	}

	return out, nil
}

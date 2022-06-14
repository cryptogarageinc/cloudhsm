package cloudhsm

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSigning(t *testing.T) {
	SetLogger(func(level LogLevel, message string) {
		if message != "" {
			fmt.Printf("[%s] %s\n", level, message)
		}
	})
	SetContextLogger(func(_ context.Context, level LogLevel, message string) {
		if message != "" {
			fmt.Printf("[%s] %s\n", level, message)
		}
	})

	// libPath := "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
	libPath := "/usr/lib/pkcs11/onepin-opensc-pkcs11.so" // for docker  // onepin-opensc-pkcs11.so  opensc-pkcs11.so
	// libPath := "/usr/lib/x86_64-linux-gnu/onepin-opensc-pkcs11.so" // for ubuntu
	pin := []byte("user:password")
	privkey := uint64(0)
	mechType := uint64(0x00001041) // ECDSA
	data := [32]byte{0x1e, 0xc5, 0x10, 0x2e, 0x93, 0xc6, 0xf2, 0xf8, 0xf7, 0x57, 0x7b, 0x40, 0x95, 0x28, 0x86, 0x08, 0xef, 0x3a, 0xb2, 0x0c, 0xe2, 0x93, 0xea, 0x1c, 0x9b, 0x14, 0xd4, 0x66, 0xcf, 0xd7, 0xdc, 0xd0}
	secp256k1 := []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a}

	err := Pkcs11Initialize(libPath)
	assert.NoError(t, err)

	sessionHandle, err := Pkcs11OpenSession(string(pin))
	assert.NoError(t, err)
	assert.NotEqual(t, uint64(0), sessionHandle)

	sessionInfo, err := Pkcs11GetSessionInfo(sessionHandle)
	assert.NoError(t, err)
	assert.NotNil(t, sessionInfo)
	if sessionInfo != nil {
		assert.NotEqual(t, uint64(0), sessionInfo.State)
	}

	signature, err := GenerateSignature(sessionHandle, privkey, mechType, data[:])
	assert.NoError(t, err)

	pubkey := uint64(0)
	err = VerifySignature(sessionHandle, pubkey, mechType, data[:], signature[:])
	assert.NoError(t, err)

	pubkeyLabel := "TestPubkeyLabel"
	privkeyLabel := "TestPrivkeyLabel"
	pubkeyHandle, privkeyHandle, err := GenerateKeyPair(sessionHandle, secp256k1, pubkeyLabel, privkeyLabel)
	assert.NoError(t, err)
	assert.NotEqual(t, uint64(0), pubkeyHandle)
	assert.NotEqual(t, uint64(0), privkeyHandle)

	pubkeyBytes, err := GetPubkey(sessionHandle, pubkey)
	assert.NoError(t, err)
	assert.NotEqual(t, 0, len(pubkeyBytes))

	ctx := context.Background()
	signature2, err := GenerateSignatureWithLabel(ctx, sessionHandle, privkeyLabel, mechType, data[:])
	assert.NoError(t, err)
	assert.NotEqual(t, 0, len(signature2))

	err = VerifySignatureWithLabel(ctx, sessionHandle, pubkeyLabel, mechType, data[:], signature[:])
	assert.NoError(t, err)

	pubkeyBytes2, err := GetPubkeyWithLabel(ctx, sessionHandle, pubkeyLabel)
	assert.NoError(t, err)
	assert.NotEqual(t, 0, len(pubkeyBytes2))

	// Pkcs11FinalizeSession(sessionHandle)

	Pkcs11CloseSession(sessionHandle)

	Pkcs11Finalize()
}

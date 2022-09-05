package cloudhsm

import (
	"context"

	"github.com/cryptogarageinc/cloudhsm/v4"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -source pkcs11.go -destination mock/pkcs11.go -package mock
//go:generate go run golang.org/x/tools/cmd/goimports@v0.1.12 -w mock/pkcs11.go

type CloudHSMPkcs11 interface {
	Initialize(ctx context.Context, path string) error
	OpenSession(ctx context.Context, pin string) (sessionHandler uint64, err error)
	GenerateKeyPair(
		ctx context.Context,
		sessionHandle uint64,
		namedCurveOid []byte,
		pubkeyLabel,
		privkeyLabel string,
	) (pubkey uint64, privkey uint64, err error)
	GetSessionInfo(session uint64) (info *SessionInfo, err error)
	FinalizeAndCloseSession(session uint64)
	CloseSession(session uint64)
	Finalize()

	GenerateSignature(
		ctx context.Context,
		sessionHandle uint64,
		privkey uint64,
		mechType uint64,
		data []byte,
	) (signature [64]byte, err error)
	VerifySignature(
		ctx context.Context,
		sessionHandle uint64,
		pubkey uint64,
		mechType uint64,
		data []byte,
		signature []byte,
	) error
	GetPubkey(
		ctx context.Context,
		sessionHandle uint64,
		pubkey uint64,
	) (pubkeyBytes []byte, err error)

	GenerateSignatureWithLabel(
		ctx context.Context,
		sessionHandle uint64,
		privkeyLabel string,
		mechType uint64,
		data []byte,
	) (signature [64]byte, err error)
	VerifySignatureWithLabel(
		ctx context.Context,
		sessionHandle uint64,
		pubkeyLabel string,
		mechType uint64,
		data []byte,
		signature []byte,
	) error
	GetPubkeyWithLabel(
		ctx context.Context,
		sessionHandle uint64,
		pubkeyLabel string,
	) (pubkeyBytes []byte, err error)
}

func NewPkcs11() *pkcs11 {
	return &pkcs11{}
}

type pkcs11 struct {
}

func (p *pkcs11) Initialize(ctx context.Context, path string) error {
	return cloudhsm.Pkcs11InitializeWithContext(ctx, path)
}

func (p *pkcs11) OpenSession(ctx context.Context, pin string) (sessionHandler uint64, err error) {
	return cloudhsm.Pkcs11OpenSessionWithContext(ctx, pin)
}

func (p *pkcs11) GenerateKeyPair(
	ctx context.Context,
	sessionHandle uint64,
	namedCurveOid []byte,
	pubkeyLabel,
	privkeyLabel string,
) (pubkey uint64, privkey uint64, err error) {
	return cloudhsm.GenerateKeyPairWithContext(ctx, sessionHandle, namedCurveOid, pubkeyLabel, privkeyLabel)
}

func (p *pkcs11) GetSessionInfo(session uint64) (info *SessionInfo, err error) {
	cInfo, err := cloudhsm.Pkcs11GetSessionInfo(session)
	if err != nil {
		return nil, err
	}
	info = newSessionInfoFromCloudHSMAPI(cInfo)
	return info, nil
}

func (p *pkcs11) FinalizeAndCloseSession(session uint64) {
	cloudhsm.Pkcs11FinalizeAndCloseSession(session)
}

func (p *pkcs11) CloseSession(session uint64) {
	cloudhsm.Pkcs11CloseSession(session)
}

func (p *pkcs11) Finalize() {
	cloudhsm.Pkcs11Finalize()
}

func (p *pkcs11) GenerateSignature(
	ctx context.Context,
	sessionHandle uint64,
	privkey uint64,
	mechType uint64,
	data []byte,
) (signature [64]byte, err error) {
	return cloudhsm.GenerateSignatureWithContext(ctx, sessionHandle, privkey, mechType, data)
}

func (p *pkcs11) VerifySignature(
	ctx context.Context,
	sessionHandle uint64,
	pubkey uint64,
	mechType uint64,
	data []byte,
	signature []byte,
) error {
	return cloudhsm.VerifySignatureWithContext(ctx, sessionHandle, pubkey, mechType, data, signature)
}

func (p *pkcs11) GetPubkey(
	ctx context.Context,
	sessionHandle uint64,
	pubkey uint64,
) (pubkeyBytes []byte, err error) {
	return cloudhsm.GetPubkeyWithContext(ctx, sessionHandle, pubkey)
}

func (p *pkcs11) GenerateSignatureWithLabel(
	ctx context.Context,
	sessionHandle uint64,
	privkeyLabel string,
	mechType uint64,
	data []byte,
) (signature [64]byte, err error) {
	return cloudhsm.GenerateSignatureWithLabel(ctx, sessionHandle, privkeyLabel, mechType, data)
}

func (p *pkcs11) VerifySignatureWithLabel(
	ctx context.Context,
	sessionHandle uint64,
	pubkeyLabel string,
	mechType uint64,
	data []byte,
	signature []byte,
) error {
	return cloudhsm.VerifySignatureWithLabel(ctx, sessionHandle, pubkeyLabel, mechType, data, signature)
}

func (p *pkcs11) GetPubkeyWithLabel(
	ctx context.Context,
	sessionHandle uint64,
	pubkeyLabel string,
) (pubkeyBytes []byte, err error) {
	return cloudhsm.GetPubkeyWithLabel(ctx, sessionHandle, pubkeyLabel)
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

func newSessionInfoFromCloudHSMAPI(info *cloudhsm.SessionInfo) *SessionInfo {
	return &SessionInfo{
		SlotID:      info.SlotID,
		State:       info.State,
		Flags:       info.Flags,
		DeviceError: info.DeviceError,
	}
}

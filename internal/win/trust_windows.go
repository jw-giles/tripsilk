//go:build windows

package win

import (
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	wintrust           = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")

	// WINTRUST_ACTION_GENERIC_VERIFY_V2
	actionGenericVerifyV2 = syscall.GUID{Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0,
		Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}
)

type wintrustFileInfo struct {
	Size         uint32
	FilePath     *uint16
	File         syscall.Handle
	KnownSubject *syscall.GUID
}

type wintrustData struct {
	Size               uint32
	PolicyCallbackData uintptr
	SIPClientData      uintptr
	UIChoice           uint32
	RevocationChecks   uint32
	UnionChoice        uint32
	File               *wintrustFileInfo
	StateAction        uint32
	StateData          syscall.Handle
	URLReference       *uint16
	ProvFlags          uint32
	UIContext          uint32
	SignatureSettings  uintptr
}

const (
	wtdUINone                = 2
	wtdRevokeNone            = 0
	wtdChoiceFile            = 1
	wtdStateActionVerify     = 1
	wtdStateActionClose      = 2
	wtdCacheOnlyURLRetrieval = 0x00001000 // never go online to check
	wtdRevocationCheckNone   = 0x00000010
)

type trustEntry struct {
	size int64
	mod  time.Time
	ok   bool
	at   time.Time
}

// trustKeep bounds how long a "signed" verdict is reused. Size and time
// are cheap to check but a program that can write the file can also put
// both back, so a swapped file is re-verified within this window.
const trustKeep = 10 * time.Minute

var (
	trustMu    sync.Mutex
	trustCache = map[string]trustEntry{}
)

// Signed reports whether the file at path carries a valid Authenticode
// signature from a certificate Windows trusts. It never goes online:
// revocation isn't checked and only cached data is used, so Tripsilk stays
// silent on the network. Results are reused until the file changes,
// and a "signed" result for at most trustKeep.
// Catalog-signed Windows files report false; callers use this only for
// apps that sign their own programs (browsers, chat apps).
func Signed(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	key := strings.ToLower(path)
	trustMu.Lock()
	if e, ok := trustCache[key]; ok && e.size == fi.Size() && e.mod.Equal(fi.ModTime()) && (!e.ok || time.Since(e.at) < trustKeep) {
		trustMu.Unlock()
		return e.ok
	}
	trustMu.Unlock()

	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	fileInfo := wintrustFileInfo{FilePath: p}
	fileInfo.Size = uint32(unsafe.Sizeof(fileInfo))
	data := wintrustData{
		UIChoice:         wtdUINone,
		RevocationChecks: wtdRevokeNone,
		UnionChoice:      wtdChoiceFile,
		File:             &fileInfo,
		StateAction:      wtdStateActionVerify,
		ProvFlags:        wtdCacheOnlyURLRetrieval | wtdRevocationCheckNone,
	}
	data.Size = uint32(unsafe.Sizeof(data))
	const invalidHandle = ^uintptr(0)
	r, _, _ := procWinVerifyTrust.Call(invalidHandle, uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	data.StateAction = wtdStateActionClose
	procWinVerifyTrust.Call(invalidHandle, uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	ok := r == 0

	trustMu.Lock()
	if len(trustCache) > 2048 {
		trustCache = map[string]trustEntry{}
	}
	trustCache[key] = trustEntry{size: fi.Size(), mod: fi.ModTime(), ok: ok, at: time.Now()}
	trustMu.Unlock()
	return ok
}

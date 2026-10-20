//go:build windows

package win

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	advapi32            = syscall.NewLazyDLL("advapi32.dll")
	procConvertSDDL     = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procConvertSidW     = advapi32.NewProc("ConvertStringSidToSidW")
	procGetSDDacl       = advapi32.NewProc("GetSecurityDescriptorDacl")
	procGetSDOwner      = advapi32.NewProc("GetSecurityDescriptorOwner")
	procGetSecurityInfo = advapi32.NewProc("GetSecurityInfo")
	procSetSecurityInfo = advapi32.NewProc("SetSecurityInfo")
	procEqualSid        = advapi32.NewProc("EqualSid")
	procCreateDirW      = kernel32.NewProc("CreateDirectoryW")
	procLocalFree       = kernel32.NewProc("LocalFree")
)

// adminOnlySDDL: owned by Administrators; SYSTEM and Administrators have
// full control; nothing inherited from the parent folder, so ordinary
// programs can't read or change what's inside.
const adminOnlySDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

const (
	seFileObject        = 1
	ownerInfo           = 0x00000001
	daclInfo            = 0x00000004
	protectedDACL       = 0x80000000
	readControl         = 0x00020000
	writeDAC            = 0x00040000
	writeOwner          = 0x00080000
	fileFlagBackup      = 0x02000000
	fileFlagOpenReparse = 0x00200000
	fileAttrReparse     = 0x00000400
	fileAttrDirectory   = 0x00000010
)

// AdminOnlyDir makes dir a real folder, owned by Administrators, that only
// Administrators and SYSTEM can open.
//
// It never sets permissions by path: a path can be swapped for a junction
// between a check and the change, pointing the change at a system folder.
// A new folder is created with its permissions in the same call. An
// existing one is opened without following links, its owner checked, and
// its permissions set through that handle. Anything else found at dir (a
// link, a file, or a folder an ordinary program made) is renamed aside and
// replaced. Setting permissions through a handle doesn't touch what's
// already inside, so planted hard links can't be used to re-permission
// other files.
func AdminOnlyDir(dir string) error {
	sd, err := adminSD()
	if err != nil {
		return err
	}
	defer procLocalFree.Call(sd)

	for attempt := 0; attempt < 3; attempt++ {
		err := createWithSD(dir, sd)
		if err == nil {
			return nil
		}
		if err != syscall.ERROR_ALREADY_EXISTS {
			return fmt.Errorf("create %s: %v", dir, err)
		}
		trusted, err := secureExisting(dir, sd)
		if err != nil {
			return err
		}
		if trusted {
			return nil
		}
		aside := fmt.Sprintf("%s.untrusted-%d", dir, time.Now().UnixNano())
		if err := os.Rename(dir, aside); err != nil {
			return fmt.Errorf("%s wasn't made by Tripsilk and couldn't be moved aside: %v", dir, err)
		}
	}
	return fmt.Errorf("%s keeps being replaced by another program", dir)
}

func adminSD() (uintptr, error) {
	sddl, _ := syscall.UTF16PtrFromString(adminOnlySDDL)
	var sd uintptr
	if r, _, e := procConvertSDDL.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&sd)), 0); r == 0 {
		return 0, fmt.Errorf("security descriptor: %v", e)
	}
	return sd, nil
}

func createWithSD(dir string, sd uintptr) error {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: sd}
	if r, _, e := procCreateDirW.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&sa))); r == 0 {
		return e
	}
	return nil
}

// secureExisting opens dir itself (not a link's target) and, if it's a real
// folder owned by Administrators or SYSTEM, applies the admin-only
// permissions through the handle. trusted is false when dir should be
// replaced instead.
func secureExisting(dir string, sd uintptr) (trusted bool, err error) {
	p, _ := syscall.UTF16PtrFromString(dir)
	h, err := syscall.CreateFile(p, readControl|writeDAC|writeOwner,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, fileFlagBackup|fileFlagOpenReparse, 0)
	if err != nil {
		return false, fmt.Errorf("open %s: %v", dir, err)
	}
	defer syscall.CloseHandle(h)
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		return false, fmt.Errorf("inspect %s: %v", dir, err)
	}
	if info.FileAttributes&fileAttrReparse != 0 || info.FileAttributes&fileAttrDirectory == 0 {
		return false, nil
	}
	var owner, osd uintptr
	if r, _, _ := procGetSecurityInfo.Call(uintptr(h), seFileObject, ownerInfo, uintptr(unsafe.Pointer(&owner)), 0, 0, 0,
		uintptr(unsafe.Pointer(&osd))); r != 0 {
		return false, fmt.Errorf("read owner of %s: %v", dir, syscall.Errno(r))
	}
	defer procLocalFree.Call(osd)
	if !isSid(owner, "BA") && !isSid(owner, "SY") {
		return false, nil
	}
	var present, defaulted int32
	var dacl, newOwner uintptr
	if r, _, e := procGetSDDacl.Call(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return false, fmt.Errorf("read DACL: %v", e)
	}
	if r, _, e := procGetSDOwner.Call(sd, uintptr(unsafe.Pointer(&newOwner)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return false, fmt.Errorf("read owner: %v", e)
	}
	if r, _, _ := procSetSecurityInfo.Call(uintptr(h), seFileObject, ownerInfo|daclInfo|protectedDACL, newOwner, 0, dacl, 0); r != 0 {
		return false, fmt.Errorf("set permissions on %s: %v", dir, syscall.Errno(r))
	}
	return true, nil
}

// isSid compares a SID with a well-known one by SDDL alias ("BA", "SY").
func isSid(sid uintptr, alias string) bool {
	a, _ := syscall.UTF16PtrFromString(alias)
	var want uintptr
	if r, _, _ := procConvertSidW.Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(&want))); r == 0 {
		return false
	}
	defer procLocalFree.Call(want)
	r, _, _ := procEqualSid.Call(sid, want)
	return r != 0
}

// AdminOwned reports whether path (a file or folder, not a link's target)
// is owned by Administrators or SYSTEM. Under C:\ProgramData any user can
// create folders and, in folders made there, files: those are owned by the
// user who made them, so this tells Tripsilk's own old files apart from
// planted ones.
func AdminOwned(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := syscall.CreateFile(p, readControl,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, fileFlagBackup|fileFlagOpenReparse, 0)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&fileAttrReparse != 0 {
		return false
	}
	var owner, osd uintptr
	if r, _, _ := procGetSecurityInfo.Call(uintptr(h), seFileObject, ownerInfo, uintptr(unsafe.Pointer(&owner)), 0, 0, 0,
		uintptr(unsafe.Pointer(&osd))); r != 0 {
		return false
	}
	defer procLocalFree.Call(osd)
	return isSid(owner, "BA") || isSid(owner, "SY")
}

//go:build windows
// +build windows

package main

import (
	"flag"
	"fmt"
	"syscall"
	"unsafe"
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type SID_IDENTIFIER_AUTHORITY struct {
	Value [6]byte
}

const (
	SE_PRIVILEGE_ENABLED        = 0x00000002
	TOKEN_ADJUST_PRIVILEGES     = 0x0020
	TOKEN_QUERY                 = 0x0008
	PROCESS_ALL_ACCESS          = 0x001F0FFF
	MEM_COMMIT                  = 0x1000
	PAGE_READONLY               = 0x02
	PAGE_READWRITE              = 0x04
	PAGE_EXECUTE_READ           = 0x20
	PAGE_EXECUTE_READWRITE      = 0x40
	TokenPrivileges             = 3
	SECURITY_BUILTIN_DOMAIN_RID = 0x20
	DOMAIN_ALIAS_RID_ADMINS     = 0x220
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procReadProcessMemory        = kernel32.NewProc("ReadProcessMemory")
	procVirtualQueryEx           = kernel32.NewProc("VirtualQueryEx")
	procLookupPrivilegeValue     = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges    = advapi32.NewProc("AdjustTokenPrivileges")
	procOpenProcessToken         = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation      = advapi32.NewProc("GetTokenInformation")
	procAllocateAndInitializeSid = advapi32.NewProc("AllocateAndInitializeSid")
	procCheckTokenMembership     = advapi32.NewProc("CheckTokenMembership")
	procFreeSid                  = advapi32.NewProc("FreeSid")
)

func main() {
	pid := flag.Int("pid", 0, "Target process ID")
	sedebug := flag.Bool("sedebug", false, "Enable SeDebugPrivilege (true/false)")
	flag.Parse()

	if *pid == 0 {
		fmt.Println("Usage: sedebug.exe -pid <PID> -sedebug=<true|false>")
		fmt.Println("\nExamples:")
		fmt.Println("  sedebug.exe -pid 1234 -sedebug=false")
		fmt.Println("  sedebug.exe -pid 2460 -sedebug=true")
		return
	}

	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println("    SeDebugPrivilege Lab: What Can It Do?")
	fmt.Println("═══════════════════════════════════════════════════\n")

	isAdmin := IsAdmin()
	fmt.Printf("[*] Running as Administrator: %v\n", isAdmin)

	if *sedebug {
		fmt.Println("[*] Enabling SeDebugPrivilege...")
		if err := EnableSeDebugPrivilege(); err != nil {
			fmt.Printf("❌ Failed to enable: %v\n", err)
			return
		}
		fmt.Println("✅ SeDebugPrivilege enabled!")
	} else {
		fmt.Println("[*] Disabling SeDebugPrivilege...")
		if err := DisableSeDebugPrivilege(); err != nil {
			fmt.Printf("❌ Failed to disable: %v\n", err)
			return
		}
		fmt.Println("✅ SeDebugPrivilege disabled!")
	}

	hasDebug := HasSeDebugPrivilege()
	fmt.Printf("[*] SeDebugPrivilege enabled: %v\n\n", hasDebug)

	fmt.Printf("[*] Opening process %d...\n", *pid)
	handle, err := OpenProcess(uint32(*pid))

	if err != nil {
		fmt.Printf("❌ FAILED: %v\n\n", err)
		fmt.Println("═══════════════════════════════════════════════════")
		fmt.Println("RESULT: Access denied")
		fmt.Println("═══════════════════════════════════════════════════")
		return
	}

	defer syscall.CloseHandle(handle)
	fmt.Printf("✅ Handle obtained: 0x%X\n\n", handle)

	fmt.Println("[*] Testing memory access...")
	if CanReadMemory(handle) {
		fmt.Println("✅ SUCCESS: Can read process memory\n")
		fmt.Println("═══════════════════════════════════════════════════")
		fmt.Println("RESULT: Full access granted")
		fmt.Println("═══════════════════════════════════════════════════")
		fmt.Println("\nYou can:")
		fmt.Println("  • Read memory")
		fmt.Println("  • Write memory")
		fmt.Println("  • Inject code")
		fmt.Println("  • Terminate process")
	} else {
		fmt.Println("❌ FAILED: Cannot read memory\n")
		fmt.Println("═══════════════════════════════════════════════════")
		fmt.Println("RESULT: Handle is restricted")
		fmt.Println("═══════════════════════════════════════════════════")
		fmt.Println("\nThis process has additional kernel protections.")
		fmt.Println("SeDebugPrivilege alone is not enough.")
	}

	fmt.Println()
}

func OpenProcess(pid uint32) (syscall.Handle, error) {
	handle, _, _ := procOpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return 0, fmt.Errorf("access denied")
	}
	return syscall.Handle(handle), nil
}

func CanReadMemory(handle syscall.Handle) bool {
	addr := FindValidMemory(handle)
	if addr == 0 {
		return false
	}

	var buffer [8]byte
	var bytesRead uintptr

	ret, _, _ := procReadProcessMemory.Call(
		uintptr(handle),
		addr,
		uintptr(unsafe.Pointer(&buffer[0])),
		8,
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	return ret != 0 && bytesRead > 0
}

func FindValidMemory(handle syscall.Handle) uintptr {
	var mbi MEMORY_BASIC_INFORMATION
	var address uintptr = 0

	for address < 0x7FFFFFFF {
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(handle),
			address,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 {
			break
		}

		if mbi.State == MEM_COMMIT &&
			(mbi.Protect == PAGE_READONLY ||
				mbi.Protect == PAGE_READWRITE ||
				mbi.Protect == PAGE_EXECUTE_READ ||
				mbi.Protect == PAGE_EXECUTE_READWRITE) {
			return mbi.BaseAddress
		}

		address = mbi.BaseAddress + mbi.RegionSize
	}
	return 0
}

func IsAdmin() bool {
	var adminSid *syscall.SID
	var ntAuthority = SID_IDENTIFIER_AUTHORITY{
		Value: [6]byte{0, 0, 0, 0, 0, 5},
	}

	ret, _, _ := procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&ntAuthority)),
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&adminSid)),
	)

	if ret == 0 {
		return false
	}
	defer procFreeSid.Call(uintptr(unsafe.Pointer(adminSid)))

	var isMember int32
	ret, _, _ = procCheckTokenMembership.Call(
		0,
		uintptr(unsafe.Pointer(adminSid)),
		uintptr(unsafe.Pointer(&isMember)),
	)

	if ret == 0 {
		return false
	}

	return isMember != 0
}

func HasSeDebugPrivilege() bool {
	var token syscall.Handle
	proc, _ := syscall.GetCurrentProcess()
	ret, _, _ := procOpenProcessToken.Call(
		uintptr(proc),
		TOKEN_QUERY,
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return false
	}
	defer syscall.CloseHandle(token)

	var luid LUID
	privName, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	ret, _, _ = procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(privName)), uintptr(unsafe.Pointer(&luid)))
	if ret == 0 {
		return false
	}

	var returnLength uint32
	procGetTokenInformation.Call(uintptr(token), TokenPrivileges, 0, 0, uintptr(unsafe.Pointer(&returnLength)))

	privBuffer := make([]byte, returnLength)
	ret, _, _ = procGetTokenInformation.Call(
		uintptr(token),
		TokenPrivileges,
		uintptr(unsafe.Pointer(&privBuffer[0])),
		uintptr(returnLength),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret == 0 {
		return false
	}

	tokenPrivs := (*TOKEN_PRIVILEGES)(unsafe.Pointer(&privBuffer[0]))
	privArray := (*[1000]LUID_AND_ATTRIBUTES)(unsafe.Pointer(&tokenPrivs.Privileges[0]))

	for i := uint32(0); i < tokenPrivs.PrivilegeCount; i++ {
		if privArray[i].Luid.LowPart == luid.LowPart && privArray[i].Luid.HighPart == luid.HighPart {
			return (privArray[i].Attributes & SE_PRIVILEGE_ENABLED) != 0
		}
	}
	return false
}

func EnableSeDebugPrivilege() error {
	var token syscall.Handle
	proc, _ := syscall.GetCurrentProcess()
	ret, _, _ := procOpenProcessToken.Call(
		uintptr(proc),
		TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return fmt.Errorf("failed to open token")
	}
	defer syscall.CloseHandle(token)

	var luid LUID
	privName, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	ret, _, _ = procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(privName)), uintptr(unsafe.Pointer(&luid)))
	if ret == 0 {
		return fmt.Errorf("privilege not available")
	}

	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{Luid: luid, Attributes: SE_PRIVILEGE_ENABLED},
		},
	}

	ret, _, _ = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0, 0, 0,
	)
	if ret == 0 {
		return fmt.Errorf("failed to adjust privileges")
	}

	return nil
}

func DisableSeDebugPrivilege() error {
	var token syscall.Handle
	proc, _ := syscall.GetCurrentProcess()
	ret, _, _ := procOpenProcessToken.Call(
		uintptr(proc),
		TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return fmt.Errorf("failed to open token")
	}
	defer syscall.CloseHandle(token)

	var luid LUID
	privName, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	ret, _, _ = procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(privName)), uintptr(unsafe.Pointer(&luid)))
	if ret == 0 {
		return fmt.Errorf("privilege not available")
	}

	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{Luid: luid, Attributes: 0},
		},
	}

	ret, _, _ = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0, 0, 0,
	)
	if ret == 0 {
		return fmt.Errorf("failed to adjust privileges")
	}

	return nil
}

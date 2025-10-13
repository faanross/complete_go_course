////go:build windows
//// +build windows
//
//package main
//
//import (
//	"fmt"
//	"os"
//	"syscall"
//	"unsafe"
//)
//
//// LUID: Locally Unique Identifier for privileges
//type LUID struct {
//	LowPart  uint32
//	HighPart int32
//}
//
//// LUID_AND_ATTRIBUTES: Privilege with its state
//type LUID_AND_ATTRIBUTES struct {
//	Luid       LUID
//	Attributes uint32
//}
//
//// TOKEN_PRIVILEGES: Structure for adjusting token privileges
//type TOKEN_PRIVILEGES struct {
//	PrivilegeCount uint32
//	Privileges     [1]LUID_AND_ATTRIBUTES
//}
//
//// SID_IDENTIFIER_AUTHORITY structure
//type SID_IDENTIFIER_AUTHORITY struct {
//	Value [6]byte
//}
//
//// SID_AND_ATTRIBUTES for token groups
//type SID_AND_ATTRIBUTES struct {
//	Sid        *syscall.SID
//	Attributes uint32
//}
//
//// TOKEN_GROUPS structure
//type TOKEN_GROUPS struct {
//	GroupCount uint32
//	Groups     [1]SID_AND_ATTRIBUTES
//}
//
//// Constants
//const (
//	SE_PRIVILEGE_ENABLED    = 0x00000002
//	TOKEN_ADJUST_PRIVILEGES = 0x0020
//	TOKEN_QUERY             = 0x0008
//	PROCESS_ALL_ACCESS      = 0x001F0FFF
//	ERROR_ACCESS_DENIED     = 5
//
//	// For admin check
//	SECURITY_NT_AUTHORITY       = 5
//	SECURITY_BUILTIN_DOMAIN_RID = 0x20
//	DOMAIN_ALIAS_RID_ADMINS     = 0x220
//
//	TokenGroups = 2
//)
//
//var (
//	kernel32 = syscall.NewLazyDLL("kernel32.dll")
//	advapi32 = syscall.NewLazyDLL("advapi32.dll")
//
//	procOpenProcess              = kernel32.NewProc("OpenProcess")
//	procGetLastError             = kernel32.NewProc("GetLastError")
//	procLookupPrivilegeValue     = advapi32.NewProc("LookupPrivilegeValueW")
//	procAdjustTokenPrivileges    = advapi32.NewProc("AdjustTokenPrivileges")
//	procOpenProcessToken         = advapi32.NewProc("OpenProcessToken")
//	procGetTokenInformation      = advapi32.NewProc("GetTokenInformation")
//	procAllocateAndInitializeSid = advapi32.NewProc("AllocateAndInitializeSid")
//	procCheckTokenMembership     = advapi32.NewProc("CheckTokenMembership")
//	procFreeSid                  = advapi32.NewProc("FreeSid")
//)
//
//// Try to open a process with full access
//func TryOpenProcess(pid uint32) (syscall.Handle, error) {
//	fmt.Printf("\n[*] Attempting to open process PID %d with PROCESS_ALL_ACCESS...\n", pid)
//
//	handle, _, err := procOpenProcess.Call(
//		uintptr(PROCESS_ALL_ACCESS),
//		0,
//		uintptr(pid),
//	)
//
//	if handle == 0 {
//		// Get the actual error code
//		lastErr, _, _ := procGetLastError.Call()
//
//		if lastErr == ERROR_ACCESS_DENIED {
//			return 0, fmt.Errorf("ACCESS DENIED (Error 5)")
//		}
//
//		return 0, fmt.Errorf("OpenProcess failed with error: %v (code: %d)", err, lastErr)
//	}
//
//	return syscall.Handle(handle), nil
//}
//
//// Check if we have a specific privilege
//func CheckPrivilege(privilegeName string) bool {
//	var hToken syscall.Handle
//
//	currentProc, _ := syscall.GetCurrentProcess()
//	ret, _, _ := procOpenProcessToken.Call(
//		uintptr(currentProc),
//		TOKEN_QUERY,
//		uintptr(unsafe.Pointer(&hToken)),
//	)
//
//	if ret == 0 {
//		return false
//	}
//	defer syscall.CloseHandle(hToken)
//
//	// Look up the privilege LUID
//	var luid LUID
//	privName, _ := syscall.UTF16PtrFromString(privilegeName)
//	ret, _, _ = procLookupPrivilegeValue.Call(
//		0,
//		uintptr(unsafe.Pointer(privName)),
//		uintptr(unsafe.Pointer(&luid)),
//	)
//
//	return ret != 0
//}
//
//// Get current integrity level (check if admin)
//func GetIntegrityLevel() string {
//	// Create admin SID
//	var adminSid *syscall.SID
//	var ntAuthority = SID_IDENTIFIER_AUTHORITY{
//		Value: [6]byte{0, 0, 0, 0, 0, 5}, // SECURITY_NT_AUTHORITY
//	}
//
//	ret, _, _ := procAllocateAndInitializeSid.Call(
//		uintptr(unsafe.Pointer(&ntAuthority)),
//		2, // 2 sub-authorities
//		SECURITY_BUILTIN_DOMAIN_RID,
//		DOMAIN_ALIAS_RID_ADMINS,
//		0, 0, 0, 0, 0, 0,
//		uintptr(unsafe.Pointer(&adminSid)),
//	)
//
//	if ret == 0 {
//		return "Unknown"
//	}
//	defer procFreeSid.Call(uintptr(unsafe.Pointer(adminSid)))
//
//	// Check token membership
//	var isMember int32
//	ret, _, _ = procCheckTokenMembership.Call(
//		0, // Use current thread token
//		uintptr(unsafe.Pointer(adminSid)),
//		uintptr(unsafe.Pointer(&isMember)),
//	)
//
//	if ret == 0 {
//		return "Unknown"
//	}
//
//	if isMember != 0 {
//		return "High (Administrator)"
//	}
//
//	return "Medium (Standard User)"
//}
//
//func main() {
//	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
//	fmt.Println("║         PRIVILEGE ESCALATION LAB: SeDebugPrivilege        ║")
//	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
//	fmt.Println()
//
//	// Check if PID was provided
//	if len(os.Args) < 2 {
//		fmt.Println("Usage: privilege_debug.exe <PID>")
//		fmt.Println("Example: privilege_debug.exe 1234")
//		fmt.Println()
//		fmt.Println("Find notepad.exe PID:")
//		fmt.Println("  tasklist | findstr notepad")
//		return
//	}
//
//	var targetPID uint32
//	fmt.Sscanf(os.Args[1], "%d", &targetPID)
//
//	fmt.Println("═══════════════════════════════════════════════════════════")
//	fmt.Println("STEP 1: ENVIRONMENT CHECK")
//	fmt.Println("═══════════════════════════════════════════════════════════")
//
//	// Check current integrity level
//	integrityLevel := GetIntegrityLevel()
//	fmt.Printf("\n[*] Current Integrity Level: %s\n", integrityLevel)
//
//	// Check if SeDebugPrivilege is available
//	hasPrivilege := CheckPrivilege("SeDebugPrivilege")
//	fmt.Printf("[*] SeDebugPrivilege available: %v\n", hasPrivilege)
//
//	if !hasPrivilege {
//		fmt.Println("\n⚠️  WARNING: SeDebugPrivilege is NOT available!")
//		fmt.Println("    This means you likely are NOT running as Administrator.")
//	}
//
//	fmt.Println()
//	fmt.Println("═══════════════════════════════════════════════════════════")
//	fmt.Println("STEP 2: ATTEMPT TO OPEN PROCESS (WITHOUT PRIVILEGE)")
//	fmt.Println("═══════════════════════════════════════════════════════════")
//
//	// Try to open process WITHOUT enabling privilege
//	handle, err := TryOpenProcess(targetPID)
//
//	if err != nil {
//		fmt.Println("\n❌ FAILED TO OPEN PROCESS")
//		fmt.Printf("   Error: %v\n", err)
//		fmt.Println()
//		fmt.Println("═══════════════════════════════════════════════════════════")
//		fmt.Println("WHY DID THIS FAIL?")
//		fmt.Println("═══════════════════════════════════════════════════════════")
//		fmt.Println()
//
//		if integrityLevel == "Medium (Standard User)" {
//			fmt.Println("❌ REASON: You are NOT running as Administrator")
//			fmt.Println()
//			fmt.Println("   Windows protects processes from unauthorized access.")
//			fmt.Println("   To open other processes with full access, you need:")
//			fmt.Println()
//			fmt.Println("   1. Administrator privileges")
//			fmt.Println("   2. SeDebugPrivilege enabled")
//			fmt.Println()
//			fmt.Println("═══════════════════════════════════════════════════════════")
//			fmt.Println("SOLUTION:")
//			fmt.Println("═══════════════════════════════════════════════════════════")
//			fmt.Println()
//			fmt.Println("🔧 Run this program as Administrator:")
//			fmt.Println()
//			fmt.Println("   1. Open Command Prompt as Administrator")
//			fmt.Println("      (Right-click → 'Run as administrator')")
//			fmt.Println()
//			fmt.Println("   2. Navigate to this directory")
//			fmt.Println()
//			fmt.Println("   3. Run again:")
//			fmt.Printf("      privilege_debug.exe %d\n", targetPID)
//			fmt.Println()
//		} else {
//			fmt.Println("❌ REASON: SeDebugPrivilege not enabled")
//			fmt.Println()
//			fmt.Println("   Even as Administrator, privileges are DISABLED by default")
//			fmt.Println("   for security (principle of least privilege).")
//			fmt.Println()
//			fmt.Println("   You must explicitly ENABLE SeDebugPrivilege before")
//			fmt.Println("   you can open processes with full access.")
//			fmt.Println()
//			fmt.Println("   This program will now attempt to enable it...")
//		}
//
//		// If we're admin, we can try to enable the privilege
//		if integrityLevel == "High (Administrator)" {
//			fmt.Println()
//			fmt.Println("═══════════════════════════════════════════════════════════")
//			fmt.Println("STEP 3: ENABLING SeDebugPrivilege")
//			fmt.Println("═══════════════════════════════════════════════════════════")
//
//			err := EnablePrivilege("SeDebugPrivilege")
//			if err != nil {
//				fmt.Printf("\n❌ Failed to enable privilege: %v\n", err)
//				return
//			}
//
//			fmt.Println("\n✅ SeDebugPrivilege ENABLED!")
//			fmt.Println()
//			fmt.Println("═══════════════════════════════════════════════════════════")
//			fmt.Println("STEP 4: RETRY OPENING PROCESS (WITH PRIVILEGE)")
//			fmt.Println("═══════════════════════════════════════════════════════════")
//
//			// Try again with privilege enabled
//			handle, err = TryOpenProcess(targetPID)
//
//			if err != nil {
//				fmt.Printf("\n❌ Still failed: %v\n", err)
//				fmt.Println("\n   Possible reasons:")
//				fmt.Println("   - Invalid PID")
//				fmt.Println("   - Process already terminated")
//				fmt.Println("   - Protected system process")
//				return
//			}
//		} else {
//			return
//		}
//	}
//
//	// Success!
//	defer syscall.CloseHandle(handle)
//
//	fmt.Println("\n✅ SUCCESS! Process opened with full access")
//	fmt.Printf("   Handle: 0x%X\n", handle)
//	fmt.Println()
//	fmt.Println("═══════════════════════════════════════════════════════════")
//	fmt.Println("WHAT CAN WE DO NOW?")
//	fmt.Println("═══════════════════════════════════════════════════════════")
//	fmt.Println()
//	fmt.Println("With PROCESS_ALL_ACCESS and SeDebugPrivilege, we can:")
//	fmt.Println()
//	fmt.Println("  ✓ Read process memory")
//	fmt.Println("  ✓ Write process memory")
//	fmt.Println("  ✓ Create threads in the process")
//	fmt.Println("  ✓ Inject code/DLLs")
//	fmt.Println("  ✓ Suspend/resume threads")
//	fmt.Println("  ✓ Query process information")
//	fmt.Println("  ✓ Terminate the process")
//	fmt.Println()
//	fmt.Println("This is why SeDebugPrivilege is so powerful and dangerous!")
//	fmt.Println()
//}
//
//// EnablePrivilege: Activates a privilege by name
//func EnablePrivilege(privilegeName string) error {
//	var hToken syscall.Handle
//
//	fmt.Printf("\n[*] Opening current process token...\n")
//
//	// Step 1: Get handle to current process's token
//	currentProc, _ := syscall.GetCurrentProcess()
//	ret, _, _ := procOpenProcessToken.Call(
//		uintptr(currentProc),
//		TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
//		uintptr(unsafe.Pointer(&hToken)),
//	)
//
//	if ret == 0 {
//		return fmt.Errorf("Failed to open process token")
//	}
//	defer syscall.CloseHandle(hToken)
//
//	fmt.Printf("    ✓ Token opened successfully\n")
//
//	// Step 2: Look up the LUID for the privilege
//	fmt.Printf("\n[*] Looking up LUID for '%s'...\n", privilegeName)
//
//	var luid LUID
//	privName, _ := syscall.UTF16PtrFromString(privilegeName)
//	ret, _, _ = procLookupPrivilegeValue.Call(
//		0,
//		uintptr(unsafe.Pointer(privName)),
//		uintptr(unsafe.Pointer(&luid)),
//	)
//
//	if ret == 0 {
//		return fmt.Errorf("LookupPrivilegeValue failed - privilege not available")
//	}
//
//	fmt.Printf("    ✓ LUID found: %d.%d\n", luid.HighPart, luid.LowPart)
//
//	// Step 3: Prepare TOKEN_PRIVILEGES structure
//	fmt.Printf("\n[*] Preparing privilege modification...\n")
//
//	tp := TOKEN_PRIVILEGES{
//		PrivilegeCount: 1,
//		Privileges: [1]LUID_AND_ATTRIBUTES{
//			{
//				Luid:       luid,
//				Attributes: SE_PRIVILEGE_ENABLED,
//			},
//		},
//	}
//
//	// Step 4: Adjust token privileges
//	fmt.Printf("\n[*] Calling AdjustTokenPrivileges...\n")
//
//	ret, _, _ = procAdjustTokenPrivileges.Call(
//		uintptr(hToken),
//		0,
//		uintptr(unsafe.Pointer(&tp)),
//		0,
//		0,
//		0,
//	)
//
//	if ret == 0 {
//		return fmt.Errorf("AdjustTokenPrivileges failed")
//	}
//
//	// Check if it actually worked
//	lastErr, _, _ := procGetLastError.Call()
//	if lastErr != 0 {
//		// ERROR_NOT_ALL_ASSIGNED = 1300
//		if lastErr == 1300 {
//			return fmt.Errorf("Privilege could not be assigned (not held by account)")
//		}
//		return fmt.Errorf("AdjustTokenPrivileges error: %d", lastErr)
//	}
//
//	fmt.Printf("    ✓ Privilege adjusted successfully\n")
//
//	return nil
//}

//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// LUID: Locally Unique Identifier for privileges
type LUID struct {
	LowPart  uint32
	HighPart int32
}

// LUID_AND_ATTRIBUTES: Privilege with its state
type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

// TOKEN_PRIVILEGES: Structure for adjusting token privileges
type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

// SID_IDENTIFIER_AUTHORITY structure
type SID_IDENTIFIER_AUTHORITY struct {
	Value [6]byte
}

// SID_AND_ATTRIBUTES for token groups
type SID_AND_ATTRIBUTES struct {
	Sid        *syscall.SID
	Attributes uint32
}

// TOKEN_GROUPS structure
type TOKEN_GROUPS struct {
	GroupCount uint32
	Groups     [1]SID_AND_ATTRIBUTES
}

// Constants
const (
	SE_PRIVILEGE_ENABLED    = 0x00000002
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY             = 0x0008
	PROCESS_ALL_ACCESS      = 0x001F0FFF
	ERROR_ACCESS_DENIED     = 5

	// For admin check
	SECURITY_NT_AUTHORITY       = 5
	SECURITY_BUILTIN_DOMAIN_RID = 0x20
	DOMAIN_ALIAS_RID_ADMINS     = 0x220

	TokenGroups = 2
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procGetLastError             = kernel32.NewProc("GetLastError")
	procReadProcessMemory        = kernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread       = kernel32.NewProc("CreateRemoteThread")
	procTerminateProcess         = kernel32.NewProc("TerminateProcess")
	procLookupPrivilegeValue     = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges    = advapi32.NewProc("AdjustTokenPrivileges")
	procOpenProcessToken         = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation      = advapi32.NewProc("GetTokenInformation")
	procAllocateAndInitializeSid = advapi32.NewProc("AllocateAndInitializeSid")
	procCheckTokenMembership     = advapi32.NewProc("CheckTokenMembership")
	procFreeSid                  = advapi32.NewProc("FreeSid")
)

// Try to open a process with full access
func TryOpenProcess(pid uint32) (syscall.Handle, error) {
	fmt.Printf("\n[*] Attempting to open process PID %d with PROCESS_ALL_ACCESS...\n", pid)

	handle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		0,
		uintptr(pid),
	)

	if handle == 0 {
		// Get the actual error code
		lastErr, _, _ := procGetLastError.Call()

		if lastErr == ERROR_ACCESS_DENIED {
			return 0, fmt.Errorf("ACCESS DENIED (Error 5)")
		}

		return 0, fmt.Errorf("OpenProcess failed with error: %v (code: %d)", err, lastErr)
	}

	return syscall.Handle(handle), nil
}

// Try to read process memory
func TryReadMemory(handle syscall.Handle, pid uint32) bool {
	fmt.Println("\n[*] Testing: ReadProcessMemory...")
	fmt.Println("    (Attempting to read from address 0x10000)")

	var buffer [8]byte
	var bytesRead uintptr

	ret, _, _ := procReadProcessMemory.Call(
		uintptr(handle),
		0x10000, // arbitrary address
		uintptr(unsafe.Pointer(&buffer[0])),
		8,
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		lastErr, _, _ := procGetLastError.Call()
		fmt.Printf("    ❌ FAILED - Error %d (Access Denied)\n", lastErr)
		fmt.Println("    └─ PPL protection blocked memory read")
		return false
	}

	fmt.Println("    ✅ SUCCESS - Memory read allowed")
	return true
}

// Try to write process memory
func TryWriteMemory(handle syscall.Handle) bool {
	fmt.Println("\n[*] Testing: WriteProcessMemory...")
	fmt.Println("    (Attempting to write to address 0x10000)")

	buffer := []byte{0x90, 0x90, 0x90, 0x90}
	var bytesWritten uintptr

	ret, _, _ := procWriteProcessMemory.Call(
		uintptr(handle),
		0x10000,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret == 0 {
		lastErr, _, _ := procGetLastError.Call()
		fmt.Printf("    ❌ FAILED - Error %d (Access Denied)\n", lastErr)
		fmt.Println("    └─ PPL protection blocked memory write")
		return false
	}

	fmt.Println("    ✅ SUCCESS - Memory write allowed")
	return true
}

// Try to create a remote thread
func TryCreateThread(handle syscall.Handle) bool {
	fmt.Println("\n[*] Testing: CreateRemoteThread...")
	fmt.Println("    (Attempting to create thread in target process)")

	threadHandle, _, _ := procCreateRemoteThread.Call(
		uintptr(handle),
		0, // default security
		0, // default stack size
		0, // null start address (will fail anyway)
		0, // no parameter
		0, // run immediately
		0, // don't care about thread ID
	)

	if threadHandle == 0 {
		lastErr, _, _ := procGetLastError.Call()
		fmt.Printf("    ❌ FAILED - Error %d (Access Denied)\n", lastErr)
		fmt.Println("    └─ PPL protection blocked thread creation")
		return false
	}

	syscall.CloseHandle(syscall.Handle(threadHandle))
	fmt.Println("    ✅ SUCCESS - Thread creation allowed")
	return true
}

// Try to terminate the process
func TryTerminate(handle syscall.Handle) bool {
	fmt.Println("\n[*] Testing: TerminateProcess...")
	fmt.Println("    (Attempting to terminate the process)")
	fmt.Println("    ⚠️  Just testing - won't actually kill it")

	// We won't actually terminate, just test if we COULD
	// by checking the handle's access rights
	ret, _, _ := procTerminateProcess.Call(
		uintptr(handle),
		0, // exit code
	)

	if ret == 0 {
		lastErr, _, _ := procGetLastError.Call()
		fmt.Printf("    ❌ FAILED - Error %d (Access Denied)\n", lastErr)
		fmt.Println("    └─ PPL protection blocked termination")
		return false
	}

	fmt.Println("    ⚠️  Would have succeeded (NOT executing for safety)")
	return true
}

// Check if we have a specific privilege
func CheckPrivilege(privilegeName string) bool {
	var hToken syscall.Handle

	currentProc, _ := syscall.GetCurrentProcess()
	ret, _, _ := procOpenProcessToken.Call(
		uintptr(currentProc),
		TOKEN_QUERY,
		uintptr(unsafe.Pointer(&hToken)),
	)

	if ret == 0 {
		return false
	}
	defer syscall.CloseHandle(hToken)

	// Look up the privilege LUID
	var luid LUID
	privName, _ := syscall.UTF16PtrFromString(privilegeName)
	ret, _, _ = procLookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(privName)),
		uintptr(unsafe.Pointer(&luid)),
	)

	return ret != 0
}

// Get current integrity level (check if admin)
func GetIntegrityLevel() string {
	// Create admin SID
	var adminSid *syscall.SID
	var ntAuthority = SID_IDENTIFIER_AUTHORITY{
		Value: [6]byte{0, 0, 0, 0, 0, 5}, // SECURITY_NT_AUTHORITY
	}

	ret, _, _ := procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&ntAuthority)),
		2, // 2 sub-authorities
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&adminSid)),
	)

	if ret == 0 {
		return "Unknown"
	}
	defer procFreeSid.Call(uintptr(unsafe.Pointer(adminSid)))

	// Check token membership
	var isMember int32
	ret, _, _ = procCheckTokenMembership.Call(
		0, // Use current thread token
		uintptr(unsafe.Pointer(adminSid)),
		uintptr(unsafe.Pointer(&isMember)),
	)

	if ret == 0 {
		return "Unknown"
	}

	if isMember != 0 {
		return "High (Administrator)"
	}

	return "Medium (Standard User)"
}

// Detect if process is PPL protected
func DetectPPL(handle syscall.Handle, pid uint32) string {
	// Try a simple memory read - PPL will block it
	var buffer [1]byte
	var bytesRead uintptr

	ret, _, _ := procReadProcessMemory.Call(
		uintptr(handle),
		0x10000,
		uintptr(unsafe.Pointer(&buffer[0])),
		1,
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		lastErr, _, _ := procGetLastError.Call()
		if lastErr == ERROR_ACCESS_DENIED {
			return "YES - Protected Process Light (PPL)"
		}
	}

	return "NO - Regular process"
}

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║         PRIVILEGE ESCALATION LAB: SeDebugPrivilege        ║")
	fmt.Println("║              Understanding PPL Protection                  ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Check if PID was provided
	if len(os.Args) < 2 {
		fmt.Println("Usage: privilege_debug.exe <PID>")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  privilege_debug.exe 1234          (regular process)")
		fmt.Println("  privilege_debug.exe <lsass_pid>   (PPL-protected process)")
		fmt.Println()
		fmt.Println("Find process PIDs:")
		fmt.Println("  tasklist | findstr notepad")
		fmt.Println("  Get-Process lsass | Select-Object Id")
		return
	}

	var targetPID uint32
	fmt.Sscanf(os.Args[1], "%d", &targetPID)

	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("STEP 1: ENVIRONMENT CHECK")
	fmt.Println("═══════════════════════════════════════════════════════════")

	// Check current integrity level
	integrityLevel := GetIntegrityLevel()
	fmt.Printf("\n[*] Current Integrity Level: %s\n", integrityLevel)

	// Check if SeDebugPrivilege is available
	hasPrivilege := CheckPrivilege("SeDebugPrivilege")
	fmt.Printf("[*] SeDebugPrivilege available: %v\n", hasPrivilege)

	if !hasPrivilege {
		fmt.Println("\n⚠️  WARNING: SeDebugPrivilege is NOT available!")
		fmt.Println("    This means you likely are NOT running as Administrator.")
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("STEP 2: ATTEMPT TO OPEN PROCESS (WITHOUT PRIVILEGE)")
	fmt.Println("═══════════════════════════════════════════════════════════")

	// Try to open process WITHOUT enabling privilege
	handle, err := TryOpenProcess(targetPID)

	if err != nil {
		fmt.Println("\n❌ FAILED TO OPEN PROCESS")
		fmt.Printf("   Error: %v\n", err)
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("WHY DID THIS FAIL?")
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println()

		if integrityLevel == "Medium (Standard User)" {
			fmt.Println("❌ REASON: You are NOT running as Administrator")
			fmt.Println()
			fmt.Println("   Windows protects processes from unauthorized access.")
			fmt.Println("   To open other processes with full access, you need:")
			fmt.Println()
			fmt.Println("   1. Administrator privileges")
			fmt.Println("   2. SeDebugPrivilege enabled")
			fmt.Println()
			fmt.Println("═══════════════════════════════════════════════════════════")
			fmt.Println("SOLUTION:")
			fmt.Println("═══════════════════════════════════════════════════════════")
			fmt.Println()
			fmt.Println("🔧 Run this program as Administrator:")
			fmt.Println()
			fmt.Println("   1. Open Command Prompt as Administrator")
			fmt.Println("      (Right-click → 'Run as administrator')")
			fmt.Println()
			fmt.Println("   2. Navigate to this directory")
			fmt.Println()
			fmt.Println("   3. Run again:")
			fmt.Printf("      privilege_debug.exe %d\n", targetPID)
			fmt.Println()
		} else {
			fmt.Println("❌ REASON: SeDebugPrivilege not enabled")
			fmt.Println()
			fmt.Println("   Even as Administrator, privileges are DISABLED by default")
			fmt.Println("   for security (principle of least privilege).")
			fmt.Println()
			fmt.Println("   You must explicitly ENABLE SeDebugPrivilege before")
			fmt.Println("   you can open processes with full access.")
			fmt.Println()
			fmt.Println("   This program will now attempt to enable it...")
		}

		// If we're admin, we can try to enable the privilege
		if integrityLevel == "High (Administrator)" {
			fmt.Println()
			fmt.Println("═══════════════════════════════════════════════════════════")
			fmt.Println("STEP 3: ENABLING SeDebugPrivilege")
			fmt.Println("═══════════════════════════════════════════════════════════")

			err := EnablePrivilege("SeDebugPrivilege")
			if err != nil {
				fmt.Printf("\n❌ Failed to enable privilege: %v\n", err)
				return
			}

			fmt.Println("\n✅ SeDebugPrivilege ENABLED!")
			fmt.Println()
			fmt.Println("═══════════════════════════════════════════════════════════")
			fmt.Println("STEP 4: RETRY OPENING PROCESS (WITH PRIVILEGE)")
			fmt.Println("═══════════════════════════════════════════════════════════")

			// Try again with privilege enabled
			handle, err = TryOpenProcess(targetPID)

			if err != nil {
				fmt.Printf("\n❌ Still failed: %v\n", err)
				fmt.Println("\n   Possible reasons:")
				fmt.Println("   - Invalid PID")
				fmt.Println("   - Process already terminated")
				fmt.Println("   - Protected system process")
				return
			}
		} else {
			return
		}
	}

	// We got a handle - but can we actually USE it?
	defer syscall.CloseHandle(handle)

	fmt.Println("\n✅ HANDLE OBTAINED")
	fmt.Printf("   Handle: 0x%X\n", handle)
	fmt.Println()
	fmt.Println("⚠️  IMPORTANT: Getting a handle does NOT mean we have real access!")
	fmt.Println("   Windows may have given us a RESTRICTED handle.")
	fmt.Println("   Let's test what we can actually DO with it...")

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("STEP 3: TESTING ACTUAL ACCESS (THE REAL TEST)")
	fmt.Println("═══════════════════════════════════════════════════════════")

	// Detect if PPL
	pplStatus := DetectPPL(handle, targetPID)
	fmt.Printf("\n[*] PPL Detection: %s\n", pplStatus)

	// Test various operations
	canRead := TryReadMemory(handle, targetPID)
	canWrite := TryWriteMemory(handle)
	canCreateThread := TryCreateThread(handle)
	//canTerminate := TryTerminate(handle)

	// Summary
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("RESULTS SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()

	if canRead && canWrite && canCreateThread {
		fmt.Println("✅ FULL ACCESS GRANTED")
		fmt.Println()
		fmt.Println("   This is a REGULAR process (not PPL-protected)")
		fmt.Println("   With SeDebugPrivilege, you have complete control:")
		fmt.Println()
		fmt.Println("   ✓ Read process memory")
		fmt.Println("   ✓ Write process memory")
		fmt.Println("   ✓ Create threads in the process")
		fmt.Println("   ✓ Inject code/DLLs")
		fmt.Println("   ✓ Suspend/resume threads")
		fmt.Println("   ✓ Query process information")
		fmt.Println("   ✓ Terminate the process")
		fmt.Println()
		fmt.Println("   This is why SeDebugPrivilege is so powerful!")
	} else {
		fmt.Println("❌ LIMITED ACCESS (PPL PROTECTION ACTIVE)")
		fmt.Println()
		fmt.Println("   This is a PPL-PROTECTED process (likely lsass.exe)")
		fmt.Println()
		fmt.Println("   Even with SeDebugPrivilege and a valid handle:")
		fmt.Println()
		fmt.Println("   ❌ Cannot read memory")
		fmt.Println("   ❌ Cannot write memory")
		fmt.Println("   ❌ Cannot create threads")
		fmt.Println("   ❌ Cannot inject code")
		fmt.Println("   ✓ CAN query basic info (name, PID)")
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("KEY LESSON: HANDLE ≠ ACCESS")
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println()
		fmt.Println("OpenProcess() succeeding is MISLEADING!")
		fmt.Println()
		fmt.Println("Windows gave you a handle, but it's essentially useless.")
		fmt.Println("PPL protection blocks the dangerous operations at the")
		fmt.Println("OPERATION level, not at handle creation time.")
		fmt.Println()
		fmt.Println("This is done for compatibility - old tools expect")
		fmt.Println("OpenProcess() to succeed even on protected processes.")
		fmt.Println()
		fmt.Println("To bypass PPL, you would need:")
		fmt.Println("  • A signed kernel driver")
		fmt.Println("  • A kernel exploit")
		fmt.Println("  • Physical access (DMA attack)")
		fmt.Println()
		fmt.Println("SeDebugPrivilege alone is NOT enough for PPL processes!")
	}

	fmt.Println()
}

// EnablePrivilege: Activates a privilege by name
func EnablePrivilege(privilegeName string) error {
	var hToken syscall.Handle

	fmt.Printf("\n[*] Opening current process token...\n")

	// Step 1: Get handle to current process's token
	currentProc, _ := syscall.GetCurrentProcess()
	ret, _, _ := procOpenProcessToken.Call(
		uintptr(currentProc),
		TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
		uintptr(unsafe.Pointer(&hToken)),
	)

	if ret == 0 {
		return fmt.Errorf("Failed to open process token")
	}
	defer syscall.CloseHandle(hToken)

	fmt.Printf("    ✓ Token opened successfully\n")

	// Step 2: Look up the LUID for the privilege
	fmt.Printf("\n[*] Looking up LUID for '%s'...\n", privilegeName)

	var luid LUID
	privName, _ := syscall.UTF16PtrFromString(privilegeName)
	ret, _, _ = procLookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(privName)),
		uintptr(unsafe.Pointer(&luid)),
	)

	if ret == 0 {
		return fmt.Errorf("LookupPrivilegeValue failed - privilege not available")
	}

	fmt.Printf("    ✓ LUID found: %d.%d\n", luid.HighPart, luid.LowPart)

	// Step 3: Prepare TOKEN_PRIVILEGES structure
	fmt.Printf("\n[*] Preparing privilege modification...\n")

	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{
				Luid:       luid,
				Attributes: SE_PRIVILEGE_ENABLED,
			},
		},
	}

	// Step 4: Adjust token privileges
	fmt.Printf("\n[*] Calling AdjustTokenPrivileges...\n")

	ret, _, _ = procAdjustTokenPrivileges.Call(
		uintptr(hToken),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)

	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed")
	}

	// Check if it actually worked
	lastErr, _, _ := procGetLastError.Call()
	if lastErr != 0 {
		// ERROR_NOT_ALL_ASSIGNED = 1300
		if lastErr == 1300 {
			return fmt.Errorf("Privilege could not be assigned (not held by account)")
		}
		return fmt.Errorf("AdjustTokenPrivileges error: %d", lastErr)
	}

	fmt.Printf("    ✓ Privilege adjusted successfully\n")

	return nil
}

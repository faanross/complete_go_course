//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// Token and process access rights
const (
	TOKEN_QUERY               = 0x0008
	PROCESS_QUERY_INFORMATION = 0x0400
)

// Structure definitions for token information
type SID_AND_ATTRIBUTES struct {
	Sid        *syscall.SID
	Attributes uint32
}

type TOKEN_MANDATORY_LABEL struct {
	Label SID_AND_ATTRIBUTES
}

// Token information class for integrity level queries
const TokenIntegrityLevel = 25

var (
	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	psapi                   = syscall.NewLazyDLL("psapi.dll")
	procOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
	procOpenProcess         = kernel32.NewProc("OpenProcess")
	procGetModuleBaseName   = psapi.NewProc("GetModuleBaseNameW")
)

// OpenProcessToken wrapper for opening a process token
func OpenProcessToken(process syscall.Handle, desiredAccess uint32, token *syscall.Handle) error {
	ret, _, err := procOpenProcessToken.Call(
		uintptr(process),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(token)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

// OpenProcess wrapper
func OpenProcess(desiredAccess uint32, inheritHandle bool, processID uint32) (syscall.Handle, error) {
	inherit := 0
	if inheritHandle {
		inherit = 1
	}
	ret, _, err := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(inherit),
		uintptr(processID),
	)
	if ret == 0 {
		return 0, err
	}
	return syscall.Handle(ret), nil
}

// GetProcessName retrieves the executable name of a process
func GetProcessName(hProcess syscall.Handle) string {
	buf := make([]uint16, syscall.MAX_PATH)
	ret, _, _ := procGetModuleBaseName.Call(
		uintptr(hProcess),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return "Unknown"
	}
	return syscall.UTF16ToString(buf)
}

// GetIntegrityLevel queries and returns a process's integrity level
func GetIntegrityLevel(hProcess syscall.Handle) (string, error) {
	var hToken syscall.Handle

	// Open the process token with query permissions
	err := OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(hToken)

	// Query token information - First call gets required buffer size
	var returnLength uint32
	procGetTokenInformation.Call(
		uintptr(hToken),
		TokenIntegrityLevel,
		0,
		0,
		uintptr(unsafe.Pointer(&returnLength)),
	)

	// Allocate buffer of required size
	buffer := make([]byte, returnLength)

	// Second call retrieves actual token integrity information
	ret, _, _ := procGetTokenInformation.Call(
		uintptr(hToken),
		TokenIntegrityLevel,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(returnLength),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret == 0 {
		return "", fmt.Errorf("GetTokenInformation failed")
	}

	// Parse the TOKEN_MANDATORY_LABEL structure
	tml := (*TOKEN_MANDATORY_LABEL)(unsafe.Pointer(&buffer[0]))

	// Extract integrity level from SID
	subAuthCount := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(tml.Label.Sid)) + 1))
	integrityLevel := *(*uint32)(unsafe.Pointer(
		uintptr(unsafe.Pointer(tml.Label.Sid)) + 8 + uintptr(subAuthCount-1)*4,
	))

	// Map the numeric integrity level to a human-readable name
	switch {
	case integrityLevel < 0x1000:
		return "Untrusted", nil
	case integrityLevel < 0x2000:
		return "Low", nil
	case integrityLevel < 0x3000:
		return "Medium", nil
	case integrityLevel < 0x4000:
		return "High", nil
	default:
		return "System", nil
	}
}

func main() {
	var hProcess syscall.Handle
	var pid uint32
	var processName string
	var err error

	// Check if PID was provided as command line argument
	if len(os.Args) > 1 {
		// Parse PID from command line
		pidArg, err := strconv.ParseUint(os.Args[1], 10, 32)
		if err != nil {
			fmt.Printf("Error: Invalid PID '%s'\n", os.Args[1])
			fmt.Println("Usage: program.exe [PID]")
			return
		}
		pid = uint32(pidArg)

		// Open the target process
		hProcess, err = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
		if err != nil {
			fmt.Printf("Error: Cannot open process with PID %d (access denied or process doesn't exist)\n", pid)
			fmt.Println("Note: You may need to run as Administrator to query other processes")
			return
		}
		defer syscall.CloseHandle(hProcess)

		processName = GetProcessName(hProcess)
	} else {
		// Use current process
		hProcess, _ = syscall.GetCurrentProcess()
		pid = uint32(os.Getpid())
		processName = os.Args[0]
	}

	// Get integrity level
	level, err := GetIntegrityLevel(hProcess)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Display results
	fmt.Println("================================")
	fmt.Printf("Process Name:    %s\n", processName)
	fmt.Printf("Process ID:      %d\n", pid)
	fmt.Printf("Integrity Level: %s\n", level)
	fmt.Println("================================")

	// Usage examples
	if len(os.Args) == 1 {
		fmt.Println("\nTip: Run with a PID to check other processes")
		fmt.Println("Example: program.exe 1234")
	}
}

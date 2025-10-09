//go:build windows

// Get process information via Windows API
package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess       = kernel32.NewProc("OpenProcess")
	procGetProcessId      = kernel32.NewProc("GetProcessId")
	procGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
)

// OpenProcess opens a handle to an existing process.
func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (syscall.Handle, error) {
	inherit := 0
	if inheritHandle {
		inherit = 1
	}

	handle, _, err := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(inherit),
		uintptr(processId),
	)

	// A zero handle indicates failure.
	if handle == 0 {
		return 0, err
	}
	return syscall.Handle(handle), nil
}

func main() {
	// 1. Define an integer flag '-pid' to accept the target process ID.
	targetPid := flag.Int("pid", 0, "The Process ID of the target process.")
	flag.Parse()

	// 2. Validate that a PID was provided.
	if *targetPid == 0 {
		fmt.Println("Error: A target Process ID must be provided with the -pid flag.")
		flag.Usage() // Prints the default usage message.
		os.Exit(1)
	}

	// Get handle to the current running process
	currentProc, _, _ := procGetCurrentProcess.Call()

	// Get the PID of our own process
	pid, _, _ := procGetProcessId.Call(currentProc)

	fmt.Printf("Current Process ID: %d\n", pid)
	fmt.Printf("Attempting to open process with PID: %d\n", *targetPid)

	// 3. Use the PID from the flag in the OpenProcess call.
	// PROCESS_QUERY_INFORMATION (0x0400) allows querying information about the process.
	handle, err := OpenProcess(0x0400, false, uint32(*targetPid))
	if err != nil {
		// The error will often be "Access is denied." if you don't have sufficient privileges.
		fmt.Printf("Failed to open process %d: %v\n", *targetPid, err)
		return
	}
	defer syscall.CloseHandle(handle)

	fmt.Printf("Successfully opened handle for process %d: 0x%X\n", *targetPid, handle)
}

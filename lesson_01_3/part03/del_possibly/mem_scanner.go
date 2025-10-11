//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// MEMORY_BASIC_INFORMATION: Structure returned by VirtualQuery
// Describes a contiguous region of memory with uniform properties
type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr // Starting address of region
	AllocationBase    uintptr // Base address of allocation that contains this region
	AllocationProtect uint32  // Protection when region was originally allocated
	RegionSize        uintptr // Size of region in bytes
	State             uint32  // MEM_COMMIT, MEM_RESERVE, or MEM_FREE
	Protect           uint32  // Current protection flags
	Type              uint32  // MEM_PRIVATE, MEM_MAPPED, or MEM_IMAGE
}

// Memory state constants
const (
	MEM_COMMIT  = 0x1000  // Memory is committed (has physical/page file backing)
	MEM_RESERVE = 0x2000  // Memory is reserved (address space reserved but not backed)
	MEM_FREE    = 0x10000 // Memory is free (not allocated)

	MEM_PRIVATE = 0x20000   // Private memory (heap, stack)
	MEM_MAPPED  = 0x40000   // Mapped file
	MEM_IMAGE   = 0x1000000 // Executable image (PE file)
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procVirtualQuery = kernel32.NewProc("VirtualQuery")
)

// VirtualQuery: Query information about a memory address
func VirtualQuery(address uintptr) (*MEMORY_BASIC_INFORMATION, error) {
	var mbi MEMORY_BASIC_INFORMATION

	// Call VirtualQuery API
	ret, _, err := procVirtualQuery.Call(
		address,                       // Address to query
		uintptr(unsafe.Pointer(&mbi)), // Buffer to receive info
		unsafe.Sizeof(mbi),            // Size of buffer
	)

	if ret == 0 {
		return nil, err // Query failed
	}
	return &mbi, nil
}

// EnumerateMemory: Walk through entire address space
func EnumerateMemory() {
	var address uintptr = 0

	// Scan from 0 to max user-mode address on x64
	for address < 0x7FFFFFFF0000 {
		mbi, err := VirtualQuery(address)
		if err != nil {
			break // End of accessible memory
		}

		// Only show committed memory (ignore reserved/free)
		if mbi.State == MEM_COMMIT {
			protection := getProtectionString(mbi.Protect)
			memType := getTypeString(mbi.Type)

			fmt.Printf("0x%016X - 0x%016X  %s  %s\n",
				mbi.BaseAddress,
				mbi.BaseAddress+mbi.RegionSize,
				protection,
				memType)
		}

		// Jump to next region
		address = mbi.BaseAddress + mbi.RegionSize
	}
}

// Helper: Convert protection flags to readable string
func getProtectionString(protect uint32) string {
	switch protect & 0xFF {
	case 0x01:
		return "---" // PAGE_NOACCESS
	case 0x02:
		return "R--" // PAGE_READONLY
	case 0x04:
		return "RW-" // PAGE_READWRITE
	case 0x20:
		return "R-X" // PAGE_EXECUTE_READ
	case 0x40:
		return "RWX" // PAGE_EXECUTE_READWRITE
	default:
		return "???"
	}
}

// Helper: Convert type flags to readable string
func getTypeString(memType uint32) string {
	switch memType {
	case MEM_PRIVATE:
		return "Private"
	case MEM_MAPPED:
		return "Mapped"
	case MEM_IMAGE:
		return "Image"
	default:
		return "Unknown"
	}
}

func main() {
	fmt.Println("Memory Map of Current Process:")
	fmt.Println("Start Address       - End Address         Prot  Type")
	fmt.Println("─────────────────────────────────────────────────────")
	EnumerateMemory()
}

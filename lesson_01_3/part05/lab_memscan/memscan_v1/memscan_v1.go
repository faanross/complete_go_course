//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

const (
	MEM_COMMIT  = 0x1000
	MEM_PRIVATE = 0x20000
	MEM_MAPPED  = 0x40000
	MEM_IMAGE   = 0x1000000
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procVirtualQuery = kernel32.NewProc("VirtualQuery")
)

func VirtualQuery(address uintptr) (*MEMORY_BASIC_INFORMATION, error) {
	var mbi MEMORY_BASIC_INFORMATION

	ret, _, err := procVirtualQuery.Call(
		address,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
	)

	if ret == 0 {
		return nil, err
	}
	return &mbi, nil
}

func getProtectionString(protect uint32) string {
	switch protect & 0xFF {
	case 0x01:
		return "---"
	case 0x02:
		return "R--"
	case 0x04:
		return "RW-"
	case 0x20:
		return "R-X"
	case 0x40:
		return "RWX"
	default:
		return "???"
	}
}

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
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║  BASIC MEMORY SCANNER v1.0 - No Module Context            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println("\n[*] Scanning process memory...")
	fmt.Println("Start Address       - End Address         Prot  Type")
	fmt.Println("─────────────────────────────────────────────────────────────")

	var address uintptr = 0
	regionCount := 0

	for address < 0x7FFFFFFF0000 {
		mbi, err := VirtualQuery(address)
		if err != nil {
			break
		}

		if mbi.State == MEM_COMMIT {
			fmt.Printf("0x%016X - 0x%016X  %s  %s\n",
				mbi.BaseAddress,
				mbi.BaseAddress+mbi.RegionSize,
				getProtectionString(mbi.Protect),
				getTypeString(mbi.Type))
			regionCount++
		}

		address = mbi.BaseAddress + mbi.RegionSize
	}

	fmt.Printf("\n[✓] Scan complete: %d regions found\n", regionCount)
	fmt.Println("\n[✗] PROBLEM: We see memory regions but don't know what they are!")
	fmt.Println("    - Which regions belong to which DLLs?")
	fmt.Println("    - What are the .text, .data, .rdata sections?")
	fmt.Println("    - Is this heap, stack, or code?")
}

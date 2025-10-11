//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
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

// ADD THIS MISSING STRUCTURE
type MODULEINFO struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

const (
	MEM_COMMIT  = 0x1000
	MEM_PRIVATE = 0x20000
	MEM_MAPPED  = 0x40000
	MEM_IMAGE   = 0x1000000
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	psapi                    = syscall.NewLazyDLL("psapi.dll")
	procVirtualQuery         = kernel32.NewProc("VirtualQuery")
	procEnumProcessModules   = psapi.NewProc("EnumProcessModules")
	procGetModuleInformation = psapi.NewProc("GetModuleInformation")
	procGetModuleBaseNameW   = psapi.NewProc("GetModuleBaseNameW")
	procGetCurrentProcess    = kernel32.NewProc("GetCurrentProcess")
)

type ModuleInfo struct {
	BaseAddress uintptr
	Size        uint32
	Name        string
}

var loadedModules []ModuleInfo

func EnumerateModules() error {
	fmt.Println("[*] Step 1: Enumerating loaded modules...")

	hProcess, _, _ := procGetCurrentProcess.Call()

	var modules [1024]syscall.Handle
	var needed uint32

	ret, _, err := procEnumProcessModules.Call(
		hProcess,
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(modules[0]))),
		uintptr(unsafe.Pointer(&needed)),
	)

	if ret == 0 {
		fmt.Printf("[✗] Failed to enumerate modules: %v\n", err)
		return err
	}

	moduleCount := int(needed) / int(unsafe.Sizeof(modules[0]))
	fmt.Printf("[✓] Found %d loaded modules\n\n", moduleCount)

	for i := 0; i < moduleCount; i++ {
		var modInfo MODULEINFO

		procGetModuleInformation.Call(
			hProcess,
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&modInfo)),
			unsafe.Sizeof(modInfo),
		)

		var nameBuffer [260]uint16
		procGetModuleBaseNameW.Call(
			hProcess,
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&nameBuffer[0])),
			uintptr(len(nameBuffer)),
		)

		moduleName := syscall.UTF16ToString(nameBuffer[:])

		loadedModules = append(loadedModules, ModuleInfo{
			BaseAddress: modInfo.BaseOfDll,
			Size:        modInfo.SizeOfImage,
			Name:        moduleName,
		})

		fmt.Printf("    [%3d] %-30s  Base: 0x%016X  Size: 0x%08X\n",
			i+1, moduleName, modInfo.BaseOfDll, modInfo.SizeOfImage)
	}

	return nil
}

func identifyModule(addr uintptr, memType uint32) string {
	if memType == MEM_IMAGE {
		for _, mod := range loadedModules {
			if addr >= mod.BaseAddress && addr < mod.BaseAddress+uintptr(mod.Size) {
				return mod.Name
			}
		}
		return "Unknown Image"
	}

	if memType == MEM_PRIVATE {
		return "Heap/Stack/Private"
	}

	if memType == MEM_MAPPED {
		return "Memory-Mapped File"
	}

	return "Unknown"
}

func main() {
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║  ENHANCED MEMORY SCANNER v2.0 - With Module Enumeration    ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝\n")

	// Enumerate modules first
	if err := EnumerateModules(); err != nil {
		return
	}

	// FIX: Use strings.Repeat instead of string * int
	fmt.Println("\n" + strings.Repeat("═", 65))
	fmt.Println("[*] Step 2: Scanning memory with module attribution...")
	fmt.Println("Start Address       - End Address         Prot  Type     Module")
	fmt.Println(strings.Repeat("─", 80))

	var address uintptr = 0

	for address < 0x7FFFFFFF0000 {
		mbi, err := VirtualQuery(address)
		if err != nil {
			break
		}

		if mbi.State == MEM_COMMIT {
			identification := identifyModule(mbi.BaseAddress, mbi.Type)

			fmt.Printf("0x%016X - 0x%016X  %s  %-7s  %s\n",
				mbi.BaseAddress,
				mbi.BaseAddress+mbi.RegionSize,
				getProtectionString(mbi.Protect),
				getTypeString(mbi.Type),
				identification)
		}

		address = mbi.BaseAddress + mbi.RegionSize
	}

	fmt.Println("\n[✓] Scan complete with module attribution")
	fmt.Println("\n[⚠️] PARTIAL SUCCESS: We know which DLL, but not which section!")
	fmt.Println("    - Can identify: memory belongs to 'kernel32.dll'")
	fmt.Println("    - Cannot identify: whether it's .text, .data, or .rdata")
	fmt.Println("    - Next step: Parse PE sections for complete forensics")
}

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

//go:build windows
// +build windows

// Enhanced memory scanner with PE parsing and module enumeration
package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// MEMORY_BASIC_INFORMATION: Structure returned by VirtualQuery
type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// IMAGE_DOS_HEADER: Beginning of every PE file ("MZ" signature)
type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32 // Offset to PE header
}

// IMAGE_NT_HEADERS64: Main PE header
type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	// ... rest of fields truncated for brevity
}

// IMAGE_SECTION_HEADER: Describes a section (.text, .data, etc.)
type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// MODULEINFO: Information about a loaded module
type MODULEINFO struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

// Memory state and type constants
const (
	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_FREE    = 0x10000

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

// ModuleInfo: Stores information about loaded modules (DLLs)
type ModuleInfo struct {
	BaseAddress uintptr
	Size        uint32
	Name        string
	Sections    map[uintptr]string // Maps address -> section name
}

var loadedModules []ModuleInfo

// EnumerateModules: Build a list of all loaded DLLs and their sections
func EnumerateModules() {
	hProcess, _, _ := procGetCurrentProcess.Call()

	var modules [1024]syscall.Handle
	var needed uint32

	// Get all loaded module handles
	ret, _, _ := procEnumProcessModules.Call(
		hProcess,
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(modules[0]))),
		uintptr(unsafe.Pointer(&needed)),
	)

	if ret == 0 {
		return
	}

	moduleCount := int(needed) / int(unsafe.Sizeof(modules[0]))

	// For each module, get its info and parse PE sections
	for i := 0; i < moduleCount; i++ {
		var modInfo MODULEINFO

		// Get module base address and size
		procGetModuleInformation.Call(
			hProcess,
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&modInfo)),
			unsafe.Sizeof(modInfo),
		)

		// Get module name
		var nameBuffer [260]uint16
		procGetModuleBaseNameW.Call(
			hProcess,
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&nameBuffer[0])),
			uintptr(len(nameBuffer)),
		)

		moduleName := syscall.UTF16ToString(nameBuffer[:])

		// Parse PE sections for this module
		sections := parsePESections(modInfo.BaseOfDll)

		loadedModules = append(loadedModules, ModuleInfo{
			BaseAddress: modInfo.BaseOfDll,
			Size:        modInfo.SizeOfImage,
			Name:        moduleName,
			Sections:    sections,
		})
	}
}

// parsePESections: Extract section names from PE headers
func parsePESections(baseAddress uintptr) map[uintptr]string {
	sections := make(map[uintptr]string)

	defer func() {
		// Catch any access violations from reading invalid memory
		recover()
	}()

	// Read DOS header
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(baseAddress))
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		return sections
	}

	// Read NT headers
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(baseAddress + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != 0x00004550 { // "PE\0\0"
		return sections
	}

	// Read section table (comes right after NT headers)
	sectionTableOffset := baseAddress + uintptr(dosHeader.E_lfanew) +
		unsafe.Sizeof(IMAGE_NT_HEADERS64{})

	numSections := int(ntHeaders.FileHeader.NumberOfSections)

	for i := 0; i < numSections; i++ {
		sectionPtr := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(
			sectionTableOffset + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{}),
		))

		// Extract section name (null-terminated or 8 bytes)
		name := strings.TrimRight(string(sectionPtr.Name[:]), "\x00")
		sectionAddr := baseAddress + uintptr(sectionPtr.VirtualAddress)

		sections[sectionAddr] = name
	}

	return sections
}

// identifyRegion: Determine what a memory region represents
func identifyRegion(mbi *MEMORY_BASIC_INFORMATION) string {
	addr := mbi.BaseAddress

	// Check for special fixed addresses
	if addr == 0x7FFE0000 || addr == 0x7FFEE000 {
		return "PEB (Process Environment Block)"
	}
	if addr >= 0x7FFE0000 && addr < 0x7FFF0000 {
		return "Shared User Data / PEB"
	}

	// For Image type, match against loaded modules
	if mbi.Type == MEM_IMAGE {
		for _, mod := range loadedModules {
			if addr >= mod.BaseAddress && addr < mod.BaseAddress+uintptr(mod.Size) {
				// Check if this address corresponds to a specific section
				for sectionAddr, sectionName := range mod.Sections {
					if addr == sectionAddr {
						return fmt.Sprintf("%s (%s)", mod.Name, sectionName)
					}
				}
				// If no specific section match, just return module name with offset
				return mod.Name
			}
		}
		return "Unknown Image"
	}

	// Private memory - could be heap or stack
	if mbi.Type == MEM_PRIVATE {
		// Large RW- regions in specific ranges are often heap
		if mbi.RegionSize > 0x10000 && (mbi.Protect&0xFF == 0x04) {
			return "Heap"
		}
		// Smaller regions might be stack or thread-local storage
		if mbi.RegionSize <= 0x10000 {
			return "Stack / TLS"
		}
		return "Private"
	}

	// Mapped memory (files)
	if mbi.Type == MEM_MAPPED {
		return "Memory-Mapped File"
	}

	return "Unknown"
}

// VirtualQuery: Query information about a memory address
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

// EnumerateMemory: Walk through entire address space
func EnumerateMemory() {
	var address uintptr = 0

	for address < 0x7FFFFFFF0000 {
		mbi, err := VirtualQuery(address)
		if err != nil {
			break
		}

		if mbi.State == MEM_COMMIT {
			protection := getProtectionString(mbi.Protect)
			memType := getTypeString(mbi.Type)
			interpretation := identifyRegion(mbi)

			fmt.Printf("0x%016X - 0x%016X  %s  %-7s  %s\n",
				mbi.BaseAddress,
				mbi.BaseAddress+mbi.RegionSize,
				protection,
				memType,
				interpretation)
		}

		address = mbi.BaseAddress + mbi.RegionSize
	}
}

// getProtectionString: Convert protection flags to readable string
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

// getTypeString: Convert type flags to readable string
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
	fmt.Println("Enhanced Memory Map of Current Process:")
	fmt.Println("Start Address       - End Address         Prot  Type     Interpretation")
	fmt.Println("────────────────────────────────────────────────────────────────────────────────")

	// First, enumerate all loaded modules and parse their PE sections
	EnumerateModules()

	// Then scan memory and identify regions
	EnumerateMemory()
}

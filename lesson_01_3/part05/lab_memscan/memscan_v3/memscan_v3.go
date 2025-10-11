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
	E_lfanew   int32
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

type MODULEINFO struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

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

type SectionInfo struct {
	Name  string
	Start uintptr
	End   uintptr
}

type ModuleInfo struct {
	BaseAddress uintptr
	Size        uint32
	Name        string
	Sections    []SectionInfo
}

var loadedModules []ModuleInfo

func parsePESections(baseAddress uintptr, moduleName string) []SectionInfo {
	var sections []SectionInfo

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("    [⚠️] %s: Cannot parse PE (memory protection issue)\n", moduleName)
		}
	}()

	// Read DOS header
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(baseAddress))
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		fmt.Printf("    [✗] %s: Invalid DOS signature (not 'MZ')\n", moduleName)
		return sections
	}

	// Read PE signature
	peHeaderOffset := baseAddress + uintptr(dosHeader.E_lfanew)
	signature := (*uint32)(unsafe.Pointer(peHeaderOffset))
	if *signature != 0x00004550 { // "PE\0\0"
		fmt.Printf("    [✗] %s: Invalid PE signature\n", moduleName)
		return sections
	}

	// Read file header
	fileHeader := (*IMAGE_FILE_HEADER)(unsafe.Pointer(peHeaderOffset + 4))
	numSections := int(fileHeader.NumberOfSections)

	fmt.Printf("    [✓] %s: PE validated, parsing %d sections\n",
		moduleName, numSections)

	// Calculate section table offset
	sectionTableOffset := peHeaderOffset + 4 +
		unsafe.Sizeof(IMAGE_FILE_HEADER{}) +
		uintptr(fileHeader.SizeOfOptionalHeader)

	// Parse each section
	for i := 0; i < numSections; i++ {
		sectionPtr := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(
			sectionTableOffset + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{}),
		))

		name := cleanSectionName(sectionPtr.Name[:])
		if name == "" {
			continue
		}

		sectionStart := baseAddress + uintptr(sectionPtr.VirtualAddress)
		sectionEnd := sectionStart + uintptr(sectionPtr.VirtualSize)

		sections = append(sections, SectionInfo{
			Name:  name,
			Start: sectionStart,
			End:   sectionEnd,
		})

		fmt.Printf("        [%d] %-8s  0x%016X - 0x%016X  (size: 0x%X)\n",
			i+1, name, sectionStart, sectionEnd, sectionPtr.VirtualSize)
	}

	return sections
}

func cleanSectionName(nameBytes []byte) string {
	length := 0
	for length < len(nameBytes) && nameBytes[length] != 0 {
		length++
	}

	if length == 0 {
		return ""
	}

	// Validate printable ASCII
	for i := 0; i < length; i++ {
		if nameBytes[i] < 0x20 || nameBytes[i] > 0x7E {
			return ""
		}
	}

	return string(nameBytes[:length])
}

func EnumerateModules() error {
	fmt.Println("[*] Phase 1: Enumerating loaded modules and parsing PE structures...")
	fmt.Println()

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

		fmt.Printf("  Module [%3d]: %-30s @ 0x%016X\n",
			i+1, moduleName, modInfo.BaseOfDll)

		// Parse PE sections
		sections := parsePESections(modInfo.BaseOfDll, moduleName)

		loadedModules = append(loadedModules, ModuleInfo{
			BaseAddress: modInfo.BaseOfDll,
			Size:        modInfo.SizeOfImage,
			Name:        moduleName,
			Sections:    sections,
		})

		fmt.Println()
	}

	return nil
}

func identifyRegion(mbi *MEMORY_BASIC_INFORMATION) string {
	addr := mbi.BaseAddress

	// Check special addresses
	if addr == 0x7FFE0000 || addr == 0x7FFEE000 {
		return "PEB (Process Environment Block)"
	}
	if addr >= 0x7FFE0000 && addr < 0x7FFF0000 {
		return "Shared User Data / PEB"
	}

	// Image memory - match to module sections
	if mbi.Type == MEM_IMAGE {
		for _, mod := range loadedModules {
			if addr >= mod.BaseAddress && addr < mod.BaseAddress+uintptr(mod.Size) {
				// Check sections
				for _, section := range mod.Sections {
					if addr >= section.Start && addr < section.End {
						return fmt.Sprintf("%s (%s)", mod.Name, section.Name)
					}
				}
				return fmt.Sprintf("%s (PE Headers)", mod.Name)
			}
		}
		return "Unknown Image"
	}

	// Private memory
	if mbi.Type == MEM_PRIVATE {
		if mbi.RegionSize > 0x10000 && (mbi.Protect&0xFF == 0x04) {
			return "Heap (Dynamic Allocation)"
		}
		if mbi.RegionSize <= 0x10000 {
			return "Stack / TLS (Thread-Local)"
		}
		return "Private Memory"
	}

	// Mapped memory
	if mbi.Type == MEM_MAPPED {
		return "Memory-Mapped File"
	}

	return "Unknown"
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

func EnumerateMemory() {
	fmt.Println("\n" + strings.Repeat("═", 80))
	fmt.Println("[*] Phase 2: Scanning memory with complete forensic attribution...")
	fmt.Println("\nStart Address       - End Address         Prot  Type     Identification")
	fmt.Println(strings.Repeat("─", 95))

	var address uintptr = 0
	imageCount := 0
	privateCount := 0
	mappedCount := 0

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

			// Count by type
			switch mbi.Type {
			case MEM_IMAGE:
				imageCount++
			case MEM_PRIVATE:
				privateCount++
			case MEM_MAPPED:
				mappedCount++
			}
		}

		address = mbi.BaseAddress + mbi.RegionSize
	}

	fmt.Println("\n" + strings.Repeat("═", 80))
	fmt.Println("[✓] Memory Forensics Complete!")
	fmt.Println("\nStatistics:")
	fmt.Printf("  • Image regions (DLLs/EXE):     %d\n", imageCount)
	fmt.Printf("  • Private regions (Heap/Stack): %d\n", privateCount)
	fmt.Printf("  • Mapped regions (Files):       %d\n", mappedCount)
	fmt.Printf("  • Total committed regions:      %d\n", imageCount+privateCount+mappedCount)
}

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║       COMPLETE MEMORY FORENSICS TOOL v3.0 - Full PE Section Parser        ║")
	fmt.Println("║                  Advanced Windows Memory Analysis                         ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════════════╝\n")

	// Phase 1: Enumerate and parse
	if err := EnumerateModules(); err != nil {
		return
	}

	// Phase 2: Scan and identify
	EnumerateMemory()

	fmt.Println("\n🎓 Full Mapping Capabilities Unlocked:")
	fmt.Println("  ✓ Module identification (which DLL)")
	fmt.Println("  ✓ Section identification (.text, .data, .rdata)")
	fmt.Println("  ✓ Memory type classification (Image/Private/Mapped)")
	fmt.Println("  ✓ Protection analysis (R-X, RW-, etc.)")
	fmt.Println("  ✓ Complete address space mapping")
}

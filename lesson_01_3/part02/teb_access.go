//go:build windows
// +build windows

package main

/*
#include <windows.h>
#include <winternl.h>

void* GetTEB() {
    return NtCurrentTeb();
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func main() {
	teb := uintptr(C.GetTEB())
	fmt.Printf("TEB Address: 0x%X\n", teb)

	// Read PEB from TEB+0x60 (x64)
	peb := *(*uintptr)(unsafe.Pointer(teb + 0x60))
	fmt.Printf("PEB Address: 0x%X\n", peb)

	// Optional: Read some PEB fields to verify
	// ImageBaseAddress is at PEB+0x10
	imageBase := *(*uintptr)(unsafe.Pointer(peb + 0x10))
	fmt.Printf("Image Base Address: 0x%X\n", imageBase)
}

# Process Integrity Level Code Explanation

## Package and Imports

```go
package main

import (
    "fmt"
    "os"
    "strconv"
    "syscall"
    "unsafe"
)
```

The program uses `syscall` for direct Windows API calls, `unsafe` for pointer manipulation when working with C-style structures, `strconv` for converting command-line PID strings to integers, and `os` for accessing command-line arguments and process information.

## Constants - Access Rights

```go
const (
    TOKEN_QUERY          = 0x0008
    PROCESS_QUERY_INFORMATION = 0x0400
)
```

`TOKEN_QUERY` (0x0008) is the access right needed to query non-sensitive token information like integrity levels. `PROCESS_QUERY_INFORMATION` (0x0400) is the access right required to retrieve information about a process, including opening its token.

## Structure Definitions

```go
type SID_AND_ATTRIBUTES struct {
    Sid        *syscall.SID
    Attributes uint32
}
```

This mirrors the Windows `SID_AND_ATTRIBUTES` structure. The `Sid` field points to a Security Identifier, and `Attributes` contains flags that describe how the SID is used (though we don't examine this field for integrity levels).

```go
type TOKEN_MANDATORY_LABEL struct {
    Label SID_AND_ATTRIBUTES
}
```

This structure represents the mandatory integrity label attached to a token. It contains a single `SID_AND_ATTRIBUTES` field where the SID encodes the integrity level.

## Token Information Class

```go
const TokenIntegrityLevel = 25
```

This is the `TOKEN_INFORMATION_CLASS` enumeration value for querying integrity levels. When passed to `GetTokenInformation`, it requests the `TOKEN_MANDATORY_LABEL` structure.

## DLL and Procedure Loading

```go
var (
    advapi32                = syscall.NewLazyDLL("advapi32.dll")
    kernel32                = syscall.NewLazyDLL("kernel32.dll")
    psapi                   = syscall.NewLazyDLL("psapi.dll")
    procOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
    procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
    procOpenProcess         = kernel32.NewProc("OpenProcess")
    procGetModuleBaseName   = psapi.NewProc("GetModuleBaseNameW")
)
```

These variables use lazy loading to access Windows DLLs and their functions. `NewLazyDLL` doesn't load the DLL immediately; it loads when first accessed. `NewProc` retrieves function addresses from the DLLs. The three DLLs are: `advapi32.dll` (security/token functions), `kernel32.dll` (process management), and `psapi.dll` (process status functions).

## OpenProcessToken Function

```go
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
```

This wraps the Windows `OpenProcessToken` API. It takes a process handle and desired access rights, then writes the opened token handle to the `token` parameter. The `.Call()` method invokes the Windows API with three `uintptr` parameters. Return value of 0 indicates failure in Windows API convention.

## OpenProcess Function

```go
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
```

This wraps the Windows `OpenProcess` API, which opens an existing process and returns a handle to it. The `desiredAccess` parameter specifies what operations you want to perform (we use `PROCESS_QUERY_INFORMATION`). The `inheritHandle` boolean is converted to 0 or 1 as Windows expects. The `processID` identifies which process to open. The return value is the process handle cast from `uintptr`.

## GetProcessName Function

```go
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
```

This retrieves the executable name of a process using `GetModuleBaseNameW` (the 'W' suffix indicates wide/Unicode version). The buffer is `[]uint16` because Windows uses UTF-16 encoding. The second parameter (0) means get the name of the executable module itself. The function writes the name into the buffer, and `syscall.UTF16ToString` converts it to a Go string.

## GetIntegrityLevel Function

```go
func GetIntegrityLevel(hProcess syscall.Handle) (string, error) {
    var hToken syscall.Handle
    
    err := OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)
    if err != nil {
        return "", err
    }
    defer syscall.CloseHandle(hToken)
```

This function takes a process handle and returns its integrity level as a string. First, it opens the process's access token with `TOKEN_QUERY` rights. The `defer` ensures the token handle is closed when the function returns.

### First GetTokenInformation Call

```go
    var returnLength uint32
    procGetTokenInformation.Call(
        uintptr(hToken),
        TokenIntegrityLevel,
        0,
        0,
        uintptr(unsafe.Pointer(&returnLength)),
    )
```

This is the sizing call. By passing 0 for both the buffer pointer and buffer size, we're asking Windows "how much memory do I need?" The required size is written to `returnLength`. This is a common pattern in Windows APIs that return variable-sized data.

### Second GetTokenInformation Call

```go
    buffer := make([]byte, returnLength)
    
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
```

Now we allocate a buffer of the correct size and call `GetTokenInformation` again. This time it writes the actual `TOKEN_MANDATORY_LABEL` structure into our buffer. The buffer pointer is obtained using `&buffer[0]` and cast to `uintptr`.

### Parsing the TOKEN_MANDATORY_LABEL

```go
    tml := (*TOKEN_MANDATORY_LABEL)(unsafe.Pointer(&buffer[0]))
```

This casts the raw byte buffer to a pointer to our `TOKEN_MANDATORY_LABEL` structure. Go now interprets the bytes according to the structure layout.

### Extracting the Integrity Level from the SID

```go
    subAuthCount := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(tml.Label.Sid)) + 1))
```

A Windows SID has a specific binary structure. The first byte is the revision number, and the second byte is the sub-authority count. This line reads the byte at offset 1 from the SID pointer, which gives us how many sub-authorities the SID contains.

```go
    integrityLevel := *(*uint32)(unsafe.Pointer(
        uintptr(unsafe.Pointer(tml.Label.Sid)) + 8 + uintptr(subAuthCount-1)*4,
    ))
```

The integrity level value is stored as the last sub-authority in the SID. The SID structure has an 8-byte header (revision, sub-auth count, and 6-byte identifier authority). After the header come the sub-authorities, each 4 bytes. We calculate the offset as: 8 bytes (header) + (subAuthCount-1) * 4 bytes. The `subAuthCount-1` gives us the zero-based index of the last sub-authority. This pointer arithmetic gets us to the integrity level value, which we dereference as a `uint32`.

### Mapping to Human-Readable Names

```go
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
```

Windows defines integrity levels in ranges. Values below 0x1000 (4096) are Untrusted, 0x1000-0x1FFF are Low, 0x2000-0x2FFF are Medium, 0x3000-0x3FFF are High, and 0x4000 and above are System/Protected. The specific values within each range can indicate sub-levels, but we're categorizing by the major ranges.

## Main Function

### Command-Line Argument Processing

```go
    var hProcess syscall.Handle
    var pid uint32
    var processName string
    var err error
    
    if len(os.Args) > 1 {
        pidArg, err := strconv.ParseUint(os.Args[1], 10, 32)
        if err != nil {
            fmt.Printf("Error: Invalid PID '%s'\n", os.Args[1])
            fmt.Println("Usage: program.exe [PID]")
            return
        }
        pid = uint32(pidArg)
```

The program checks if a command-line argument was provided. `os.Args[0]` is the program name, so `os.Args[1]` is the first argument. `strconv.ParseUint` converts the string to an unsigned 64-bit integer (base 10, 32-bit max), which we then cast to `uint32` for the PID.

### Opening Target Process

```go
        hProcess, err = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
        if err != nil {
            fmt.Printf("Error: Cannot open process with PID %d (access denied or process doesn't exist)\n", pid)
            fmt.Println("Note: You may need to run as Administrator to query other processes")
            return
        }
        defer syscall.CloseHandle(hProcess)
        
        processName = GetProcessName(hProcess)
```

If a PID was provided, we open that process with `PROCESS_QUERY_INFORMATION` access. The `defer` ensures we close the handle when main() exits. Then we retrieve the process name using the handle.

### Using Current Process

```go
    } else {
        hProcess, _ = syscall.GetCurrentProcess()
        pid = uint32(os.Getpid())
        processName = os.Args[0]
    }
```

If no PID was provided, we use `GetCurrentProcess()` which returns a pseudo-handle to the current process (value -1, which Windows interprets specially). `os.Getpid()` gets our own process ID, and `os.Args[0]` gives us our executable name.

### Querying and Displaying Results

```go
    level, err := GetIntegrityLevel(hProcess)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Println("================================")
    fmt.Printf("Process Name:    %s\n", processName)
    fmt.Printf("Process ID:      %d\n", pid)
    fmt.Printf("Integrity Level: %s\n", level)
    fmt.Println("================================")
```

This calls our `GetIntegrityLevel` function with whichever process handle we obtained, then displays the results in a formatted manner.

### Usage Hint

```go
    if len(os.Args) == 1 {
        fmt.Println("\nTip: Run with a PID to check other processes")
        fmt.Println("Example: program.exe 1234")
    }
```

If the program was run without arguments (only checking its own integrity level), display a hint about the PID functionality for educational purposes.
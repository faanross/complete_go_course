# Windows Privilege Debug Code: Technical Companion

## Build Tags and Package Setup

```go
//go:build windows
// +build windows
```

These build constraints ensure this code only compiles on Windows systems. The double-slash syntax is the modern format, while `+build` is the legacy format (kept for backwards compatibility).

---

## Data Structure Definitions

### LUID Structure

```go
type LUID struct {
    LowPart  uint32
    HighPart int32
}
```

**Technical Details**:
- Total size: 8 bytes (4 + 4)
- Maps directly to Windows `LUID` structure
- `LowPart` is unsigned, `HighPart` is signed (Windows convention)
- Used as a unique identifier for privileges on the local system
- Each privilege (SeDebugPrivilege, SeShutdownPrivilege, etc.) has a unique LUID value

### LUID_AND_ATTRIBUTES Structure

```go
type LUID_AND_ATTRIBUTES struct {
    Luid       LUID
    Attributes uint32
}
```

**Technical Details**:
- Size: 12 bytes (8 for LUID + 4 for Attributes)
- `Attributes` is a bitmask containing flags like:
    - `SE_PRIVILEGE_ENABLED` (0x00000002)
    - `SE_PRIVILEGE_ENABLED_BY_DEFAULT` (0x00000001)
    - `SE_PRIVILEGE_REMOVED` (0x00000004)
    - `SE_PRIVILEGE_USED_FOR_ACCESS` (0x80000000)

### TOKEN_PRIVILEGES Structure

```go
type TOKEN_PRIVILEGES struct {
    PrivilegeCount uint32
    Privileges     [1]LUID_AND_ATTRIBUTES
}
```

**Implementation Notes**:
- This is a variable-length structure
- `[1]LUID_AND_ATTRIBUTES` is a C-style "array of at least 1" trick
- In C, you'd allocate more space for multiple privileges
- Here we only need 1 privilege, so the fixed array works
- Total size: 16 bytes (4 + 12)
- When passed to `AdjustTokenPrivileges`, Windows reads `PrivilegeCount` to know how many array elements to process

### SID_IDENTIFIER_AUTHORITY Structure

```go
type SID_IDENTIFIER_AUTHORITY struct {
    Value [6]byte
}
```

**Technical Details**:
- 6-byte array representing the top-level authority for a SID
- Common values:
    - `{0,0,0,0,0,0}` = Null Authority
    - `{0,0,0,0,0,1}` = World Authority
    - `{0,0,0,0,0,5}` = NT Authority (used in this code)
- The value `{0,0,0,0,0,5}` with subauthorities `{SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS}` creates the Administrators group SID

### SID_AND_ATTRIBUTES Structure

```go
type SID_AND_ATTRIBUTES struct {
    Sid        *syscall.SID
    Attributes uint32
}
```

**Technical Details**:
- Pointer to SID structure (variable length)
- `Attributes` contains flags like:
    - `SE_GROUP_MANDATORY` (0x00000001)
    - `SE_GROUP_ENABLED_BY_DEFAULT` (0x00000002)
    - `SE_GROUP_ENABLED` (0x00000004)

### TOKEN_GROUPS Structure

```go
type TOKEN_GROUPS struct {
    GroupCount uint32
    Groups     [1]SID_AND_ATTRIBUTES
}
```

**Implementation Notes**:
- Same variable-length pattern as `TOKEN_PRIVILEGES`
- Not directly used in this code but defined for completeness
- Would be used if querying token group membership via `GetTokenInformation`

---

## Constants Breakdown

```go
const (
    SE_PRIVILEGE_ENABLED    = 0x00000002
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY             = 0x0008
    PROCESS_ALL_ACCESS      = 0x001F0FFF
    ERROR_ACCESS_DENIED     = 5
    
    SECURITY_NT_AUTHORITY       = 5
    SECURITY_BUILTIN_DOMAIN_RID = 0x20
    DOMAIN_ALIAS_RID_ADMINS     = 0x220
    
    TokenGroups = 2
)
```

**Detailed Breakdown**:

- **`SE_PRIVILEGE_ENABLED = 0x00000002`**: Bitmask flag indicating a privilege should be enabled in the token

- **`TOKEN_ADJUST_PRIVILEGES = 0x0020`**: Access right needed to modify privileges in a token

- **`TOKEN_QUERY = 0x0008`**: Access right needed to query token information

- **`PROCESS_ALL_ACCESS = 0x001F0FFF`**: Composite access mask containing:
    - `STANDARD_RIGHTS_REQUIRED` (0x000F0000)
    - `SYNCHRONIZE` (0x00100000)
    - All process-specific rights (0x0FFF)
    - Grants maximum access to a process object

- **`ERROR_ACCESS_DENIED = 5`**: Win32 error code for access denied (ERROR_ACCESS_DENIED)

- **`SECURITY_NT_AUTHORITY = 5`**: Value for NT Authority in SID_IDENTIFIER_AUTHORITY

- **`SECURITY_BUILTIN_DOMAIN_RID = 0x20`**: First subauthority (32) for built-in domain

- **`DOMAIN_ALIAS_RID_ADMINS = 0x220`**: Second subauthority (544) for Administrators group
    - Complete SID: S-1-5-32-544 (Administrators)

- **`TokenGroups = 2`**: Enumeration value for `TOKEN_INFORMATION_CLASS` when querying group membership

---

## Windows API Procedure Loading

```go
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
```

**Technical Implementation**:

- **`syscall.NewLazyDLL`**: Loads DLL lazily (on first use, not at program start)
- **`NewProc`**: Gets function pointer by name
- **`LookupPrivilegeValueW`**: Wide-character version (Unicode), hence the 'W' suffix

**Why Lazy Loading**:
- Defers actual `LoadLibrary` call until first procedure invocation
- Reduces startup time
- Allows checking if procedures exist without crashing

---

## Function Implementation Analysis

### TryOpenProcess

```go
func TryOpenProcess(pid uint32) (syscall.Handle, error) {
    handle, _, err := procOpenProcess.Call(
        uintptr(PROCESS_ALL_ACCESS),
        0,
        uintptr(pid),
    )
```

**API Signature**: `HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)`

**Parameter Mapping**:
1. `uintptr(PROCESS_ALL_ACCESS)` → `dwDesiredAccess`: Requested access rights
2. `0` → `bInheritHandle`: FALSE (child processes won't inherit this handle)
3. `uintptr(pid)` → `dwProcessId`: Process ID to open

**Return Value Handling**:
```go
if handle == 0 {
    lastErr, _, _ := procGetLastError.Call()
```

- Windows API returns `NULL` (0) on failure
- Must call `GetLastError()` to get actual error code
- The `err` from `.Call()` is Go's error, not Windows error

**Error Code Check**:
```go
if lastErr == ERROR_ACCESS_DENIED {
    return 0, fmt.Errorf("ACCESS DENIED (Error 5)")
}
```

- Specifically checks for error code 5
- This is the most common failure for insufficient privileges

### TryReadMemory

```go
func TryReadMemory(handle syscall.Handle, pid uint32) bool {
    var buffer [8]byte
    var bytesRead uintptr
    
    ret, _, _ := procReadProcessMemory.Call(
        uintptr(handle),
        0x10000,
        uintptr(unsafe.Pointer(&buffer[0])),
        8,
        uintptr(unsafe.Pointer(&bytesRead)),
    )
```

**API Signature**: `BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)`

**Parameter Mapping**:
1. `uintptr(handle)` → `hProcess`: Process handle from OpenProcess
2. `0x10000` → `lpBaseAddress`: Arbitrary memory address (64KB mark, usually valid in user space)
3. `uintptr(unsafe.Pointer(&buffer[0]))` → `lpBuffer`: Pointer to receive data
4. `8` → `nSize`: Number of bytes to read
5. `uintptr(unsafe.Pointer(&bytesRead))` → `lpNumberOfBytesRead`: Out parameter for bytes actually read

**Unsafe Pointer Usage**:
- `&buffer[0]` gets address of first array element
- `unsafe.Pointer()` converts Go pointer to generic pointer
- `uintptr()` converts to integer for syscall interface

**Why This Address**:
- `0x10000` (65536) is typically in executable's address space
- Below this is usually reserved/unmapped
- Not attempting to read specific data, just testing access

### TryWriteMemory

```go
func TryWriteMemory(handle syscall.Handle) bool {
    buffer := []byte{0x90, 0x90, 0x90, 0x90}
    var bytesWritten uintptr
    
    ret, _, _ := procWriteProcessMemory.Call(
        uintptr(handle),
        0x10000,
        uintptr(unsafe.Pointer(&buffer[0])),
        uintptr(len(buffer)),
        uintptr(unsafe.Pointer(&bytesWritten)),
    )
```

**API Signature**: `BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)`

**Data Being Written**:
- `{0x90, 0x90, 0x90, 0x90}` = Four NOP instructions (x86/x64)
- Choice is irrelevant since we're just testing access
- Would overwrite whatever is at 0x10000 (if successful)

**Slice to Pointer**:
```go
uintptr(unsafe.Pointer(&buffer[0]))
```
- Slices are not directly compatible with uintptr
- Must take address of first element explicitly

### TryCreateThread

```go
func TryCreateThread(handle syscall.Handle) bool {
    threadHandle, _, _ := procCreateRemoteThread.Call(
        uintptr(handle),
        0,
        0,
        0,
        0,
        0,
        0,
    )
```

**API Signature**: `HANDLE CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)`

**Parameter Mapping**:
1. `uintptr(handle)` → `hProcess`
2. `0` → `lpThreadAttributes`: NULL (default security)
3. `0` → `dwStackSize`: 0 (default stack size)
4. `0` → `lpStartAddress`: NULL (invalid - will cause error)
5. `0` → `lpParameter`: NULL
6. `0` → `dwCreationFlags`: 0 (run immediately)
7. `0` → `lpThreadId`: NULL (don't care about thread ID)

**Why NULL Start Address**:
```go
0, // null start address (will fail anyway)
```
- Not actually trying to execute code
- Just testing if API call is *allowed*
- PPL will block this before checking if address is valid

**Handle Cleanup**:
```go
if threadHandle == 0 {
    // error handling
} else {
    syscall.CloseHandle(syscall.Handle(threadHandle))
}
```
- Even on success, immediately closes the thread handle
- Prevents resource leaks

### CheckPrivilege

```go
func CheckPrivilege(privilegeName string) bool {
    var hToken syscall.Handle
    
    currentProc, _ := syscall.GetCurrentProcess()
    ret, _, _ := procOpenProcessToken.Call(
        uintptr(currentProc),
        TOKEN_QUERY,
        uintptr(unsafe.Pointer(&hToken)),
    )
```

**API Signature**: `BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)`

**Key Points**:
- `syscall.GetCurrentProcess()` returns pseudo-handle (-1/0xFFFFFFFF)
- Pseudo-handles don't need to be closed
- `TOKEN_QUERY` is sufficient to check privilege existence

**Privilege Lookup**:
```go
var luid LUID
privName, _ := syscall.UTF16PtrFromString(privilegeName)
ret, _, _ = procLookupPrivilegeValue.Call(
    0,
    uintptr(unsafe.Pointer(privName)),
    uintptr(unsafe.Pointer(&luid)),
)
```

**API Signature**: `BOOL LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid)`

**Parameters**:
1. `0` → `lpSystemName`: NULL (local system)
2. `privName` → `lpName`: Unicode string like "SeDebugPrivilege"
3. `&luid` → `lpLuid`: Output parameter receiving the LUID

**UTF-16 Conversion**:
- Windows Unicode APIs expect UTF-16LE strings
- `syscall.UTF16PtrFromString` converts Go string (UTF-8) to null-terminated UTF-16
- Returns pointer suitable for passing to Windows APIs

**Return Value**:
```go
return ret != 0
```
- Only checking if lookup succeeds
- Not actually examining the LUID value
- Success means privilege exists in token (though might be disabled)

### GetIntegrityLevel

```go
func GetIntegrityLevel() string {
    var adminSid *syscall.SID
    var ntAuthority = SID_IDENTIFIER_AUTHORITY{
        Value: [6]byte{0, 0, 0, 0, 0, 5},
    }
```

**SID Construction**:
- `{0, 0, 0, 0, 0, 5}` = NT_AUTHORITY
- Will be combined with subauthorities to form complete SID

**AllocateAndInitializeSid Call**:
```go
ret, _, _ := procAllocateAndInitializeSid.Call(
    uintptr(unsafe.Pointer(&ntAuthority)),
    2,
    SECURITY_BUILTIN_DOMAIN_RID,
    DOMAIN_ALIAS_RID_ADMINS,
    0, 0, 0, 0, 0, 0,
    uintptr(unsafe.Pointer(&adminSid)),
)
```

**API Signature**: `BOOL AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD nSubAuthority0-7, PSID *pSid)`

**Parameters**:
1. `&ntAuthority` → Authority structure
2. `2` → Number of subauthorities to use
3. `SECURITY_BUILTIN_DOMAIN_RID` (0x20) → First subauthority
4. `DOMAIN_ALIAS_RID_ADMINS` (0x220) → Second subauthority
   5-10. `0, 0, 0, 0, 0, 0` → Unused subauthorities (up to 8 total)
11. `&adminSid` → Output pointer to SID

**Resulting SID**: S-1-5-32-544 (BUILTIN\Administrators)

**Memory Management**:
```go
defer procFreeSid.Call(uintptr(unsafe.Pointer(adminSid)))
```
- `AllocateAndInitializeSid` allocates memory
- Must call `FreeSid` to prevent leak
- `defer` ensures cleanup even if function returns early

**Membership Check**:
```go
var isMember int32
ret, _, _ = procCheckTokenMembership.Call(
    0,
    uintptr(unsafe.Pointer(adminSid)),
    uintptr(unsafe.Pointer(&isMember)),
)
```

**API Signature**: `BOOL CheckTokenMembership(HANDLE TokenHandle, PSID SidToCheck, PBOOL IsMember)`

**Parameters**:
1. `0` → `TokenHandle`: NULL (uses current thread's impersonation token, or process token if not impersonating)
2. `adminSid` → SID to check membership against
3. `&isMember` → Output: non-zero if member, zero if not

**Result Interpretation**:
```go
if isMember != 0 {
    return "High (Administrator)"
}
return "Medium (Standard User)"
```
- Non-zero = current token has Administrators group
- Zero = not an administrator

### DetectPPL

```go
func DetectPPL(handle syscall.Handle, pid uint32) string {
    var buffer [1]byte
    var bytesRead uintptr
    
    ret, _, _ := procReadProcessMemory.Call(
        uintptr(handle),
        0x10000,
        uintptr(unsafe.Pointer(&buffer[0])),
        1,
        uintptr(unsafe.Pointer(&bytesRead)),
    )
```

**Detection Logic**:
- Minimal read (1 byte) to test access
- If `ReadProcessMemory` fails with ERROR_ACCESS_DENIED despite valid handle → PPL
- This is a heuristic, not definitive

**Why This Works**:
- PPL processes allow handle creation for compatibility
- But block actual dangerous operations at kernel level
- Memory read is first operation that reveals protection

**Error Checking**:
```go
if ret == 0 {
    lastErr, _, _ := procGetLastError.Call()
    if lastErr == ERROR_ACCESS_DENIED {
        return "YES - Protected Process Light (PPL)"
    }
}
```

**Limitation**:
- Doesn't distinguish between PPL and other access denials
- Could fail for other reasons (invalid address, terminated process)
- In practice, if OpenProcess succeeded but ReadProcessMemory fails with error 5, it's almost certainly PPL

### EnablePrivilege

```go
func EnablePrivilege(privilegeName string) error {
    var hToken syscall.Handle
    
    currentProc, _ := syscall.GetCurrentProcess()
    ret, _, _ := procOpenProcessToken.Call(
        uintptr(currentProc),
        TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
        uintptr(unsafe.Pointer(&hToken)),
    )
```

**Access Rights**:
- `TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY` = 0x0020 | 0x0008 = 0x0028
- Both rights needed: QUERY to check current state, ADJUST to modify

**Privilege Lookup**:
```go
var luid LUID
privName, _ := syscall.UTF16PtrFromString(privilegeName)
ret, _, _ = procLookupPrivilegeValue.Call(
    0,
    uintptr(unsafe.Pointer(privName)),
    uintptr(unsafe.Pointer(&luid)),
)
```
- Converts privilege name string to LUID
- Same as in `CheckPrivilege` but we store the LUID this time

**Structure Preparation**:
```go
tp := TOKEN_PRIVILEGES{
    PrivilegeCount: 1,
    Privileges: [1]LUID_AND_ATTRIBUTES{
        {
            Luid:       luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        },
    },
}
```

**Memory Layout**:
```
Offset  | Field                    | Size | Value
--------|--------------------------|------|--------
0x00    | PrivilegeCount           | 4    | 1
0x04    | Privileges[0].Luid.Low   | 4    | (LUID low part)
0x08    | Privileges[0].Luid.High  | 4    | (LUID high part)
0x0C    | Privileges[0].Attributes | 4    | 0x00000002
```

**AdjustTokenPrivileges Call**:
```go
ret, _, _ = procAdjustTokenPrivileges.Call(
    uintptr(hToken),
    0,
    uintptr(unsafe.Pointer(&tp)),
    0,
    0,
    0,
)
```

**API Signature**: `BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)`

**Parameters**:
1. `hToken` → Token to modify
2. `0` → `DisableAllPrivileges`: FALSE (we're enabling, not disabling all)
3. `&tp` → `NewState`: Pointer to TOKEN_PRIVILEGES structure
4. `0` → `BufferLength`: 0 (not retrieving previous state)
5. `0` → `PreviousState`: NULL (don't need previous state)
6. `0` → `ReturnLength`: NULL (don't need return length)

**Error Handling**:
```go
if ret == 0 {
    return fmt.Errorf("AdjustTokenPrivileges failed")
}

lastErr, _, _ := procGetLastError.Call()
if lastErr != 0 {
    if lastErr == 1300 {
        return fmt.Errorf("Privilege could not be assigned (not held by account)")
    }
    return fmt.Errorf("AdjustTokenPrivileges error: %d", lastErr)
}
```

**Critical Detail**:
- `AdjustTokenPrivileges` returns non-zero even for partial success
- Must check `GetLastError()` to verify complete success
- Error 1300 (`ERROR_NOT_ALL_ASSIGNED`) means privilege not in token at all
- Error 0 means complete success

---

## Main Function Flow

### Command Line Parsing

```go
if len(os.Args) < 2 {
    // usage message
    return
}

var targetPID uint32
fmt.Sscanf(os.Args[1], "%d", &targetPID)
```

**Technical Notes**:
- `os.Args[0]` = program name
- `os.Args[1]` = first argument
- `fmt.Sscanf` parses string to uint32
- No error checking (will result in targetPID=0 if invalid)

### Initial Process Open Attempt

```go
handle, err := TryOpenProcess(targetPID)

if err != nil {
    // Failed without privilege
    if integrityLevel == "High (Administrator)" {
        err := EnablePrivilege("SeDebugPrivilege")
        if err != nil {
            return
        }
        
        handle, err = TryOpenProcess(targetPID)
        // ...
    }
}
```

**Logic Flow**:
1. Try opening process first (privilege might already be enabled)
2. If fails and running as admin → enable privilege
3. Retry after enabling privilege
4. If still fails → invalid PID or protected process

### Handle Validation Loop

```go
defer syscall.CloseHandle(handle)

pplStatus := DetectPPL(handle, targetPID)
canRead := TryReadMemory(handle, targetPID)
canWrite := TryWriteMemory(handle)
canCreateThread := TryCreateThread(handle)
```

**Resource Management**:
- `defer syscall.CloseHandle(handle)` ensures handle cleanup
- Executed when function returns, even via panic
- Important to prevent handle leaks

**Test Sequence**:
1. PPL detection via memory read
2. Explicit memory read test
3. Memory write test
4. Remote thread creation test
5. (Terminate test commented out for safety)

### Results Analysis

```go
if canRead && canWrite && canCreateThread {
    // Full access - regular process
} else {
    // Limited access - PPL protected
}
```

**Boolean Logic**:
- All operations must succeed for full access
- Any failure indicates restrictions (likely PPL)

---

## Memory and Safety Considerations

### Unsafe Pointer Conversions

Throughout the code:
```go
uintptr(unsafe.Pointer(&variable))
```

**Why This Pattern**:
1. `&variable` → Go pointer (type *T)
2. `unsafe.Pointer(&variable)` → Generic pointer
3. `uintptr(...)` → Integer representation for syscall

**Safety Issues**:
- Go GC doesn't see uintptr as pointer reference
- Variable could be moved/collected between conversion and use
- Safe here because immediately used in syscall
- Would be unsafe if stored and used later

### Handle Lifecycle

```go
handle, _, err := procOpenProcess.Call(...)
// ...
defer syscall.CloseHandle(handle)
```

**Kernel Object Management**:
- Handles are kernel resources
- Must be explicitly closed
- Leaking handles can exhaust system resources
- `defer` ensures cleanup even on early returns

### Buffer Allocations

```go
var buffer [8]byte          // Stack allocation
buffer := []byte{...}       // Heap allocation (slice)
```

**Memory Location**:
- Arrays: Stack-allocated (known size)
- Slices: Header on stack, backing array on heap
- Taking address of either is safe for duration of call

---

## Error Handling Patterns

### Three-Value Syscall Returns

```go
ret, _, _ := procSomeAPI.Call(...)
```

**Return Values**:
1. `ret` (uintptr): The actual return value (BOOL, HANDLE, etc.)
2. `_` (uintptr): Unused (legacy)
3. `_` (error): Go error (often ignored, use GetLastError instead)

### Checking Windows Errors

```go
if ret == 0 {
    lastErr, _, _ := procGetLastError.Call()
    if lastErr == ERROR_ACCESS_DENIED {
        // specific handling
    }
}
```

**Pattern**:
1. Check if API failed (usually ret == 0 for BOOL, or ret == 0/INVALID_HANDLE_VALUE for handles)
2. Call GetLastError for error code
3. Compare against known error constants

### GetLastError Timing

```go
ret, _, _ := procAdjustTokenPrivileges.Call(...)
if ret == 0 {
    return fmt.Errorf("...")
}
lastErr, _, _ := procGetLastError.Call()
```

**Critical**: Call GetLastError *immediately* after the API call being checked. Any intervening Win32 API call can overwrite the error code.
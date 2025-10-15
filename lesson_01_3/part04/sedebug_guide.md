# SeDebugPrivilege Lab - Technical Code Documentation

## Overview
This document provides a detailed technical breakdown of the SeDebugPrivilege demonstration tool. Each section explains what the code does at a technical level and why specific approaches are used.

---

## Data Structures

### LUID (Locally Unique Identifier)
```go
type LUID struct {
    LowPart  uint32
    HighPart int32
}
```
**Purpose**: Represents a 64-bit value guaranteed to be unique on the local system. Windows uses LUIDs to identify privileges.
- `LowPart`: Lower 32 bits (unsigned)
- `HighPart`: Upper 32 bits (signed)

### LUID_AND_ATTRIBUTES
```go
type LUID_AND_ATTRIBUTES struct {
    Luid       LUID
    Attributes uint32
}
```
**Purpose**: Pairs a privilege LUID with its state flags.
- `Luid`: The privilege identifier
- `Attributes`: Bitfield containing flags like `SE_PRIVILEGE_ENABLED` (0x00000002)

### TOKEN_PRIVILEGES
```go
type TOKEN_PRIVILEGES struct {
    PrivilegeCount uint32
    Privileges     [1]LUID_AND_ATTRIBUTES
}
```
**Purpose**: Describes privilege information for an access token.
- `PrivilegeCount`: Number of privileges in the array
- `Privileges`: Variable-length array (declared as [1] but can be larger in memory)

**Note**: The `[1]` array size is a C-style pattern. The actual array extends beyond this declared size in the allocated memory buffer.

### MEMORY_BASIC_INFORMATION
```go
type MEMORY_BASIC_INFORMATION struct {
    BaseAddress       uintptr
    AllocationBase    uintptr
    AllocationProtect uint32
    RegionSize        uintptr
    State             uint32
    Protect           uint32
    Type              uint32
}
```
**Purpose**: Contains information about a range of pages in the virtual address space.
- `BaseAddress`: Start address of the region
- `State`: Memory state (MEM_COMMIT = 0x1000)
- `Protect`: Protection flags (PAGE_READONLY, PAGE_READWRITE, etc.)

### SID_IDENTIFIER_AUTHORITY
```go
type SID_IDENTIFIER_AUTHORITY struct {
    Value [6]byte
}
```
**Purpose**: Identifies the authority that issued a Security Identifier (SID).
- For NT Authority: `[6]byte{0, 0, 0, 0, 0, 5}`

---

## Windows API Functions

### Lazy DLL Loading
```go
kernel32 = syscall.NewLazyDLL("kernel32.dll")
advapi32 = syscall.NewLazyDLL("advapi32.dll")
```
**Purpose**: Load Windows system DLLs on-demand without explicit linking.
- `NewLazyDLL`: Creates a DLL reference that loads only when first accessed
- `NewProc`: Gets a function pointer from the DLL

### Loaded Functions
- **kernel32.dll**: Process and memory operations
    - `OpenProcess`: Obtain a handle to a process
    - `ReadProcessMemory`: Read memory from another process
    - `VirtualQueryEx`: Query virtual memory information

- **advapi32.dll**: Security and privilege operations
    - `LookupPrivilegeValueW`: Get LUID for a privilege name
    - `AdjustTokenPrivileges`: Enable/disable privileges
    - `OpenProcessToken`: Get handle to process access token
    - `GetTokenInformation`: Retrieve token information
    - `AllocateAndInitializeSid`: Create a SID
    - `CheckTokenMembership`: Check if token is member of a group
    - `FreeSid`: Release SID memory

---

## Core Functions Breakdown

### main()
**Flow**:
1. Parse command-line flags (`-pid` and `-sedebug`)
2. Check if running as Administrator
3. Enable or disable SeDebugPrivilege based on flag
4. Verify privilege state
5. Attempt to open target process
6. Test memory read capabilities
7. Display results

**Key Logic**:
```go
if *sedebug {
    EnableSeDebugPrivilege()
} else {
    DisableSeDebugPrivilege()
}
```
This allows testing both privileged and unprivileged scenarios.

---

### IsAdmin()
**Purpose**: Determines if the current process is running with administrator privileges.

**Technical Process**:
1. **Create Administrator SID**:
   ```go
   ntAuthority := SID_IDENTIFIER_AUTHORITY{Value: [6]byte{0, 0, 0, 0, 0, 5}}
   ```
   NT Authority identifier = 5

2. **Allocate SID**:
   ```go
   procAllocateAndInitializeSid.Call(
       uintptr(unsafe.Pointer(&ntAuthority)),
       2,  // Sub-authority count
       SECURITY_BUILTIN_DOMAIN_RID,  // 0x20
       DOMAIN_ALIAS_RID_ADMINS,      // 0x220
       ...
   )
   ```
   Creates SID: S-1-5-32-544 (BUILTIN\Administrators)

3. **Check Membership**:
   ```go
   procCheckTokenMembership.Call(
       0,  // NULL = current thread token
       uintptr(unsafe.Pointer(adminSid)),
       uintptr(unsafe.Pointer(&isMember)),
   )
   ```
   Returns non-zero in `isMember` if token belongs to Administrators group.

4. **Cleanup**:
   ```go
   defer procFreeSid.Call(uintptr(unsafe.Pointer(adminSid)))
   ```
   Releases allocated SID memory.

---

### HasSeDebugPrivilege()
**Purpose**: Checks if SeDebugPrivilege is currently enabled in the process token.

**Technical Process**:
1. **Open Current Process Token**:
   ```go
   proc, _ := syscall.GetCurrentProcess()
   procOpenProcessToken.Call(uintptr(proc), TOKEN_QUERY, ...)
   ```
   Gets handle to current process's access token with query rights.

2. **Lookup SeDebugPrivilege LUID**:
   ```go
   privName, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
   procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(privName)), ...)
   ```
   Converts privilege name to its LUID representation.

3. **Query Token Privileges**:
   ```go
   procGetTokenInformation.Call(uintptr(token), TokenPrivileges, 0, 0, ...)
   ```
   First call with NULL buffer gets required buffer size in `returnLength`.

4. **Allocate and Retrieve**:
   ```go
   privBuffer := make([]byte, returnLength)
   procGetTokenInformation.Call(..., uintptr(unsafe.Pointer(&privBuffer[0])), ...)
   ```
   Second call populates buffer with all token privileges.

5. **Parse and Search**:
   ```go
   tokenPrivs := (*TOKEN_PRIVILEGES)(unsafe.Pointer(&privBuffer[0]))
   privArray := (*[1000]LUID_AND_ATTRIBUTES)(unsafe.Pointer(&tokenPrivs.Privileges[0]))
   ```
   Casts buffer to structure and treats privilege array as large fixed array for indexing.

6. **Check Enable Status**:
   ```go
   if privArray[i].Luid == luid {
       return (privArray[i].Attributes & SE_PRIVILEGE_ENABLED) != 0
   }
   ```
   Bitwise AND to check if SE_PRIVILEGE_ENABLED flag is set.

---

### EnableSeDebugPrivilege()
**Purpose**: Enables SeDebugPrivilege in the current process token.

**Technical Process**:
1. **Open Token with Adjust Rights**:
   ```go
   procOpenProcessToken.Call(
       uintptr(proc),
       TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
       ...
   )
   ```
   Requires both adjust and query rights.

2. **Lookup Privilege LUID**:
   ```go
   procLookupPrivilegeValue.Call(...)
   ```
   Same as HasSeDebugPrivilege().

3. **Build TOKEN_PRIVILEGES Structure**:
   ```go
   tp := TOKEN_PRIVILEGES{
       PrivilegeCount: 1,
       Privileges: [1]LUID_AND_ATTRIBUTES{
           {Luid: luid, Attributes: SE_PRIVILEGE_ENABLED},
       },
   }
   ```
   Sets the enable flag (0x00000002).

4. **Adjust Token**:
   ```go
   procAdjustTokenPrivileges.Call(
       uintptr(token),
       0,  // Do not disable all
       uintptr(unsafe.Pointer(&tp)),
       ...
   )
   ```
   Modifies token to enable the specified privilege.

---

### DisableSeDebugPrivilege()
**Purpose**: Disables SeDebugPrivilege in the current process token.

**Technical Difference**:
```go
tp := TOKEN_PRIVILEGES{
    PrivilegeCount: 1,
    Privileges: [1]LUID_AND_ATTRIBUTES{
        {Luid: luid, Attributes: 0},  // Attributes = 0 (disabled)
    },
}
```
Sets attributes to 0 instead of `SE_PRIVILEGE_ENABLED`.

---

### OpenProcess()
**Purpose**: Obtains a handle to the target process.

**Technical Details**:
```go
procOpenProcess.Call(
    uintptr(PROCESS_ALL_ACCESS),  // 0x001F0FFF - full access rights
    0,                             // bInheritHandle = FALSE
    uintptr(pid),                  // Target process ID
)
```

**Access Rights Breakdown** (PROCESS_ALL_ACCESS):
- PROCESS_TERMINATE
- PROCESS_CREATE_THREAD
- PROCESS_VM_OPERATION
- PROCESS_VM_READ
- PROCESS_VM_WRITE
- PROCESS_DUP_HANDLE
- PROCESS_CREATE_PROCESS
- PROCESS_SET_QUOTA
- PROCESS_SET_INFORMATION
- PROCESS_QUERY_INFORMATION
- PROCESS_SUSPEND_RESUME
- DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, SYNCHRONIZE

**Result**: Returns handle on success, 0 on failure.

---

### FindValidMemory()
**Purpose**: Locates a readable memory region in the target process.

**Technical Process**:
1. **Iterate Address Space**:
   ```go
   for address < 0x7FFFFFFF {
   ```
   Scans user-mode address space (up to ~2GB on 32-bit, adjusted for 64-bit).

2. **Query Memory Region**:
   ```go
   procVirtualQueryEx.Call(
       uintptr(handle),
       address,
       uintptr(unsafe.Pointer(&mbi)),
       unsafe.Sizeof(mbi),
   )
   ```
   Fills `MEMORY_BASIC_INFORMATION` structure with region details.

3. **Check Validity**:
   ```go
   if mbi.State == MEM_COMMIT &&
      (mbi.Protect == PAGE_READONLY ||
       mbi.Protect == PAGE_READWRITE ||
       mbi.Protect == PAGE_EXECUTE_READ ||
       mbi.Protect == PAGE_EXECUTE_READWRITE)
   ```
   Looks for committed memory with readable protection flags.

4. **Advance Address**:
   ```go
   address = mbi.BaseAddress + mbi.RegionSize
   ```
   Jumps to next region boundary.

**Return**: Base address of first valid region, or 0 if none found.

---

### CanReadMemory()
**Purpose**: Verifies ability to read from target process memory.

**Technical Process**:
1. **Find Valid Address**:
   ```go
   addr := FindValidMemory(handle)
   ```

2. **Attempt Read**:
   ```go
   procReadProcessMemory.Call(
       uintptr(handle),
       addr,
       uintptr(unsafe.Pointer(&buffer[0])),
       8,  // Read 8 bytes
       uintptr(unsafe.Pointer(&bytesRead)),
   )
   ```

3. **Verify Success**:
   ```go
   return ret != 0 && bytesRead > 0
   ```
   Both return value and bytes read must be non-zero.

**Why This Works**:
- With SeDebugPrivilege: Can open protected processes and read memory
- Without SeDebugPrivilege: OpenProcess or ReadProcessMemory fails for protected processes

---

## Memory Safety and Unsafe Operations

### Pointer Conversions
The code extensively uses `unsafe.Pointer` to interface with Windows APIs:

```go
uintptr(unsafe.Pointer(&variable))
```

**Explanation**:
1. `&variable` - Get Go pointer
2. `unsafe.Pointer()` - Convert to unsafe pointer (type erasure)
3. `uintptr()` - Convert to integer suitable for syscall

**Warning**: This breaks Go's memory safety guarantees. Required for syscalls.

### Structure Casting
```go
tokenPrivs := (*TOKEN_PRIVILEGES)(unsafe.Pointer(&privBuffer[0]))
```
**Purpose**: Reinterpret byte slice as structured data returned from Windows API.

### Variable-Length Arrays
```go
privArray := (*[1000]LUID_AND_ATTRIBUTES)(unsafe.Pointer(&tokenPrivs.Privileges[0]))
```
**Technique**: Cast to large fixed array to enable indexing beyond declared [1] size.

---

## Flag Processing and Constants

### Protection Flags
- `PAGE_READONLY` (0x02): Read-only access
- `PAGE_READWRITE` (0x04): Read and write access
- `PAGE_EXECUTE_READ` (0x20): Execute and read access
- `PAGE_EXECUTE_READWRITE` (0x40): Execute, read, and write access

### Memory State
- `MEM_COMMIT` (0x1000): Memory is allocated and backed by physical storage or page file

### Token Rights
- `TOKEN_QUERY` (0x0008): Query token information
- `TOKEN_ADJUST_PRIVILEGES` (0x0020): Modify token privileges

### Process Access
- `PROCESS_ALL_ACCESS` (0x001F0FFF): All possible access rights to a process

---

## Error Handling Patterns

### Syscall Return Values
```go
ret, _, _ := procOpenProcess.Call(...)
if ret == 0 {
    return fmt.Errorf("access denied")
}
```
Windows APIs typically return 0 on failure, non-zero on success.

### Resource Cleanup
```go
defer syscall.CloseHandle(token)
defer procFreeSid.Call(...)
```
Uses `defer` to ensure handles and memory are released even on early returns.

---

## Key Technical Insights

### Why SeDebugPrivilege Matters
1. **Normal Process Access**: Restricted by process security descriptors
2. **With SeDebugPrivilege**: Bypasses most security checks in OpenProcess()
3. **Limitations**: Some processes (PPL - Protected Process Light) still resist access

### Two-Stage Buffer Query Pattern
```go
// Stage 1: Get size
procGetTokenInformation.Call(..., 0, 0, uintptr(unsafe.Pointer(&returnLength)))
// Stage 2: Get data
privBuffer := make([]byte, returnLength)
procGetTokenInformation.Call(..., uintptr(unsafe.Pointer(&privBuffer[0])), ...)
```
Common Windows API pattern when buffer size is unknown.

### Admin vs SeDebugPrivilege
- **IsAdmin()**: Checks group membership (who you are)
- **HasSeDebugPrivilege()**: Checks enabled privilege (what you can do)
- An admin can have the privilege but not enabled until explicitly adjusted

### Memory Scanning Strategy
The `FindValidMemory()` function walks the virtual address space region by region rather than byte by byte, which is efficient because:
1. Memory is organized in contiguous regions
2. `VirtualQueryEx` returns entire region properties
3. Can skip unmapped or protected regions quickly

---
tes the impact of SeDebugPrivilege on process access capabilities.
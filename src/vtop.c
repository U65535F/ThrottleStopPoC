#include "vtop.h"

typedef struct MemoryRange {
    ULONGLONG pfn;
    size_t pageCount;
} MemoryRange;

typedef struct MemoryTranslation {
    const void* virtualAddress;
    ULONGLONG physicalAddress;
} MemoryTranslation;

static MemoryRange* g_MemoryRanges = NULL;
static size_t g_MemoryRangeCount = 0;
static size_t g_MemoryRangeCapacity = 0;

static MemoryTranslation* g_MemoryTranslations = NULL;
static size_t g_MemoryTranslationCount = 0;
static size_t g_MemoryTranslationCapacity = 0;

BOOL EnsureMemoryRangeCapacity(size_t required) {
    if (required <= g_MemoryRangeCapacity)
        return TRUE;

    size_t newCapacity = g_MemoryRangeCapacity ? g_MemoryRangeCapacity * 2 : 128;
    while (newCapacity < required)
        newCapacity *= 2;

    MemoryRange* newPtr;
    if (g_MemoryRanges == NULL)
        newPtr = (MemoryRange*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newCapacity * sizeof(MemoryRange));
    else
        newPtr = (MemoryRange*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, g_MemoryRanges, newCapacity * sizeof(MemoryRange));
    if (!newPtr) 
        return FALSE;

    g_MemoryRanges = newPtr;
    g_MemoryRangeCapacity = newCapacity;
    return TRUE;
}

BOOL EnsureMemoryTranslationCapacity(size_t required) {
    if (required <= g_MemoryTranslationCapacity)
        return TRUE;

    size_t newCapacity = g_MemoryTranslationCapacity ? g_MemoryTranslationCapacity * 2 : 1024;
    while (newCapacity < required)
        newCapacity *= 2;

    MemoryTranslation* newPtr;
    if (g_MemoryTranslations == NULL)
        newPtr = (MemoryTranslation*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newCapacity * sizeof(MemoryTranslation));
    else
        newPtr = (MemoryTranslation*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, g_MemoryTranslations, newCapacity * sizeof(MemoryTranslation));
    if (!newPtr) return FALSE;

    g_MemoryTranslations = newPtr;
    g_MemoryTranslationCapacity = newCapacity;
    return TRUE;
}


NTSTATUS AcquireRequiredPrivileges() {
    BOOLEAN old = FALSE;
    NTSTATUS status = RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &old);
    if (!NT_SUCCESS(status))
        return status;

    status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &old);
    if (!NT_SUCCESS(status))
        return status;

    return status;
}

NTSTATUS QuerySuperfetchInfo(SUPERFETCH_INFORMATION_CLASS infoClass, PVOID buffer, ULONG length, PULONG returnLength) {
    SUPERFETCH_INFORMATION superfetchInfo = {
        .Version = 45,
        .Magic = 'kuhC',
        .InfoClass = infoClass,
        .Data = buffer,
        .Length = length
    };

    return NtQuerySystemInformation(SystemSuperfetchInformation, &superfetchInfo, sizeof(superfetchInfo), returnLength);
}


static NTSTATUS QueryMemoryRangesV1() {
    ULONG bufferLength = 0;
    PF_MEMORY_RANGE_INFO_V1 probe = { .Version = 1 };
    NTSTATUS status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery, &probe, sizeof(probe), &bufferLength);
    if (status != STATUS_BUFFER_TOO_SMALL)
        return status;

    PF_MEMORY_RANGE_INFO_V1* memoryRangeInfo = (PF_MEMORY_RANGE_INFO_V1*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLength);
    if (!memoryRangeInfo)
        return STATUS_MEMORY_NOT_ALLOCATED;

    memoryRangeInfo->Version = 1;
    status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery, memoryRangeInfo, bufferLength, NULL);
    if (!NT_SUCCESS(status))
        return status;

    g_MemoryRangeCount = 0;
    for (ULONG i = 0; i < memoryRangeInfo->RangeCount; i++) {
        if (!EnsureMemoryRangeCapacity(g_MemoryRangeCount + 1))
            return STATUS_MEMORY_NOT_ALLOCATED;
        g_MemoryRanges[g_MemoryRangeCount].pfn = memoryRangeInfo->Ranges[i].BasePfn;
        g_MemoryRanges[g_MemoryRangeCount].pageCount = memoryRangeInfo->Ranges[i].PageCount;
        g_MemoryRangeCount++;
    }

    HeapFree(GetProcessHeap(), 0, memoryRangeInfo);
    return STATUS_SUCCESS;
}

static NTSTATUS QueryMemoryRangesV2() {
    ULONG bufferLength = 0;

    PF_MEMORY_RANGE_INFO_V2 probe = { .Version = 2 };
    NTSTATUS status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery, &probe, sizeof(probe), &bufferLength);
    if (status != STATUS_BUFFER_TOO_SMALL)
        return status;

    PF_MEMORY_RANGE_INFO_V2* memoryRangeInfo = (PF_MEMORY_RANGE_INFO_V2*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLength);
    if (!memoryRangeInfo)
        return STATUS_MEMORY_NOT_ALLOCATED;

    memoryRangeInfo->Version = 2;
    status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery, memoryRangeInfo, bufferLength, NULL);
    if (!NT_SUCCESS(status))
        return status;

    g_MemoryRangeCount = 0;
    for (ULONG i = 0; i < memoryRangeInfo->RangeCount; i++) {
        if (!EnsureMemoryRangeCapacity(g_MemoryRangeCount + 1))
            return STATUS_MEMORY_NOT_ALLOCATED;
        g_MemoryRanges[g_MemoryRangeCount].pfn = memoryRangeInfo->Ranges[i].BasePfn;
        g_MemoryRanges[g_MemoryRangeCount].pageCount = memoryRangeInfo->Ranges[i].PageCount;
        g_MemoryRangeCount++;
    }

    HeapFree(GetProcessHeap(), 0, memoryRangeInfo);
    return STATUS_SUCCESS;
}

NTSTATUS BuildMemoryMap() {
    NTSTATUS status = AcquireRequiredPrivileges();
    if (!NT_SUCCESS(status))
        return status;

    if (!NT_SUCCESS(QueryMemoryRangesV1())) {
        status = QueryMemoryRangesV2();
        if (!NT_SUCCESS(status))
            return status;
    }

    g_MemoryTranslationCount = 0;
    for (size_t r = 0; r < g_MemoryRangeCount; r++) {
        ULONGLONG basePfn = g_MemoryRanges[r].pfn;
        size_t pageCount = g_MemoryRanges[r].pageCount;

        size_t bufferLength = sizeof(PF_PFN_PRIO_REQUEST) + sizeof(MMPFN_IDENTITY) * pageCount;
        PF_PFN_PRIO_REQUEST* request = (PF_PFN_PRIO_REQUEST*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLength);
        if (!request) 
            return STATUS_MEMORY_NOT_ALLOCATED;

        request->Version = request->RequestFlags = 1;
        request->PfnCount = pageCount;

        for (ULONGLONG i = 0; i < pageCount; i++)
            request->PageData[i].PageFrameIndex = basePfn + i;

        status = QuerySuperfetchInfo(SuperfetchPfnQuery, request, (ULONG)bufferLength, NULL);
        if (!NT_SUCCESS(status)) {
            HeapFree(GetProcessHeap(), 0, request);
            return status;
        }

        for (ULONGLONG i = 0; i < pageCount; i++) {
            if (request->PageData[i].u2.VirtualAddress) {
                if (!EnsureMemoryTranslationCapacity(g_MemoryTranslationCount + 1)) {
                    HeapFree(GetProcessHeap(), 0, request);
                    return STATUS_MEMORY_NOT_ALLOCATED;
                }
                g_MemoryTranslations[g_MemoryTranslationCount].virtualAddress = request->PageData[i].u2.VirtualAddress;
                g_MemoryTranslations[g_MemoryTranslationCount].physicalAddress = (basePfn + i) << 12;
                g_MemoryTranslationCount++;
            }
        }
		HeapFree(GetProcessHeap(), 0, request);
    }

    return STATUS_SUCCESS;
}

ULONGLONG vtop(ULONGLONG address) {
    const void* alignedAddress = (const void*)(address & ~0xFFFULL);

    for (size_t i = 0; i < g_MemoryTranslationCount; i++) {
        if (g_MemoryTranslations[i].virtualAddress == alignedAddress)
            return g_MemoryTranslations[i].physicalAddress + (address & 0xFFF);
    }

    return 0;
}

void FreeMemoryMaps() {
    if (g_MemoryRanges) {
        HeapFree(GetProcessHeap(), 0, g_MemoryRanges);
        g_MemoryRanges = NULL;
        g_MemoryRangeCapacity = g_MemoryRangeCount = 0;
    }
    if (g_MemoryTranslations) {
        HeapFree(GetProcessHeap(), 0, g_MemoryTranslations);
        g_MemoryTranslations = NULL;
        g_MemoryTranslationCapacity = g_MemoryTranslationCount = 0;
    }
}

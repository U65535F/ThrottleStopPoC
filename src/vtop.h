#pragma once
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef enum SUPERFETCH_INFORMATION_CLASS {
    SuperfetchRetrieveTrace = 1,        // Query
    SuperfetchSystemParameters = 2,     // Query
    SuperfetchLogEvent = 3,             // Set
    SuperfetchGenerateTrace = 4,        // Set
    SuperfetchPrefetch = 5,             // Set
    SuperfetchPfnQuery = 6,             // Query
    SuperfetchPfnSetPriority = 7,       // Set
    SuperfetchPrivSourceQuery = 8,      // Query
    SuperfetchSequenceNumberQuery = 9,  // Query
    SuperfetchScenarioPhase = 10,       // Set
    SuperfetchWorkerPriority = 11,      // Set
    SuperfetchScenarioQuery = 12,       // Query
    SuperfetchScenarioPrefetch = 13,    // Set
    SuperfetchRobustnessControl = 14,   // Set
    SuperfetchTimeControl = 15,         // Set
    SuperfetchMemoryListQuery = 16,     // Query
    SuperfetchMemoryRangesQuery = 17,   // Query
    SuperfetchTracingControl = 18,      // Set
    SuperfetchTrimWhileAgingControl = 19,
    SuperfetchInformationMax = 20
} SUPERFETCH_INFORMATION_CLASS;

typedef struct SUPERFETCH_INFORMATION {
    ULONG Version;
    ULONG Magic;
    SUPERFETCH_INFORMATION_CLASS InfoClass;
    PVOID Data;
    ULONG Length;
} SUPERFETCH_INFORMATION;

typedef struct MEMORY_FRAME_INFORMATION {
    ULONGLONG UseDescription : 4;
    ULONGLONG ListDescription : 3;
    ULONGLONG Reserved0 : 1;
    ULONGLONG Pinned : 1;
    ULONGLONG DontUse : 48;
    ULONGLONG Priority : 3;
    ULONGLONG Reserved : 4;
} MEMORY_FRAME_INFORMATION;

typedef struct FILEOFFSET_INFORMATION {
    ULONGLONG DontUse : 9;
    ULONGLONG Offset : 48;
    ULONGLONG Reserved : 7;
} FILEOFFSET_INFORMATION;

typedef struct PAGEDIR_INFORMATION {
    ULONGLONG DontUse : 9;
    ULONGLONG PageDirectoryBase : 48;
    ULONGLONG Reserved : 7;
} PAGEDIR_INFORMATION;

typedef struct UNIQUE_PROCESS_INFORMATION {
    ULONGLONG DontUse : 9;
    ULONGLONG UniqueProcessKey : 48;
    ULONGLONG Reserved : 7;
} UNIQUE_PROCESS_INFORMATION;

typedef struct MMPFN_IDENTITY {
    union {
        MEMORY_FRAME_INFORMATION   e1;
        FILEOFFSET_INFORMATION     e2;
        PAGEDIR_INFORMATION        e3;
        UNIQUE_PROCESS_INFORMATION e4;
    } u1;
    SIZE_T PageFrameIndex;
    union {
        struct {
            ULONG Image : 1;
            ULONG Mismatch : 1;
        } e1;
        PVOID FileObject;
        PVOID UniqueFileObjectKey;
        PVOID ProtoPteAddress;
        PVOID VirtualAddress;
    } u2;
} MMPFN_IDENTITY;

typedef struct SYSTEM_MEMORY_LIST_INFORMATION {
    SIZE_T ZeroPageCount;
    SIZE_T FreePageCount;
    SIZE_T ModifiedPageCount;
    SIZE_T ModifiedNoWritePageCount;
    SIZE_T BadPageCount;
    SIZE_T PageCountByPriority[8];
    SIZE_T RepurposedPagesByPriority[8];
    ULONG_PTR ModifiedPageCountPageFile;
} SYSTEM_MEMORY_LIST_INFORMATION;

typedef struct PF_PFN_PRIO_REQUEST {
    ULONG Version;
    ULONG RequestFlags;
    SIZE_T PfnCount;
    SYSTEM_MEMORY_LIST_INFORMATION MemInfo;
    MMPFN_IDENTITY PageData[ANYSIZE_ARRAY];
} PF_PFN_PRIO_REQUEST;

typedef struct PF_PHYSICAL_MEMORY_RANGE {
    ULONG_PTR BasePfn;
    ULONG_PTR PageCount;
} PF_PHYSICAL_MEMORY_RANGE;

// always set the Version field to 1 or 2 before use
typedef struct PF_MEMORY_RANGE_INFO_V1 {
    ULONG Version;
    ULONG RangeCount;
    PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY];
} PF_MEMORY_RANGE_INFO_V1;

typedef struct PF_MEMORY_RANGE_INFO_V2 {
    ULONG Version;
    ULONG Flags;
    ULONG RangeCount;
    PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY];
} PF_MEMORY_RANGE_INFO_V2;

#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13
#define SE_DEBUG_PRIVILEGE 20

#define SystemSuperfetchInformation (SYSTEM_INFORMATION_CLASS)79

NTSYSAPI NTSTATUS RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
NTSTATUS BuildMemoryMap();
ULONGLONG vtop(ULONGLONG address);
void FreeMemoryMaps();
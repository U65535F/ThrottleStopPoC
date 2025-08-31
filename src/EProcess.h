#pragma once
#include "vtop.h"
#include "Exploit.h"
#include <PsApi.h>

#define EP_UNIQUEPID_OFFSET   0x1D0ULL
#define EP_ACTIVELINKS_OFFSET 0x1D8ULL

ULONGLONG GetEprocessFromPid(DWORD pid);
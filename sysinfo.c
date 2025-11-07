// sysinfo.c
// Compilar: veja instruções no README abaixo
#include <ws2tcpip.h>   // getnameinfo, NI_NUMERICHOST, sockaddr
#include <iphlpapi.h>
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <windows.h>
#include <time.h>
#include <intrin.h>
#include <psapi.h>
#include <setupapi.h>
#include <tchar.h>
#include <winreg.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "setupapi.lib")

// Helpers para escrita
static FILE *out = NULL;
void w(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    fflush(out);
    va_end(ap);
}

void separator() {
    w("\n------------------------------------------------------------\n\n");
}

// Timestamp filename
void create_output_file() {
    time_t t = time(NULL);
    struct tm tm;
    localtime_s(&tm, &t);
    char fname[128];
    snprintf(fname, sizeof(fname), "sysinfo_%04d%02d%02d_%02d%02d%02d.txt",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec);
    out = fopen(fname, "w");
    if (!out) {
        fprintf(stderr, "Erro ao criar arquivo %s\n", fname);
        exit(1);
    }
    w("System info generated on: %s\n\n", asctime(&tm));
}

// System / OS info
void collect_system_info() {
    w("== System / OS Info ==\n");
    // Computer name
    char compname[256];
    DWORD sz = sizeof(compname);
    if (GetComputerNameA(compname, &sz)) {
        w("Computer Name: %s\n", compname);
    }

    // Username
    char username[256];
    DWORD usz = sizeof(username);
    if (GetUserNameA(username, &usz)) {
        w("User: %s\n", username);
    }

    // OS version via RtlGetVersion (fallback to GetVersionEx deprecated)
    typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (hNt) {
        RtlGetVersionPtr fn = (RtlGetVersionPtr)GetProcAddress(hNt, "RtlGetVersion");
        if (fn) {
            RTL_OSVERSIONINFOW rovi;
            ZeroMemory(&rovi, sizeof(rovi));
            rovi.dwOSVersionInfoSize = sizeof(rovi);
            if (fn(&rovi) == 0) {
                w("OS: Windows %d.%d (Build %d) - %ls\n",
                    rovi.dwMajorVersion, rovi.dwMinorVersion,
                    rovi.dwBuildNumber, rovi.szCSDVersion);
            }
        }
    }

    // System info
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    w("Processor Architecture: %u\n", si.wProcessorArchitecture);
    w("Number of Processors: %u\n", si.dwNumberOfProcessors);
    w("Page size: %u\n", si.dwPageSize);

    // Memory
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        w("Total Physical Memory (MB): %llu\n", ms.ullTotalPhys / (1024ULL * 1024ULL));
        w("Available Physical Memory (MB): %llu\n", ms.ullAvailPhys / (1024ULL * 1024ULL));
        w("Memory Load (%%): %lu\n", ms.dwMemoryLoad);
    }
    separator();
}

// CPU info via CPUID
void collect_cpu_info() {
    w("== CPU Info ==\n");
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    int nIds = cpuInfo[0];
    char vendor[0x20] = { 0 };
    ((int*)vendor)[0] = cpuInfo[1]; // EBX
    ((int*)vendor)[1] = cpuInfo[3]; // EDX
    ((int*)vendor)[2] = cpuInfo[2]; // ECX
    w("CPU vendor: %s\n", vendor);

    // Get brand string
    char brand[0x40] = { 0 };
    if (nIds >= 0x80000004) {
        int regs[4];
        __cpuid(regs, 0x80000002);
        memcpy(brand, regs, sizeof(regs));
        __cpuid(regs, 0x80000003);
        memcpy(brand + 16, regs, sizeof(regs));
        __cpuid(regs, 0x80000004);
        memcpy(brand + 32, regs, sizeof(regs));
        w("CPU brand: %s\n", brand);
    }

    // Features
    __cpuid(cpuInfo, 1);
    unsigned int edx = cpuInfo[3];
    unsigned int ecx = cpuInfo[2];
    w("Features (ecx): 0x%08x\n", ecx);
    w("Features (edx): 0x%08x\n", edx);

    separator();
}

// Disks and volumes
void collect_disk_info() {
    w("== Disk / Volume Info ==\n");
    DWORD mask = GetLogicalDrives();
    if (!mask) {
        w("GetLogicalDrives failed.\n");
        separator();
        return;
    }
    for (int i = 0; i < 26; ++i) {
        if (mask & (1 << i)) {
            char root[] = { 'A' + i, ':', '\\', 0 };
            ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
            if (GetDiskFreeSpaceExA(root, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
                w("Drive %c: Total GB: %llu, Free GB: %llu\n",
                    'A' + i,
                    totalNumberOfBytes.QuadPart / (1024ULL * 1024ULL * 1024ULL),
                    totalNumberOfFreeBytes.QuadPart / (1024ULL * 1024ULL * 1024ULL));
            }
            char volName[MAX_PATH] = { 0 };
            char fsName[MAX_PATH] = { 0 };
            DWORD serial = 0, maxCompLen = 0, fsFlags = 0;
            if (GetVolumeInformationA(root, volName, sizeof(volName), &serial, &maxCompLen, &fsFlags, fsName, sizeof(fsName))) {
                w("  Volume label: %s, FS: %s\n", volName, fsName);
            }
        }
    }
    separator();
}

// Network adapters
// Network adapters
void collect_network_info() {
    w("== Network Adapters ==\n");

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    ULONG outBufLen = 15000;
    IP_ADAPTER_ADDRESSES *pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    DWORD rv = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);

    if (rv == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        rv = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
    }

    if (rv == NO_ERROR) {
        IP_ADAPTER_ADDRESSES *pCurr = pAddresses;
        while (pCurr) {
            w("Adapter: %ls\n", pCurr->FriendlyName);
            w("  Description: %ls\n", pCurr->Description);
            w("  Physical Address: ");

            for (unsigned int i = 0; i < pCurr->PhysicalAddressLength; i++) {
                w(i == pCurr->PhysicalAddressLength - 1 ?
                    "%02X\n" : "%02X-", pCurr->PhysicalAddress[i]);
            }

            IP_ADAPTER_UNICAST_ADDRESS *pUnicast = pCurr->FirstUnicastAddress;
            while (pUnicast) {
                char addrBuf[128];
                getnameinfo(
                    pUnicast->Address.lpSockaddr,
                    pUnicast->Address.iSockaddrLength,
                    addrBuf, sizeof(addrBuf), NULL, 0,
                    NI_NUMERICHOST
                );
                w("  IP: %s\n", addrBuf);
                pUnicast = pUnicast->Next;
            }

            w("\n");
            pCurr = pCurr->Next;
        }
    } else {
        w("GetAdaptersAddresses failed. Code: %lu\n", rv);
    }

    if (pAddresses) free(pAddresses);
    WSACleanup();
    separator();
}


// Loaded drivers via PSAPI
void collect_loaded_drivers() {
    w("== Loaded Drivers (psapi) ==\n");
    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        int cDrivers = cbNeeded / sizeof(drivers[0]);
        for (int i = 0; i < cDrivers; i++) {
            char szDriver[1024];
            if (GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver))) {
                w("%s\n", szDriver);
            }
        }
    } else {
        w("EnumDeviceDrivers failed or returned too many drivers.\n");
    }
    separator();
}

// Devices via SetupAPI (list all present device instances)
void collect_devices_setupapi() {
    w("== Devices (SetupAPI) ==\n");
    HDEVINFO hDevInfo = SetupDiGetClassDevsA(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        w("SetupDiGetClassDevs failed.\n");
        separator();
        return;
    }
    SP_DEVINFO_DATA devInfoData;
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        CHAR buffer[1024];
        if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_DEVICEDESC, NULL, (PBYTE)buffer, sizeof(buffer), NULL)) {
            w("Device: %s\n", buffer);
        }
        // driver/service name
        if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_SERVICE, NULL, (PBYTE)buffer, sizeof(buffer), NULL)) {
            w("  Service/Driver: %s\n", buffer);
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    separator();
}

// Installed services (brief)
void collect_services() {
    w("== Services (brief) ==\n");
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        w("OpenSCManager failed (need privileges?).\n");
        separator();
        return;
    }
    DWORD bytesNeeded = 0, servicesReturned = 0, resume = 0;
    // call once to get size
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, &resume, NULL);
    BYTE *buf = (BYTE*)malloc(bytesNeeded + 10);
    if (EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf, bytesNeeded, &bytesNeeded, &servicesReturned, &resume, NULL)) {
        ENUM_SERVICE_STATUS_PROCESSA *p = (ENUM_SERVICE_STATUS_PROCESSA*)buf;
        for (DWORD i = 0; i < servicesReturned; ++i) {
            w("Service: %s (Status: %lu)\n", p[i].lpServiceName, p[i].ServiceStatusProcess.dwCurrentState);
        }
    } else {
        w("EnumServicesStatusEx failed.\n");
    }
    if (buf) free(buf);
    CloseServiceHandle(scm);
    separator();
}

// Registry basic info: WindowsProductName if available
void collect_registry_info() {
    w("== Registry (basic) ==\n");
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        CHAR prodName[256]; DWORD sz = sizeof(prodName);
        if (RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)prodName, &sz) == ERROR_SUCCESS) {
            w("ProductName: %s\n", prodName);
        }
        RegCloseKey(hKey);
    } else {
        w("Failed to open registry key CurrentVersion\n");
    }
    separator();
}

int main() {
    create_output_file();
    w("SysInfo tool by Zer0G0ld (example)\n\n");

    collect_system_info();
    collect_cpu_info();
    collect_disk_info();
    collect_network_info();
    collect_loaded_drivers();
    collect_devices_setupapi();
    collect_services();
    collect_registry_info();

    w("\n== End of Report ==\n");
    fclose(out);
    printf("Relatório gerado com sucesso.\n");
    return 0;
}

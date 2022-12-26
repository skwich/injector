#include <iostream>
#include <format>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

std::string GetDirectory()
{
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    return std::string(buffer).substr(0, pos);
}

DWORD GetProcID(const char* procname)
{
    DWORD procID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, procID);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(entry);

        if (Process32First(hSnap, &entry))
        {
            do
            {
                if (!strcmp(entry.szExeFile, procname))
                {
                    procID = entry.th32ProcessID;
                    std::cout << std::format("Process ID:{}", procID) << std::endl;
                    break;
                }
            } while (Process32Next(hSnap, &entry));
        }
    }
    CloseHandle(hSnap);
    return procID;
}

BOOL InjectDll(DWORD procID, const char* dllpath)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (hProc == INVALID_HANDLE_VALUE)
    {
        std::cout << "[!] hProc has invalid handle!" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    void* loc = VirtualAllocEx(hProc, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    bool WPM = WriteProcessMemory(hProc, loc, dllpath, strlen(dllpath) + 1, NULL);
    if (!WPM)
    {
        std::cout << "[!] Dll injected failure!" << std::endl;
        CloseHandle(hProc);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, NULL, NULL);
    if (hThread == INVALID_HANDLE_VALUE)
    {
        std::cout << "[!] hThread has invalid handle!" << std::endl;
        VirtualFree(loc, strlen(dllpath) + 1, MEM_RELEASE);
        CloseHandle(hThread);
        return false;
    }

    std::cout << "Dll injected successfuly!" << std::endl;
    VirtualFree(loc, strlen(dllpath) + 1, MEM_RELEASE);
    CloseHandle(hProc);
    CloseHandle(hThread);
    return true;
}

int main()
{    
    std::string procname = "ac_client.exe",
                path = GetDirectory(),
                dllpath = path + "\\lavahack.dll";

    if (!PathFileExistsA(dllpath.c_str()))
    {
        std::cout << "[!] DLL not found!" << std::endl;
        system("pause");
        return EXIT_FAILURE;
    }

    DWORD procID = GetProcID(procname.c_str());
    if (procID == NULL)
    {
        system("cls");
        std::cout << "[!] Process not found!" << std::endl;
        system("pause");
        return EXIT_FAILURE;
    }

    if (!InjectDll(procID, dllpath.c_str()))
    {
        std::cout << "[!] Injection failure!" << std::endl;
        system("pause");
        return EXIT_FAILURE;
    }

    system("pause");
    return EXIT_SUCCESS;
}
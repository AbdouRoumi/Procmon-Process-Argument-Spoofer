#include <Windows.h>
#include <stdio.h>



BOOL ReadFromTargetProcess(IN HANDLE hProcess,IN PVOID pAddress ,OUT PVOID* ppReadBuffer,IN DWORD dwBufferSize) {
	SIZE_T sNmbrOfBytesRead = NULL;
	*ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
	if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize) {
		printf("ReadProcessMemory has failed with error : %d\n", GetLastError());
		printf("Bytes Read : %d of %d\n", sNmbrOfBytesRead,dwBufferSize);
		return FALSE;
	}
	return TRUE;
}

BOOL WriteFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, IN PVOID pBuffer, IN DWORD dwBufferSize) {

	SIZE_T sNmbrOfBytesWritten = NULL;

	if (!WriteProcessMemory(hProcess, pAddress, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
		
		printf("Write Process memory has failed with ERROR : %d\n", GetLastError());
		printf("Bytes written of %d : %d \n", sNmbrOfBytesWritten, dwBufferSize);
		return FALSE;
	}
	return TRUE;
}


BOOL 

#pragma once

#ifndef __ANTIHOOK_H__
#define __ANTIHOOK_H__

#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <winternl.h>

#include "additional.h"
#include "lycosidae.hpp"

void* __teb()
{
#ifdef _AMD64_
	return (void *)__readgsqword(0x30);
#else
  return (void *)__readfsdword(0x18);
#endif
}

unsigned int __pid()
{
#ifdef _AMD64_
	return *(unsigned int *)(static_cast<unsigned char *>(__teb()) + 0x40);
#else
  return *(unsigned int *)((unsigned char *)__teb() + 0x20);
#endif
}

unsigned int __tid()
{
#ifdef _AMD64_
	return *(unsigned int *)(static_cast<unsigned char *>(__teb()) + 0x48);
#else
  return *(unsigned int *)((unsigned char *)__teb() + 0x24);
#endif
}

extern "C" NTSYSAPI NTSTATUS NTAPI NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN CLIENT_ID* ClientId
);

extern "C" NTSYSAPI NTSTATUS NTAPI NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT OPTIONAL PULONG PreviousSuspendCount
);

extern "C" NTSYSAPI NTSTATUS NTAPI NtResumeThread(
	IN HANDLE ThreadHandle,
	OUT OPTIONAL PULONG SuspendCount
);

extern "C" NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect
);

extern "C" NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType
);

PVOID Alloc(OPTIONAL PVOID Base, SIZE_T Size, ULONG Protect)
{
	auto Status = NtAllocateVirtualMemory(GetCurrentProcess(), &Base, Base ? 12 : 0, &Size,
	                                               MEM_RESERVE | MEM_COMMIT, Protect);
	return NT_SUCCESS(Status) ? Base : nullptr;
}

VOID Free(PVOID Base)
{
	SIZE_T RegionSize = 0;
	NtFreeVirtualMemory(GetCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
}

BOOLEAN NTAPI EnumProcesses_(
	BOOLEAN (*Callback)(
		PWRK_SYSTEM_PROCESS_INFORMATION Process,
		OPTIONAL PVOID Argument
	),
	OPTIONAL PVOID Argument
)
{
	ULONG Length = 0;
	auto Status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &Length);
	if (Status != static_cast<NTSTATUS>(0xC0000004L)) return FALSE;
	auto Info = static_cast<PWRK_SYSTEM_PROCESS_INFORMATION>(Alloc(nullptr, Length, PAGE_READWRITE));
	if (!Info) return FALSE;
	Status = NtQuerySystemInformation(SystemProcessInformation, Info, Length, &Length);
	if (!NT_SUCCESS(Status))
	{
		Free(Info);
		return FALSE;
	}
	do
	{
		if (!Callback(Info, Argument)) break;
		Info = (PWRK_SYSTEM_PROCESS_INFORMATION)((PBYTE)Info + Info->NextEntryOffset);
	}
	while (Info->NextEntryOffset);
	Free(Info);
	return TRUE;
}

BOOLEAN SuspendResumeCallback(PWRK_SYSTEM_PROCESS_INFORMATION Process, PVOID Arg)
{
	if (!Process || !Arg) return FALSE;
	auto Info = static_cast<PSUSPEND_RESUME_INFO>(Arg);
	if ((SIZE_T)Process->UniqueProcessId != static_cast<SIZE_T>(Info->CurrentPid)) return TRUE;
	// Continue the processes enumeration loop
	for (unsigned int i = 0; i < Process->NumberOfThreads; ++i)
	{
		if ((SIZE_T)Process->Threads[i].ClientId.UniqueThread == static_cast<SIZE_T>(Info->CurrentTid)) continue;
		HANDLE hThread = nullptr;
		auto Status = NtOpenThread(&hThread, THREAD_SUSPEND_RESUME, nullptr,
		                                    (CLIENT_ID*)&Process->Threads[i].ClientId);
		if (NT_SUCCESS(Status) && hThread)
		{
			ULONG SuspendCount = 0;
			switch (Info->Type)
			{
			case srtSuspend:
				NtSuspendThread(hThread, &SuspendCount);
				break;
			case srtResume:
				NtResumeThread(hThread, &SuspendCount);
				break;
			}
			NtClose(hThread);
		}
	}
	return FALSE; // Stop the processes enumeration loop
}

BOOLEAN SuspendThreads()
{
	SUSPEND_RESUME_INFO Info;
	Info.CurrentPid = __pid();
	Info.CurrentTid = __tid();
	Info.Type = srtSuspend;
	return EnumProcesses_(SuspendResumeCallback, &Info);
}

BOOLEAN ResumeThreads()
{
	SUSPEND_RESUME_INFO Info;
	Info.CurrentPid = __pid();
	Info.CurrentTid = __tid();
	Info.Type = srtResume;
	return EnumProcesses_(SuspendResumeCallback, &Info);
}

DWORD GetModuleName(const HMODULE hModule, LPSTR szModuleName, const DWORD nSize)
{
	auto dwLength = GetModuleFileNameExA(
		GetCurrentProcess(), // Process handle.
		hModule, // Module handle.
		szModuleName, // Pointer to buffer to receive file name.
		nSize // Size of the buffer in characters.
	);
	// GetModuleFileNameEx returns 0 on error.
	if (dwLength == 0)
	{
		// Default value if the module name cannot be found.
		__strncpy(szModuleName, (LPCSTR)PRINT_HIDE_STR("<not found>"), nSize - 1);
		// TODO: not tested error with HideString
		return ERR_MOD_NAME_NOT_FOUND;
	}
	return ERR_SUCCESS;
}

DWORD ProtectMemory(const LPVOID lpAddress, const SIZE_T nSize, const DWORD flNewProtect)
{
	DWORD flOldProtect = 0;
	auto bRet = VirtualProtect(
		lpAddress, // Base address to protect.
		nSize, // Size to protect.
		flNewProtect, // Desired protection.
		&flOldProtect // Previous protection.
	);
	if (bRet == FALSE)
	{
		return 0;
	}
	return flOldProtect;
}

DWORD ReplaceExecSection(const HMODULE hModule, const LPVOID lpMapping)
{
	// Parse the PE headers.
	auto pidh = static_cast<PIMAGE_DOS_HEADER>(lpMapping);
	auto pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpMapping + pidh->e_lfanew);
	// Walk the section headers and find the .text section.
	for (WORD i = 0; i < pinh->FileHeader.NumberOfSections; i++)
	{
		auto pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + (static_cast<DWORD_PTR>(IMAGE_SIZEOF_SECTION_HEADER) * i));
		if (!str_cmp_char((const char *)pish->Name, (LPCSTR)PRINT_HIDE_STR(".text")))
		{
			// Deprotect the module's memory region for write permissions.
			auto flProtect = ProtectMemory(
				(LPVOID)((DWORD_PTR)hModule + static_cast<DWORD_PTR>(pish->VirtualAddress)), // Address to protect.
				pish->Misc.VirtualSize, // Size to protect.
				PAGE_EXECUTE_READWRITE // Desired protection.
			);
			if (!flProtect)
			{
				// Deprotecting failed!
				return ERR_MEM_DEPROTECT_FAILED;
			}
			// Replace the hooked module's .text section with the newly mapped module's.
			copy_memory(
				(LPVOID)((DWORD_PTR)hModule + static_cast<DWORD_PTR>(pish->VirtualAddress)),
				(LPVOID)((DWORD_PTR)lpMapping + static_cast<DWORD_PTR>(pish->VirtualAddress)),
				pish->Misc.VirtualSize
			);
			// Reprotect the module's memory region.
			flProtect = ProtectMemory(
				(LPVOID)((DWORD_PTR)hModule + static_cast<DWORD_PTR>(pish->VirtualAddress)), // Address to protect.
				pish->Misc.VirtualSize, // Size to protect.
				flProtect // Revert to old protection.
			);
			if (!flProtect)
			{
				// Reprotecting went wrong!
				return ERR_MEM_REPROTECT_FAILED;
			}
			return ERR_SUCCESS;
		}
	}
	// .text section not found?
	return ERR_TEXT_SECTION_NOT_FOUND;
}

DWORD UnhookModule(const HMODULE hModule)
{
	CHAR szModuleName[MAX_PATH];
	ZeroMemory(szModuleName, sizeof(szModuleName));
	// Get the full path of the module.
	auto dwRet = GetModuleName(
		hModule,
		szModuleName,
		sizeof(szModuleName)
	);
	if (dwRet == ERR_MOD_NAME_NOT_FOUND)
	{
		// Failed to get module name.
		return dwRet;
	}
	// Get a handle to the module's file.
	auto hFile = CreateFileA(
		szModuleName, // Module path name.
		GENERIC_READ, // Desired access.
		FILE_SHARE_READ, // Share access.
		nullptr, // Security attributes.
		OPEN_EXISTING, // Creation disposition.
		0, // Attributes.
		nullptr // Template file handle.
	);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// Failed to open file.
		return ERR_CREATE_FILE_FAILED;
	}
	// Create a mapping object for the module.
	auto hFileMapping = CreateFileMappingW(
		hFile, // Handle to file.
		nullptr, // Mapping attributes.
		PAGE_READONLY | SEC_IMAGE, // Page protection.
		0, // Maximum size high DWORD.
		0, // Maximum size low DWORD.
		nullptr // Name of mapping object.
	);
	if (!hFileMapping)
	{
		// Failed to create mapping handle.
		// Clean up.
		CloseHandle(hFile);
		return ERR_CREATE_FILE_MAPPING_FAILED;
	}
	else if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		// Error creating mapping handle.
		// Clean up.
		CloseHandle(hFile);
		return ERR_CREATE_FILE_MAPPING_ALREADY_EXISTS;
	}
	// Map the module.
	auto lpMapping = MapViewOfFile(
		hFileMapping, // Handle of mapping object.
		FILE_MAP_READ, // Desired access.
		0, // File offset high DWORD.
		0, // File offset low DWORD.
		0 // Number of bytes to map.
	);
	if (!lpMapping)
	{
		// Mapping failed.
		// Clean up.
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return ERR_MAP_FILE_FAILED;
	}
	// printf("Mapping at [%016p]\n", lpMapping);
	// Unhook hooks.
	SuspendThreads();
	dwRet = ReplaceExecSection(
		hModule, // Handle to the hooked module.
		lpMapping // Pointer to the newly mapped module.
	);
	NtFlushInstructionCache(GetCurrentProcess(), nullptr, 0);
	ResumeThreads();
	if (dwRet)
	{
		// Something went wrong!
		// Clean up.
		UnmapViewOfFile(lpMapping);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return dwRet;
	}
	// Clean up.
	UnmapViewOfFile(lpMapping);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	return ERR_SUCCESS;
}

HMODULE AddModule(const char* lpLibName)
{
	auto hModule = GetModuleHandleA(lpLibName);
	if (!hModule)
	{
		hModule = LoadLibraryA(lpLibName);
	}
	return hModule;
}

DWORD Unhook(const char* lpLibName)
{
	auto hModule = AddModule(lpLibName);
	auto hMod = UnhookModule(hModule);
	// free lib
	if (hMod)
	{
		FreeLibrary(hModule);
	}
	else
	{
		FreeLibrary(hModule);
	}
	return hMod;
}

#endif // !__ANTIHOOK_H__

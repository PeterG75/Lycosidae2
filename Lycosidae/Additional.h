#pragma once
#include "windows.h"
#include <stdlib.h>
#include <cstddef>

typedef enum _ERR_CODE
{
	ERR_SUCCESS,
	ERR_ENUM_PROCESS_MODULES_FAILED,
	ERR_SIZE_TOO_SMALL,
	ERR_MOD_NAME_NOT_FOUND,
	ERR_MOD_QUERY_FAILED,
	ERR_CREATE_FILE_FAILED,
	ERR_CREATE_FILE_MAPPING_FAILED,
	ERR_CREATE_FILE_MAPPING_ALREADY_EXISTS,
	ERR_MAP_FILE_FAILED,
	ERR_MEM_DEPROTECT_FAILED,
	ERR_MEM_REPROTECT_FAILED,
	ERR_TEXT_SECTION_NOT_FOUND,
	ERR_FILE_PATH_QUERY_FAILED
} ERR_CODE;

typedef enum _SUSPEND_RESUME_TYPE
{
	srtSuspend,
	srtResume
} SUSPEND_RESUME_TYPE, *PSUSPEND_RESUME_TYPE;

typedef struct _SUSPEND_RESUME_INFO
{
	ULONG CurrentPid;
	ULONG CurrentTid;
	SUSPEND_RESUME_TYPE Type;
} SUSPEND_RESUME_INFO, *PSUSPEND_RESUME_INFO;

typedef struct _WRK_SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} WRK_SYSTEM_PROCESS_INFORMATION, *PWRK_SYSTEM_PROCESS_INFORMATION;

typedef enum _WRK_MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation
} WRK_MEMORY_INFORMATION_CLASS, *PWRK_MEMORY_INFORMATION_CLASS;


#define THRESHOLD sizeof(long)

// Anti Hook
#pragma comment(lib, "Shlwapi.lib")
#define NtCurrentProcess() ((HANDLE)-1)

// Hide String
#define MMIX(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }
#define DEBUG_PRINT(m,...) //printf(m,__VA_ARGS__)
#define BLOCK_SIZE 16
#define HIDE_STR(hide, s) auto hide = HideString<sizeof(s) - 1, __COUNTER__ >(s, std::make_index_sequence<sizeof(s) - 1>())
#define PRINT_HIDE_STR(s) (HideString<sizeof(s) - 1, __COUNTER__ >(s, std::make_index_sequence<sizeof(s) - 1>()).decrypt())
#define NTDLL char_to_wchar((LPCSTR)PRINT_HIDE_STR("ntdll.dll"))

// Lycosidae
#define DEBUG_READ_EVENT 0x0001
#define DEBUG_PROCESS_ASSIGN 0x0002
#define DEBUG_SET_INFORMATION 0x0004
#define DEBUG_QUERY_INFORMATION 0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
    DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
    DEBUG_QUERY_INFORMATION)

// API Obfuscation
#define STRONG_SEED 10376313370251892926
#define RAND_DWORD1	0x03EC7B5E
#define ROR(x,n) (((x) >> (n)) | ((x) << (32-(n))))

// -----------------
struct LDR_MODULE
{
	LIST_ENTRY e[3];
	HMODULE base;
	void* entry;
	UINT size;
	UNICODE_STRING dllPath;
	UNICODE_STRING dllname;
};

typedef struct _PEB_LDR_DATA_
{
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY* InMemoryOrderModuleList;
} PEB_LDR_DATA_, *PPEB_LDR_DATA_;

#ifdef _WIN64
typedef struct _PEB_c
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[21];
	PPEB_LDR_DATA_ Ldr;
} PEB_c;

#else
typedef struct _PEB_c
{
  /*0x000*/     UINT8        InheritedAddressSpace;
  /*0x001*/     UINT8        ReadImageFileExecOptions;
  /*0x002*/     UINT8        BeingDebugged;
  /*0x003*/     UINT8        SpareBool;
  /*0x004*/     VOID *Mutant;
  /*0x008*/     VOID *ImageBaseAddress;
  /*0x00C*/     struct _PEB_LDR_DATA *Ldr;
  /*.....*/
} PEB_c;
#endif

typedef struct object_type_information
{
	UNICODE_STRING type_name;
	ULONG total_number_of_handles;
	ULONG total_number_of_objects;
} object_type_information, *pobject_type_information;

typedef struct object_all_information
{
	ULONG number_of_objects;
	object_type_information object_type_information[1];
} object_all_information, *pobject_all_information;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN KernelDebuggerEnabled;
	BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef NTSTATUS (NTAPI *p_nt_close)(HANDLE);
typedef NTSTATUS (NTAPI *p_nt_query_information_process)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS (WINAPI *p_nt_query_object)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS (__stdcall *t_nt_query_system_information)(IN ULONG, OUT PVOID, IN ULONG, OUT PULONG);

static std::size_t min_add_header(size_t a, size_t b)
{
	return (a > b) ? a : b;
}

static void big_copy(void* dest, const void* src, size_t iterations)
{
	auto d = static_cast<long *>(dest);
	auto s = static_cast<const long *>(src);
	auto eight = iterations / 8;
	auto single = iterations % 8;
	while (eight > 0)
	{
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		--eight;
	}
	while (single > 0)
	{
		*d++ = *s++;
		--single;
	}
}

static void small_copy(void* dest, const void* src, size_t iterations)
{
	auto d = static_cast<char *>(dest);
	auto s = static_cast<const char *>(src);
	while (iterations > 0)
	{
		*d++ = *s++;
		--iterations;
	}
}

void* copy_memory(void* dest, const void* src, size_t size)
{
	//Small size is handled here
	if (size < THRESHOLD)
	{
		small_copy(dest, src, size);
		return dest;
	}
	//Start copying 8 bytes as soon as one of the pointers is aligned
	auto bytes_to_align = min_add_header((size_t)dest % sizeof(long), (size_t)src % sizeof(long));
	auto position = dest;
	//Align
	if (bytes_to_align > 0)
	{
		small_copy(position, src, bytes_to_align);
		position = static_cast<char *>(position) + bytes_to_align;
		src = (char *)src + bytes_to_align;
		size -= bytes_to_align;
	}
	//How many iterations can be done
	auto safe_big_iterations = size / sizeof(long);
	auto remaining_bytes = size % sizeof(long);
	//Copy most bytes here
	big_copy(position, src, safe_big_iterations);
	position = static_cast<char *>(position) + safe_big_iterations * sizeof(long);
	src = (char *)src + safe_big_iterations * sizeof(long);
	//Process the remaining bytes
	small_copy(position, src, remaining_bytes);
	return dest;
}

char* __strncpy(char* s, const char* ct, size_t n)
{
	auto saver = s;
	while (n--)
		*saver++ = *ct++;
	*saver = '\0';
	return s;
}

int str_cmp_wchar(const wchar_t* x, const wchar_t* y)
{
	while (*x)
	{
		if (*x != *y)
			break;
		x++;
		y++;
	}
	return *static_cast<const wchar_t *>(x) - *static_cast<const wchar_t *>(y);
}

int str_cmp_char(const char* X, const char* Y)
{
	while (*X)
	{
		// if characters differ or end of second string is reached
		if (*X != *Y)
			break;
		// move to next pair of characters
		X++;
		Y++;
	}
	// return the ASCII difference after converting char* to unsigned char*
	return *(const unsigned char *)X - *(const unsigned char *)Y;
}

#pragma warning (disable : 4996)
const wchar_t* char_to_wchar(const char* c)
{
	const auto cSize = strlen(c) + 1;
	auto wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);
	return wc;
}

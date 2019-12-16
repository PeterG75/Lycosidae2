#pragma once

#include <windows.h>

#include "Additional.h"
#include "api_obfuscation.hpp"
#include "hide_str.hpp"

#include <iostream>
#include <libloaderapi.h>
#include <winternl.h>
#include <Psapi.h>
#include <xstring>
#include <cassert>


BOOL check_remote_debugger_present_api()
{
  auto b_is_dbg_present = FALSE;
  hash_CheckRemoteDebuggerPresent(hash_GetCurrentProcess(), &b_is_dbg_present);
  return b_is_dbg_present;
}

void nt_close_invalide_handle_helper()
{
  const auto nt_close = reinterpret_cast<p_nt_close>(hash_GetProcAddress(hash_GetModuleHandleW(NTDLL), (LPCSTR)PRINT_HIDE_STR("NtClose")));
  nt_close(reinterpret_cast<HANDLE>(0x99999999ULL));
}

BOOL nt_close_invalide_handle()
{
  __try
  {
    nt_close_invalide_handle_helper();
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return TRUE;
  }
  return FALSE;
}

BOOL nt_query_information_process_process_debug_flags()
{
  const auto process_debug_flags = 0x1f;
  const auto nt_query_info_process = reinterpret_cast<p_nt_query_information_process>(hash_GetProcAddress(
                                       hash_GetModuleHandleW(NTDLL), (LPCSTR)PRINT_HIDE_STR("NtQueryInformationProcess")));
  unsigned long no_debug_inherit = 0;
  const auto status = nt_query_info_process(hash_GetCurrentProcess(), process_debug_flags, &no_debug_inherit, sizeof(DWORD),
                      nullptr);
  if (status == 0x00000000 && no_debug_inherit == 0)
    return TRUE;
  return FALSE;
}

BOOL nt_query_information_process_process_debug_object()
{
  const auto process_debug_object_handle = 0x1e;
  const auto nt_query_info_process = reinterpret_cast<p_nt_query_information_process>(hash_GetProcAddress(
                                       hash_GetModuleHandleW(NTDLL), (LPCSTR)PRINT_HIDE_STR("NtQueryInformationProcess")));
  HANDLE h_debug_object = nullptr;
  const unsigned long d_process_information_length = sizeof(ULONG) * 2;
  const auto status = nt_query_info_process(hash_GetCurrentProcess(), process_debug_object_handle, &h_debug_object,
                      d_process_information_length,
                      nullptr);
  if (status == 0x00000000 && h_debug_object)
    return TRUE;
  return FALSE;
}

BOOL nt_query_object_object_all_types_information()
{
  const auto nt_query_object = reinterpret_cast<p_nt_query_object>(hash_GetProcAddress(
                                 hash_GetModuleHandleW(NTDLL), (LPCSTR)PRINT_HIDE_STR("NtQueryObject")));
  ULONG size;
  auto status = nt_query_object(nullptr, 3, &size, sizeof(ULONG), &size);
  const auto p_memory = hash_VirtualAlloc(nullptr, (size_t)size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (p_memory == nullptr)
    return FALSE;
  status = nt_query_object(reinterpret_cast<HANDLE>(-1), 3, p_memory, size, nullptr);
  if (status != 0x00000000)
  {
    hash_VirtualFree(p_memory, 0, MEM_RELEASE);
    return FALSE;
  }
  const auto p_object_all_info = static_cast<pobject_all_information>(p_memory);
  auto p_obj_info_location = reinterpret_cast<UCHAR *>(p_object_all_info->object_type_information);
  const auto num_objects = p_object_all_info->number_of_objects;
  for (UINT i = 0; i < num_objects; i++)
  {
    const auto pObjectTypeInfo = reinterpret_cast<pobject_type_information>(p_obj_info_location);
    if (str_cmp_wchar((const wchar_t *)(char_to_wchar((LPCSTR)PRINT_HIDE_STR("DebugObject"))),
                      (const wchar_t *)(pObjectTypeInfo->type_name.Buffer)) == 0)
    {
      if (pObjectTypeInfo->total_number_of_objects > 0)
      {
        hash_VirtualFree(p_memory, 0, MEM_RELEASE);
        return TRUE;
      }
      hash_VirtualFree(p_memory, 0, MEM_RELEASE);
      return FALSE;
    }
    p_obj_info_location = reinterpret_cast<unsigned char *>(pObjectTypeInfo->type_name.Buffer);
    p_obj_info_location += pObjectTypeInfo->type_name.MaximumLength;
    auto tmp = reinterpret_cast<ULONG_PTR>(p_obj_info_location) & -static_cast<int>(sizeof(void *));
    if (static_cast<ULONG_PTR>(tmp) != reinterpret_cast<ULONG_PTR>(p_obj_info_location))
      tmp += sizeof(void *);
    p_obj_info_location = reinterpret_cast<unsigned char *>(tmp);
  }
  hash_VirtualFree(p_memory, 0, MEM_RELEASE);
  return FALSE;
}

BOOL process_job()
{
  auto found_problem = FALSE;
  const DWORD job_process_struct_size = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR) * 1024;
  auto job_process_id_list = static_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST *>(malloc(
                               job_process_struct_size));
  if (job_process_id_list)
  {
    SecureZeroMemory(job_process_id_list, job_process_struct_size);
    job_process_id_list->NumberOfProcessIdsInList = 1024;
    if (hash_QueryInformationJobObject(nullptr, JobObjectBasicProcessIdList, job_process_id_list, job_process_struct_size,
                                       nullptr))
    {
      auto ok_processes = 0;
      for (DWORD i = 0; i < job_process_id_list->NumberOfAssignedProcesses; i++)
      {
        const auto process_id = job_process_id_list->ProcessIdList[i];
        if (process_id == static_cast<ULONG_PTR>(hash_GetCurrentProcessId()))
        {
          ok_processes++;
        }
        else
        {
          const auto h_job_process = hash_OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(process_id));
          if (h_job_process != nullptr)
          {
            const auto process_name_buffer_size = 4096;
            const auto process_name = static_cast<LPTSTR>(malloc(sizeof(TCHAR) * process_name_buffer_size));
            if (process_name)
            {
              RtlSecureZeroMemory(process_name, sizeof(TCHAR) * process_name_buffer_size);
              if (hash_K32GetProcessImageFileNameW(h_job_process, process_name, process_name_buffer_size) > 0)
              {
                std::wstring pnStr(process_name);
                if (pnStr.find(static_cast<std::wstring>(char_to_wchar((LPCSTR)PRINT_HIDE_STR("\\Windows\\System32\\conhost.exe")))) != std::string::npos)
                {
                  ok_processes++;
                }
              }
              free(process_name);
            }
            hash_CloseHandle(h_job_process);
          }
        }
      }
      found_problem = ok_processes != static_cast<int>(job_process_id_list->NumberOfAssignedProcesses);
    }
    free(job_process_id_list);
  }
  return found_problem;
}

void set_handle_informatiom_protected_handle_helper()
{
  const auto h_mutex = hash_CreateMutexW(nullptr, FALSE, char_to_wchar((LPCSTR)PRINT_HIDE_STR("923482934823948")));
  hash_SetHandleInformation(h_mutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
  hash_CloseHandle(h_mutex);
}

BOOL set_handle_informatiom_protected_handle()
{
  __try
  {
    set_handle_informatiom_protected_handle_helper();
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return TRUE;
  }
  return FALSE;
}

BOOL titan_hide_check()
{
  const auto ntdll = hash_GetModuleHandleW(NTDLL);
  const auto nt_query_system_information = reinterpret_cast<t_nt_query_system_information>(hash_GetProcAddress(
        ntdll, (LPCSTR)PRINT_HIDE_STR("NtQuerySystemInformation")));
  SYSTEM_CODEINTEGRITY_INFORMATION c_info;
  c_info.Length = sizeof c_info;
  nt_query_system_information(SystemCodeIntegrityInformation, &c_info, sizeof c_info, nullptr);
  const int ret = c_info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN || c_info.CodeIntegrityOptions &
                  CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;
  return ret;
}

BOOL NtQuerySystemInformation_SystemKernelDebuggerInformation()
{
  const int SystemKernelDebuggerInformation = 0x23;
  SYSTEM_KERNEL_DEBUGGER_INFORMATION KdDebuggerInfo;
  const auto ntdll = hash_GetModuleHandleW(NTDLL);
  const auto NtQuerySystemInformation = reinterpret_cast<t_nt_query_system_information>(hash_GetProcAddress(
                                          ntdll, (LPCSTR)PRINT_HIDE_STR("NtQuerySystemInformation")));
  NTSTATUS Status = NtQuerySystemInformation(SystemKernelDebuggerInformation, &KdDebuggerInfo, sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION), NULL);
  if (Status >= 0)
  {
    if (KdDebuggerInfo.KernelDebuggerEnabled || !KdDebuggerInfo.KernelDebuggerNotPresent)
      return TRUE;
  }
  return FALSE;
}

BOOL SharedUserData_KernelDebugger()
{
  const ULONG_PTR UserSharedData = 0x7FFE0000;
  const UCHAR KdDebuggerEnabledByte = *(UCHAR *)(UserSharedData + 0x2D4);
  const BOOLEAN KdDebuggerEnabled = (KdDebuggerEnabledByte & 0x1) == 0x1;
  const BOOLEAN KdDebuggerNotPresent = (KdDebuggerEnabledByte & 0x2) == 0;
  if (KdDebuggerEnabled || !KdDebuggerNotPresent)
    return TRUE;
  return FALSE;
}

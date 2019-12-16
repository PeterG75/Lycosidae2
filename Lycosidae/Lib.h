#pragma once
#include "anti_hook.hpp"
#include "Additional.h"
void log()
{
}

template <typename First, typename ...Rest>
void log(First &&message, Rest &&...rest)
{
  std::cout << std::forward<First>(message);
  log(std::forward<Rest>(rest)...);
}
extern "C" __declspec(dllexport) void init_lib();

void init_lib()
{
  if (Unhook((LPCSTR)PRINT_HIDE_STR("ntdll.dll")) == 0) {
#ifndef ANTIHOOK_LOG
    log((LPCSTR)PRINT_HIDE_STR("ntdll restored\r\n"));
#endif
  }
  else {
#ifndef ANTIHOOK_LOG
    log((LPCSTR)PRINT_HIDE_STR("ntdll fail restored\r\n"));
#endif
  }
  if (Unhook((LPCSTR)PRINT_HIDE_STR("kernel32.dll")) == 0) {
#ifndef ANTIHOOK_LOG
    log((LPCSTR)PRINT_HIDE_STR("kernel32 restored\r\n"));
#endif
  }
  else {
#ifndef ANTIHOOK_LOG
    log((LPCSTR)PRINT_HIDE_STR("kernel32 fail restored\r\n"));
#endif
  }
  if (Unhook((LPCSTR)PRINT_HIDE_STR("user32.dll")) == 0) {
#ifndef ANTIHOOK_LOG
    log((LPCSTR)PRINT_HIDE_STR("user32 restored\r\n"));
#endif
  }
  else {
#ifndef ANTIHOOK_LOG
    log((LPCSTR)PRINT_HIDE_STR("user32 fail restored\r\n"));
#endif
  }
  //const auto enable_debug_checks = 1;
  ///* Debugger Detection */
  //if (enable_debug_checks)
  //{
  if (nt_close_invalide_handle() != FALSE)
  {
#ifndef LYCOSIDAE_LOG
    log((LPCSTR)PRINT_HIDE_STR("CloseHandle with an invalide handle detected\r\n"));
#endif
  }
  if (set_handle_informatiom_protected_handle() != FALSE)
  {
#ifndef LYCOSIDAE_LOG
    log((LPCSTR)PRINT_HIDE_STR("CloseHandle protected handle trick  detected\r\n"));
#endif
  }
  if (check_remote_debugger_present_api() != FALSE)
  {
#ifndef LYCOSIDAE_LOG
    log((LPCSTR)PRINT_HIDE_STR("CheckRemoteDebuggerPresent detected\r\n"));
#endif
  }
  if (nt_query_information_process_process_debug_flags() != FALSE)
  {
#ifndef LYCOSIDAE_LOG
    log((LPCSTR)PRINT_HIDE_STR("NtQueryInformationProcess with ProcessDebugFlags detected\r\n"));
#endif
  }
  if (nt_query_information_process_process_debug_object() != FALSE)
  {
#ifndef LYCOSIDAE_LOG
    log((LPCSTR)PRINT_HIDE_STR("NtQueryInformationProcess with ProcessDebugObject detected\r\n"));
#endif
  }
  if (nt_query_object_object_all_types_information() != FALSE)
  {
#ifndef LYCOSIDAE_LOG
    log((LPCSTR)PRINT_HIDE_STR("NtQueryObject with ObjectAllTypesInformation detected\r\n"));
#endif
  }
  if (process_job() != FALSE)
  {
#ifndef LYCOSIDAE_LOG
    log((LPCSTR)PRINT_HIDE_STR("If process is in a job detected\r\n"));
#endif
  }
  // TitanHide detection
  if (titan_hide_check() != FALSE)
  {
#ifndef LYCOSIDAE_LOG
    log((LPCSTR)PRINT_HIDE_STR("TitanHide detected\r\n"));
#endif
  }
  if (NtQuerySystemInformation_SystemKernelDebuggerInformation() != FALSE)
  {
#ifndef LYCOSIDAE_LOG
    log((LPCSTR)PRINT_HIDE_STR("NtQuerySystemInformation_SystemKernelDebuggerInformation detected\r\n"));
#endif
  }
  if (SharedUserData_KernelDebugger() != FALSE)
  {
#ifndef LYCOSIDAE_LOG
    log((LPCSTR)PRINT_HIDE_STR("SharedUserData_KernelDebugger detected\r\n"));
#endif
  }
  log((LPCSTR)PRINT_HIDE_STR("Foo program. Check source code.\r\n"));
}


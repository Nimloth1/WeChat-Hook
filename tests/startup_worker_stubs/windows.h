#pragma once
#include <cstdint>
#include <cwchar>
#ifndef _MSC_VER
#define __declspec(x)
#endif
#define WINAPI
#define APIENTRY
using DWORD=std::uint32_t;
using LONG=std::int32_t;
using BOOL=int;
using HMODULE=void*;
using LPVOID=void*;
using LPCWSTR=const wchar_t*;
constexpr BOOL TRUE=1;
constexpr DWORD DLL_PROCESS_ATTACH=1;
constexpr DWORD GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS=4;
constexpr DWORD GET_MODULE_HANDLE_EX_FLAG_PIN=1;
inline int mock_mode=0;
inline DWORD mock_win32=0;
inline int mock_winsock=0;
inline LONG InterlockedExchange(volatile LONG* p,LONG v) { auto old=*p;*p=v;return old; }
inline DWORD GetCurrentThreadId(){return 123;}
inline DWORD GetLastError(){return mock_win32;}
inline int WSAGetLastError(){return mock_winsock;}
inline void OutputDebugStringA(const char*){}
inline BOOL DisableThreadLibraryCalls(HMODULE){return TRUE;}
inline DWORD GetModuleFileNameW(HMODULE,wchar_t* p,DWORD){std::wmemcpy(p,L"Weixin.exe",11);return 10;}
inline const wchar_t* GetCommandLineW(){return L"Weixin.exe";}
#ifndef _MSC_VER
inline int _wcsicmp(const wchar_t* a,const wchar_t* b){return std::wcscmp(a,b);}
#endif
inline BOOL GetModuleHandleExW(DWORD,LPCWSTR,HMODULE* p){*p=reinterpret_cast<HMODULE>(1);return TRUE;}
inline void* CreateThread(void*,int,DWORD(*)(void*),void*,DWORD,void*){return reinterpret_cast<void*>(1);}
inline BOOL CloseHandle(void*){return TRUE;}

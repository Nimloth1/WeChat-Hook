#include <windows.h>
#include <iostream>
#include <atomic>
#include <thread>
#include <vector>

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2 || GetModuleHandleW(L"Weixin.dll")) return 1;
    HMODULE candidate = LoadLibraryExW(argv[1], nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!candidate) { std::cerr << "Load failed " << GetLastError() << '\n'; return 2; }
    const char* names[] = {
        "GetFileVersionInfoA", "GetFileVersionInfoByHandle", "GetFileVersionInfoExA",
        "GetFileVersionInfoExW", "GetFileVersionInfoSizeA", "GetFileVersionInfoSizeExA",
        "GetFileVersionInfoSizeExW", "GetFileVersionInfoSizeW", "GetFileVersionInfoW",
        "VerFindFileA", "VerFindFileW", "VerInstallFileA", "VerInstallFileW",
        "VerLanguageNameA", "VerLanguageNameW", "VerQueryValueA", "VerQueryValueW"
    };
    for (const char* name : names) if (!GetProcAddress(candidate, name)) {
        std::cerr << "Missing export " << name << '\n'; FreeLibrary(candidate); return 3;
    }
    using VersionSize = DWORD(WINAPI*)(LPCWSTR, LPDWORD);
    auto size = reinterpret_cast<VersionSize>(GetProcAddress(candidate, "GetFileVersionInfoSizeW"));
    wchar_t directory[MAX_PATH]{};
    GetSystemDirectoryW(directory, MAX_PATH);
    std::wstring kernel(directory);
    kernel += L"\\kernel32.dll";
    DWORD ignored = 0;
    const DWORD result = size(kernel.c_str(), &ignored);
    std::atomic<unsigned int> failures{ 0 };
    std::vector<std::thread> callers;
    for (unsigned int i = 0; i < 8; ++i) callers.emplace_back([&] {
        for (unsigned int attempt = 0; attempt < 16; ++attempt) {
            DWORD unused = 0;
            if (size(kernel.c_str(), &unused) != result) ++failures;
        }
    });
    for (auto& caller : callers) caller.join();
    FreeLibrary(candidate);
    if (!result || failures || GetModuleHandleW(L"Weixin.dll")) return 4;
    std::cout << "PASS: candidate loaded outside WeChat; 17 exports and 128 concurrent system version queries work\n";
    return 0;
}

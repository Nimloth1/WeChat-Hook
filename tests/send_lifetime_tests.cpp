#include <winsock2.h>
#include <windows.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

int Child(const wchar_t* dll,const wchar_t* empty_appdata,bool main_process)
{
    if (GetModuleHandleW(L"Weixin.dll")) return 10;
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    if (!SetEnvironmentVariableW(L"LOCALAPPDATA",empty_appdata)) return 11;
    // 复用审核中的离线调度方式：阻止 worker 运行，先完成 Load/Free，放大启动窗口。
    // 这两个 ntdll 入口仅用于测试，不进入候选 DLL。
    using Lock = LONG(NTAPI*)(ULONG,ULONG*,ULONG_PTR*);
    using Unlock = LONG(NTAPI*)(ULONG,ULONG_PTR);
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto lock = reinterpret_cast<Lock>(GetProcAddress(ntdll,"LdrLockLoaderLock"));
    const auto unlock = reinterpret_cast<Unlock>(GetProcAddress(ntdll,"LdrUnlockLoaderLock"));
    ULONG disposition = 0; ULONG_PTR cookie = 0;
    if (!lock || !unlock || lock(0,&disposition,&cookie) < 0) return 12;
    const auto module = LoadLibraryExW(dll,nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) { unlock(0,cookie); return 13; }
    const bool released = FreeLibrary(module) != FALSE;
    MEMORY_BASIC_INFORMATION info{};
    const bool mapped = VirtualQuery(module,&info,sizeof(info)) && info.State == MEM_COMMIT && info.Type == MEM_IMAGE;
    const bool expected = released && (main_process ? mapped : !mapped);
    unlock(0,cookie);
    Sleep(1000); // 旧产物会在这里以悬空线程入口崩溃；父进程有十秒硬超时。
    if (!expected || GetModuleHandleW(L"Weixin.dll")
        || fs::exists(fs::path(empty_appdata)/L"VW12-WeChatHook")) return 14;
    std::cout << "PASS synthetic Weixin.exe: immediate FreeLibrary, main=" << main_process
        << ", mapped=" << mapped << ", no approval/module/private call\n";
    return 0;
}

int wmain(int argc,wchar_t** argv)
{
    if (argc >= 4 && std::wstring(argv[3]) == L"--offline-loader-child")
        return Child(argv[1],argv[2],argc == 4);
    if (argc != 2 || GetModuleHandleW(L"Weixin.dll")) return 1;
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2,2),&data)) return 2;
    const auto socket = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    int exclusive = 1;
    sockaddr_in address{}; address.sin_family = AF_INET;
    address.sin_port = htons(30001); address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // 独占测试端口，让合成 worker 走绑定失败路径，不启动候选 HTTP 服务。
    if (socket == INVALID_SOCKET
        || setsockopt(socket,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))
        || bind(socket,reinterpret_cast<const sockaddr*>(&address),sizeof(address))) {
        std::cerr << "Offline lifetime fixture cannot reserve PW loopback 30001; no existing owner changed\n";
        if (socket != INVALID_SOCKET) closesocket(socket);
        WSACleanup(); return 3;
    }
    int result = 0;
    fs::path root;
    try {
        wchar_t temp[32768]{},self[32768]{};
        if (!GetTempPathW(32768,temp) || !GetModuleFileNameW(nullptr,self,32768)) throw std::runtime_error("paths_failed");
        root = fs::path(temp)/(L"wechat-loader-offline-"+std::to_wstring(GetCurrentProcessId()));
        if (!fs::create_directory(root)) throw std::runtime_error("temp_collision");
        const auto child = root/L"Weixin.exe";
        if (!CopyFileW(self,child.c_str(),TRUE)) throw std::runtime_error("copy_fixture_failed");
        const auto appdata = root/L"empty-localappdata";
        fs::create_directory(appdata);
        const std::vector<std::wstring> modes{L"",L"",L" --type=renderer",L" --crashpad-handler"};
        for (const auto& mode : modes) {
            auto command = L"\""+child.wstring()+L"\" \""+fs::absolute(argv[1]).wstring()+L"\" \""
                +appdata.wstring()+L"\" --offline-loader-child"+mode;
            STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
            if (!CreateProcessW(child.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,root.c_str(),&startup,&process))
                throw std::runtime_error("child_failed");
            CloseHandle(process.hThread);
            const auto wait = WaitForSingleObject(process.hProcess,10000);
            if (wait != WAIT_OBJECT_0) { TerminateProcess(process.hProcess,99); WaitForSingleObject(process.hProcess,5000); }
            DWORD exit = 0; const auto queried = GetExitCodeProcess(process.hProcess,&exit); CloseHandle(process.hProcess);
            if (wait != WAIT_OBJECT_0 || !queried || exit) {
                std::cerr << "Synthetic loader child exit=0x" << std::hex << exit << std::dec << '\n';
                throw std::runtime_error("lifetime_regression");
            }
        }
        std::cout << "PASS send_lifetime: 4 synthetic process cases (2 main, renderer, crashpad); no WeChat process/module/API used\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; result = 4;
    }
    closesocket(socket); WSACleanup();
    if (!root.empty()) { std::error_code error; fs::remove_all(root,error); }
    return result;
}

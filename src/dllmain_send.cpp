#include "httplib.h"
#include <windows.h>
#include "send_native.h"
#include "send_routes.h"
#include "version_proxy.h"
#include <string>

namespace {
DWORD WINAPI RunSendServer(void*)
{
    try {
        // 许可由用户批准后另行准备；缺省不创建目录、许可或消耗标记。
        const auto path = send_fix::ApprovalPath();
        auto backend = std::make_unique<send_fix::WindowsBackend>();
        auto controller = std::make_unique<send_fix::Controller>(send_fix::LoadApproval(path),*backend,
            [path](const send_fix::Approval& approval) { return send_fix::ConsumeApproval(path,approval); });
        auto server = std::make_unique<httplib::Server>();
        server->new_task_queue = [] { return new httplib::ThreadPool(4); };
        send_fix::RegisterSendRoutes(*server,*controller);
        // bind 成功才启动监听；端口占用时不报告启动成功，也不另占端口。
        if (!server->bind_to_port("127.0.0.1",30001)) {
            OutputDebugStringA("[SendFix] loopback bind failed; no sending server started\n");
            return 1;
        }
        // 禁止热卸载：线程在 DLL 内运行，不能让 FreeLibrary 留下悬空代码指针。
        HMODULE pinned = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&RunSendServer),&pinned)) {
            server->stop();
            return 2;
        }
        server->listen_after_bind();
    } catch (...) { return 3; }
    return 0;
}
}

BOOL APIENTRY DllMain(HMODULE module,DWORD reason,LPVOID)
{
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(module);
    InitRealDll();
    wchar_t path[32768]{};
    const auto length = GetModuleFileNameW(nullptr,path,32768);
    if (!length || length >= 32768) return TRUE;
    const auto slash = wcsrchr(path,L'\\');
    if (_wcsicmp(slash ? slash+1 : path,L"Weixin.exe") != 0) return TRUE;
    const std::wstring command(GetCommandLineW());
    if (command.find(L"--type=") != std::wstring::npos || command.find(L"--crashpad-handler") != std::wstring::npos) return TRUE;
    const auto thread = CreateThread(nullptr,0,RunSendServer,nullptr,0,nullptr);
    if (thread) CloseHandle(thread);
    return TRUE;
}

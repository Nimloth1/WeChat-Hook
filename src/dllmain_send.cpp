#include "httplib.h"
#include <windows.h>
#include "send_native.h"
#include "send_routes.h"
#include "version_proxy.h"
#include "send_startup.h"
#include <string>
#include <system_error>

// Data export only: no function, path, token, account identifier or message contents.
extern "C" {
__declspec(dllexport) send_fix::StartupState SendFixStartupState = {
    send_fix::StartupMagic,1,sizeof(send_fix::StartupState),0,0,0,0,0,0,0
};
}
namespace {
void Loader(send_fix::LoaderStage stage) noexcept {
    InterlockedExchange(&SendFixStartupState.loader_stage,static_cast<LONG>(stage));
}
void Worker(send_fix::WorkerStage stage) noexcept {
    InterlockedExchange(&SendFixStartupState.worker_stage,static_cast<LONG>(stage));
}
void LastErrors(DWORD win32,int winsock) noexcept {
    InterlockedExchange(&SendFixStartupState.win32_error,static_cast<LONG>(win32));
    InterlockedExchange(&SendFixStartupState.winsock_error,static_cast<LONG>(winsock));
}
DWORD WINAPI RunSendServer(void*)
{
    InterlockedExchange(&SendFixStartupState.worker_thread_id,static_cast<LONG>(GetCurrentThreadId()));
    Worker(send_fix::WorkerStage::entered);
    try {
        // 许可由用户批准后另行准备；缺省不创建目录、许可或消耗标记。
        const auto path = send_fix::ApprovalPath();
        auto backend = std::make_unique<send_fix::WindowsBackend>();
        auto controller = std::make_unique<send_fix::Controller>([path] { return send_fix::LoadApproval(path); },*backend,
            [path](const send_fix::Approval& approval) { return send_fix::ConsumeApproval(path,approval); });
        Worker(send_fix::WorkerStage::approval_read);
        auto server = std::make_unique<httplib::Server>();
        server->new_task_queue = [] { return new httplib::ThreadPool(4); };
        send_fix::RegisterSendRoutes(*server,*controller);
        Worker(send_fix::WorkerStage::routes_ready);
        // bind 成功才启动监听；端口占用时不报告启动成功，也不另占端口。
        Worker(send_fix::WorkerStage::binding);
        if (!server->bind_to_port("127.0.0.1",30001)) {
            const auto winsock=WSAGetLastError();
            const auto win32=GetLastError();
            LastErrors(win32,winsock);
            Worker(send_fix::WorkerStage::bind_failed);
            OutputDebugStringA("[SendFix] loopback bind failed; no sending server started\n");
            return 1;
        }
        Worker(send_fix::WorkerStage::bound);
        Worker(send_fix::WorkerStage::listen_entered);
        if (!server->listen_after_bind()) {
            const auto winsock=WSAGetLastError();
            const auto win32=GetLastError();
            LastErrors(win32,winsock);
            Worker(send_fix::WorkerStage::listen_failed);
            return 2;
        }
        Worker(send_fix::WorkerStage::listen_returned);
    } catch (const std::bad_alloc&) {
        Worker(send_fix::WorkerStage::allocation_failed); return 3;
    } catch (const std::system_error& error) {
        const auto& category=error.code().category();
        const LONG kind=category==std::system_category() ? 1 : category==std::generic_category() ? 2 : 3;
        InterlockedExchange(&SendFixStartupState.standard_error_code,error.code().value());
        InterlockedExchange(&SendFixStartupState.standard_error_category,kind);
        Worker(send_fix::WorkerStage::system_exception); return 3;
    } catch (const std::exception&) {
        Worker(send_fix::WorkerStage::standard_exception); return 3;
    } catch (...) {
        Worker(send_fix::WorkerStage::unknown_exception); return 3;
    }
    return 0;
}
}

BOOL APIENTRY DllMain(HMODULE module,DWORD reason,LPVOID)
{
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    Loader(send_fix::LoaderStage::entered);
    DisableThreadLibraryCalls(module);
    InitRealDll();
    Loader(send_fix::LoaderStage::proxy_ready);
    wchar_t path[32768]{};
    const auto length = GetModuleFileNameW(nullptr,path,32768);
    if (!length || length >= 32768) { LastErrors(GetLastError(),0); Loader(send_fix::LoaderStage::path_failed); return TRUE; }
    const auto slash = wcsrchr(path,L'\\');
    if (_wcsicmp(slash ? slash+1 : path,L"Weixin.exe") != 0) { Loader(send_fix::LoaderStage::other_host); return TRUE; }
    const std::wstring command(GetCommandLineW());
    if (command.find(L"--type=") != std::wstring::npos || command.find(L"--crashpad-handler") != std::wstring::npos) {
        Loader(send_fix::LoaderStage::child_process); return TRUE;
    }
    // 必须在发布线程入口前固定模块；worker 内再固定会留下 FreeLibrary 竞争窗口。
    // 固定失败不创建线程；固定成功后即使创建线程/绑定失败，也只在进程退出时卸载。
    HMODULE pinned = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(module),&pinned)) {
        LastErrors(GetLastError(),0); Loader(send_fix::LoaderStage::pin_failed); return TRUE;
    }
    Loader(send_fix::LoaderStage::pinned);
    const auto thread = CreateThread(nullptr,0,RunSendServer,nullptr,0,nullptr);
    if (thread) {
        Loader(send_fix::LoaderStage::thread_created);
        CloseHandle(thread);
    } else {
        LastErrors(GetLastError(),0); Loader(send_fix::LoaderStage::thread_failed);
    }
    return TRUE;
}

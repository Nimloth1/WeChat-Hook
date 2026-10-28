#pragma once
#include <windows.h>

namespace send_fix {
// Observation only: never consulted to authorize a send or decide to start/retry.
// Kept as 32-bit scalar fields so an external reader need not call into WeChat.
inline constexpr DWORD StartupMagic = 0x31534653; // SFS1
struct StartupState {
    DWORD magic, version, bytes;
    volatile LONG loader_stage, worker_stage, win32_error, winsock_error, worker_thread_id;
    volatile LONG standard_error_code, standard_error_category;
};
static_assert(sizeof(StartupState)==40,"startup diagnostic schema");
enum class LoaderStage : LONG {
    not_entered=0, entered=10, proxy_ready=20, other_host=30, child_process=40,
    pin_failed=50, pinned=60, thread_failed=70, thread_created=80, path_failed=90
};
enum class WorkerStage : LONG {
    not_entered=0, entered=10, approval_read=20, routes_ready=30, binding=40,
    bound=50, listen_entered=60, listen_returned=70, bind_failed=100,
    allocation_failed=110, standard_exception=120, unknown_exception=130, system_exception=140, listen_failed=150
};
} // namespace send_fix

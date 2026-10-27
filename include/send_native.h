#pragma once
#include "send_api.h"
#include <windows.h>

namespace send_fix {
class WindowsBackend : public Backend {
public:
    std::unique_ptr<PreparedCall> Prepare(const Request&, const Approval&) override;
};
std::wstring ApprovalPath();
Approval LoadApproval(const std::wstring& path);
bool ConsumeApproval(const std::wstring& path, const Approval& approval);
// 测试与生产共用的只读附件验证，返回的句柄禁止写入/删除共享，调用者负责 CloseHandle。
HANDLE OpenImage(const Request& request, std::uint64_t& size);
std::string HashOpenFile(HANDLE file, std::uint64_t maximum);
} // namespace send_fix

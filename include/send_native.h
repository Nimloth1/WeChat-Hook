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
// 使用卷 GUID 路径，逐层拒绝重解析点并锁住所有父目录及文件。
// 私有调用可能异步读取路径：进入后保持句柄至进程退出，不能只锁到 Run 返回。
struct LockedImage {
    HANDLE file = INVALID_HANDLE_VALUE;
    std::vector<HANDLE> parents;
    std::u16string path;
    std::uint64_t size = 0;
    bool retained = false;
    LockedImage() = default;
    ~LockedImage();
    LockedImage(const LockedImage&) = delete;
    LockedImage& operator=(const LockedImage&) = delete;
    LockedImage(LockedImage&& other) noexcept;
    void RetainOnNativeEntry() noexcept { retained = true; }
};
LockedImage OpenImage(const Request& request);
std::string HashOpenFile(HANDLE file, std::uint64_t maximum);
} // namespace send_fix

#pragma once
#include "send_api.h"
#include <windows.h>

namespace send_fix {
class WindowsBackend : public Backend {
public:
    std::unique_ptr<PreparedCall> Prepare(const Request&, const Approval&) override;
    RetentionUsage Retention() override;
};
std::wstring ApprovalPath();
Approval LoadApproval(const std::wstring& path);
bool ConsumeApproval(const std::wstring& path, const Approval& approval);
// 使用卷 GUID 路径，逐层拒绝重解析点并锁住所有父目录及文件。
// 正常发送由原消息及所有已跟踪克隆共同持锁；具体析构完成后回收。
// 原生故障的未知所有权路径仍保守保留至进程退出，不能只锁到 Run 返回。
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
// 文件复用相同的稳定路径/句柄锁；名称保留以兼容现有图片调用方。
LockedImage OpenImage(const Request& request);
LockedImage OpenFile(const Request& request);
std::string HashOpenFile(HANDLE file, std::uint64_t maximum);
} // namespace send_fix

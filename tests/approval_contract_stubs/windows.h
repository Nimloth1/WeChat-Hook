#pragma once
// 仅供macOS离线编译LoadApproval/ConsumeApproval。文件读写/独占创建/fsync用真实POSIX调用；
// 不模拟Windows共享锁、ACL、DLL、进程或网络，不能替代Windows系统验证。
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using HANDLE = int;
using DWORD = std::uint32_t;
using ULONG = std::uint32_t;
using PUCHAR = unsigned char*;
struct LARGE_INTEGER { long long QuadPart; };
constexpr HANDLE INVALID_HANDLE_VALUE = -1;
constexpr DWORD GENERIC_READ = 1, GENERIC_WRITE = 2, FILE_SHARE_READ = 1;
constexpr DWORD OPEN_EXISTING = 3, CREATE_NEW = 1, FILE_ATTRIBUTE_NORMAL = 0;
constexpr DWORD FILE_FLAG_WRITE_THROUGH = 0, FILE_TYPE_DISK = 1;
constexpr DWORD INVALID_FILE_ATTRIBUTES = 0xffffffff;
inline HANDLE CreateFileW(const wchar_t* path, DWORD access, DWORD, void*, DWORD creation, DWORD, void*) {
    const auto flags = (access & GENERIC_WRITE ? O_WRONLY : O_RDONLY)
        | (creation == CREATE_NEW ? O_CREAT | O_EXCL : 0);
    return open(std::filesystem::path(path).c_str(), flags, 0600);
}
inline bool CloseHandle(HANDLE file) { return close(file) == 0; }
inline DWORD GetFileType(HANDLE file) {
    struct stat value{};
    return fstat(file, &value) == 0 && S_ISREG(value.st_mode) ? FILE_TYPE_DISK : 0;
}
inline bool GetFileSizeEx(HANDLE file, LARGE_INTEGER* size) {
    struct stat value{};
    if (fstat(file, &value) != 0) return false;
    size->QuadPart = value.st_size;
    return true;
}
inline bool ReadFile(HANDLE file, void* data, DWORD size, DWORD* count, void*) {
    const auto result = read(file, data, size);
    *count = result < 0 ? 0 : static_cast<DWORD>(result);
    return result >= 0;
}
inline bool WriteFile(HANDLE file, const void* data, DWORD size, DWORD* count, void*) {
    const auto result = write(file, data, size);
    *count = result < 0 ? 0 : static_cast<DWORD>(result);
    return result >= 0;
}
inline bool FlushFileBuffers(HANDLE file) { return fsync(file) == 0; }
inline DWORD GetFileAttributesW(const wchar_t* path) {
    struct stat value{};
    return stat(std::filesystem::path(path).c_str(), &value) == 0 ? 0 : INVALID_FILE_ATTRIBUTES;
}
// ApprovalPath不是本夹具的输入入口；路径由合成测试显式传入。
inline DWORD GetEnvironmentVariableW(const wchar_t*, wchar_t*, DWORD) { return 0; }

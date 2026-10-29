#include "send_native.h"
#include <algorithm>

namespace send_fix {
std::wstring ApprovalPath()
{
    wchar_t local[32768]{};
    const auto length = GetEnvironmentVariableW(L"LOCALAPPDATA",local,32768);
    if (!length || length >= 32768) return {};
    return std::wstring(local) + L"\\VW12-WeChatHook\\send-approval.json";
}

Approval LoadApproval(const std::wstring& path)
{
    Approval result;
    if (path.empty()) return result;
    HANDLE file = CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file == INVALID_HANDLE_VALUE) return result;
    LARGE_INTEGER size{}; DWORD read = 0;
    char bytes[8193]{};
    const bool valid = GetFileType(file) == FILE_TYPE_DISK && GetFileSizeEx(file,&size)
        && size.QuadPart > 0 && size.QuadPart <= 8192
        && ReadFile(file,bytes,static_cast<DWORD>(size.QuadPart),&read,nullptr) && read == size.QuadPart;
    CloseHandle(file);
    if (!valid) return result;
    try {
        const auto value = nlohmann::json::parse(bytes,bytes+read);
        if (!value.is_object() || value.size() != 9 || !value["version"].is_number_integer()
            || (value["version"] != 1 && value["version"] != 2)
            || !value["enabled"].is_boolean() || value["enabled"] != true
            || !value["expires_utc"].is_number_integer()) return {};
        for (auto key : {"token","request_id","recipient","kind","payload_sha256","module_sha256"})
            if (!value[key].is_string()) return {};
        result.token = value["token"].get<std::string>();
        result.request_id = value["request_id"].get<std::string>();
        result.recipient = value["recipient"].get<std::string>();
        result.kind = value["kind"].get<std::string>();
        result.payload_sha256 = value["payload_sha256"].get<std::string>();
        result.module_sha256 = value["module_sha256"].get<std::string>();
        result.expires = value["expires_utc"].get<std::time_t>();
        result.version = value["version"].get<int>();
        if (result.token.size() < 32 || result.token.size() > 128 || result.request_id.size() < 16
            || result.request_id.size() > 64 || result.recipient.empty() || result.recipient.size() > 128
            || !IsHexHash(result.payload_sha256) || !IsHexHash(result.module_sha256)
            || (result.kind != "text" && result.kind != "image" && result.kind != "file") || !ApprovalLifetimeValid(result)) return {};
        for (char c : result.token + result.request_id)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '-' || c == '_')) return {};
        const auto marker = path + L".used-" + std::wstring(result.request_id.begin(),result.request_id.end());
        if (GetFileAttributesW(marker.c_str()) != INVALID_FILE_ATTRIBUTES) return {};
        result.enabled = true;
        return result;
    } catch (...) { return {}; }
}

bool ConsumeApproval(const std::wstring& path, const Approval& approval)
{
    const auto current = LoadApproval(path);
    if (!current.enabled || current.token != approval.token || current.request_id != approval.request_id
        || current.recipient != approval.recipient || current.kind != approval.kind
        || current.payload_sha256 != approval.payload_sha256 || current.module_sha256 != approval.module_sha256
        || current.expires != approval.expires || current.version != approval.version) return false;
    const auto marker = path + L".used-" + std::wstring(approval.request_id.begin(),approval.request_id.end());
    const auto file = CreateFileW(marker.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    // 先持久记录消耗，再进入任何微信私有函数。失败也保留标记，等待人工核查。
    DWORD written = 0;
    const bool saved = WriteFile(file,approval.payload_sha256.data(),64,&written,nullptr)
        && written == 64 && FlushFileBuffers(file);
    CloseHandle(file);
    return saved;
}
} // namespace send_fix

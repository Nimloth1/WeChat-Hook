#include "send_native.h"
#include "send_context.h"
#include "global.h"
#include <bcrypt.h>
#include <objbase.h>
#include <algorithm>
#include <cstdio>
#include <vector>
#include <new>

namespace send_fix {
namespace {
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE v = INVALID_HANDLE_VALUE) : value(v) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(other.value) { other.value = INVALID_HANDLE_VALUE; }
};
struct HashScope {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    ~HashScope() { if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); }
};
struct NativeModuleReference {
    HMODULE value = nullptr;
    std::atomic<bool> retained{false};
    ~NativeModuleReference() { if (value && !retained.load()) FreeLibrary(value); }
};

RetentionBudget& NativeRetentionBudget()
{
    // 进程共用，不能通过更换许可、controller 或 backend 重置。
    static RetentionBudget budget(16 * 1024 * 1024,256);
    return budget;
}

// SEH 仅隔离私有调用异常，不能证明被调用函数没有破坏进程或已发送消息。
bool CallInit(std::uint64_t function, std::uint64_t object)
{
    using Function = std::int64_t(__fastcall*)(std::uint64_t);
    __try { reinterpret_cast<Function>(function)(object); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool CallCreate(std::uint64_t function, std::uint64_t out, std::uint64_t n0, std::uint64_t n1,
    std::uint64_t n2, std::uint64_t scratch, std::uint64_t context)
{
    using Function = std::int64_t(__fastcall*)(std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t);
    __try { reinterpret_cast<Function>(function)(out,n0,n1,n2,scratch,context); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool CallSubmit(std::uint64_t function, std::uint64_t arg1, std::uint64_t arg2)
{
    using Function = std::int64_t(__fastcall*)(std::uint64_t,std::uint64_t);
    __try { reinterpret_cast<Function>(function)(arg1,arg2); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool CallAllocate(std::uint64_t function, std::size_t bytes, void*& out)
{
    using Function = void*(__fastcall*)(std::size_t);
    __try { out = reinterpret_cast<Function>(function)(bytes); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { out = nullptr; return false; }
}
bool CallClone(std::uint64_t function, std::uint64_t object, std::uint64_t* out)
{
    using Function = void*(__fastcall*)(std::uint64_t,std::uint64_t*);
    __try { reinterpret_cast<Function>(function)(object,out); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

std::string Guid()
{
    GUID value{};
    if (FAILED(CoCreateGuid(&value))) throw std::runtime_error("guid_failed");
    char text[37]{};
    std::snprintf(text,sizeof(text),"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        value.Data1,value.Data2,value.Data3,value.Data4[0],value.Data4[1],value.Data4[2],value.Data4[3],
        value.Data4[4],value.Data4[5],value.Data4[6],value.Data4[7]);
    return text;
}

bool MemoryRange(std::uint64_t pointer, std::size_t bytes, bool executable)
{
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQuery(reinterpret_cast<void*>(pointer),&info,sizeof(info)) || info.State != MEM_COMMIT
        || (info.Protect & (PAGE_GUARD|PAGE_NOACCESS))) return false;
    const auto end = reinterpret_cast<std::uint64_t>(info.BaseAddress) + info.RegionSize;
    if (pointer > end || bytes > end-pointer) return false;
    return !executable || (info.Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY));
}

std::uint64_t Module(const Approval& approval,HMODULE module)
{
    if (!module) throw std::runtime_error("wechat_module_missing");
    if (approval.module_sha256 != "f487e4f56930456a25fb0d7b058c77e2dcd364e268d49bdfff4dc0e3be26ba36")
        throw std::runtime_error("native_ownership_module_not_supported");
    wchar_t path[32768]{};
    const auto length = GetModuleFileNameW(module,path,32768);
    if (!length || length >= 32768) throw std::runtime_error("module_path_failed");
    Handle file(CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr));
    if (file.value == INVALID_HANDLE_VALUE || HashOpenFile(file.value,512ULL*1024*1024) != approval.module_sha256)
        throw std::runtime_error("wechat_module_hash_mismatch");
    DWORD unused = 0;
    const auto bytes = GetFileVersionInfoSizeW(path,&unused);
    if (!bytes || bytes > 1024*1024) throw std::runtime_error("module_version_failed");
    std::vector<unsigned char> version(bytes);
    VS_FIXEDFILEINFO* info = nullptr; UINT info_size = 0;
    if (!GetFileVersionInfoW(path,0,bytes,version.data())
        || !VerQueryValueW(version.data(),L"\\",reinterpret_cast<void**>(&info),&info_size)
        || info_size < sizeof(VS_FIXEDFILEINFO) || info->dwSignature != 0xfeef04bd
        || info->dwFileVersionMS != ((4u<<16)|1u) || info->dwFileVersionLS != ((10u<<16)|27u))
        throw std::runtime_error("wechat_version_not_4_1_10_27");
    const auto base = reinterpret_cast<std::uint64_t>(module);
    // 本模块已由 Windows 装载；仍在访问 NT 头前验证边界。
    if (!MemoryRange(base,sizeof(IMAGE_DOS_HEADER),false)) throw std::runtime_error("module_header_failed");
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 || dos->e_lfanew > 1024*1024
        || !MemoryRange(base+dos->e_lfanew,sizeof(IMAGE_NT_HEADERS64),false)) throw std::runtime_error("module_header_failed");
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base+dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        throw std::runtime_error("module_architecture_failed");
    for (auto relative : {offset::create_param2,static_cast<std::uint64_t>(offset::txt_message_ctr),offset::send_message,
        std::uint64_t(0x680d0fc),std::uint64_t(0x680d138),std::uint64_t(0x1678000),
        std::uint64_t(0x6b2d30)})
        if (relative >= nt->OptionalHeader.SizeOfImage || !MemoryRange(base+relative,16,true))
            throw std::runtime_error("function_address_not_executable");
    for (auto relative : {offset::param1_vtable,offset::param2,offset::param2_1,offset::param2_2,offset::param2_3,
                          static_cast<std::uint64_t>(offset::txt_message_vtbl),offset::img_msg_vtbl,offset::img_msg_vtb2,
                          std::uint64_t(0x84f9a78),std::uint64_t(0x8279578)})
        if (relative >= nt->OptionalHeader.SizeOfImage || !MemoryRange(base+relative,8,false))
            throw std::runtime_error("data_address_not_readable");
    return base;
}

#include "send_ownership.inc"

} // namespace

RetentionUsage WindowsBackend::Retention() {
    auto usage=NativeRetentionBudget().Usage();
    if (auto runtime=existing_ownership.load()) {
        usage.pending_owners=runtime->Pending();
        usage.ownership_fault=runtime->Poisoned();
    }
    return usage;
}

std::string HashOpenFile(HANDLE file, std::uint64_t maximum)
{
    LARGE_INTEGER size{}, zero{};
    if (!GetFileSizeEx(file,&size) || size.QuadPart <= 0 || static_cast<std::uint64_t>(size.QuadPart) > maximum
        || !SetFilePointerEx(file,zero,nullptr,FILE_BEGIN)) throw std::runtime_error("file_size_invalid");
    HashScope scope;
    if (BCryptOpenAlgorithmProvider(&scope.algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0) < 0
        || BCryptCreateHash(scope.algorithm,&scope.hash,nullptr,0,nullptr,0,0) < 0) throw std::runtime_error("hash_failed");
    unsigned char buffer[65536]{}; DWORD read = 0; std::uint64_t total = 0;
    while (true) {
        if (!ReadFile(file,buffer,sizeof(buffer),&read,nullptr)) throw std::runtime_error("file_read_failed");
        if (!read) break;
        total += read;
        if (total > maximum || BCryptHashData(scope.hash,buffer,read,0) < 0) throw std::runtime_error("hash_failed");
    }
    if (total != static_cast<std::uint64_t>(size.QuadPart)) throw std::runtime_error("file_changed");
    unsigned char hash[32]{};
    if (BCryptFinishHash(scope.hash,hash,32,0) < 0) throw std::runtime_error("hash_failed");
    constexpr char hex[] = "0123456789abcdef"; std::string result;
    for (auto byte : hash) { result += hex[byte>>4]; result += hex[byte&15]; }
    return result;
}

LockedImage::~LockedImage()
{
    if (retained) return;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    for (auto parent = parents.rbegin(); parent != parents.rend(); ++parent) CloseHandle(*parent);
}

LockedImage::LockedImage(LockedImage&& other) noexcept
    : file(other.file), parents(std::move(other.parents)), path(std::move(other.path)),
      size(other.size), retained(other.retained)
{
    other.file = INVALID_HANDLE_VALUE;
    other.parents.clear();
}

namespace {
void CheckImagePathHandle(HANDLE file, const std::wstring& expected, bool directory)
{
    BY_HANDLE_FILE_INFORMATION attributes{};
    wchar_t final_path[32768]{};
    if (file == INVALID_HANDLE_VALUE || GetFileType(file) != FILE_TYPE_DISK
        || !GetFileInformationByHandle(file,&attributes)
        || (attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        || !!(attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory)
        throw std::runtime_error("image_path_not_stable");
    const auto length = GetFinalPathNameByHandleW(file,final_path,32768,FILE_NAME_NORMALIZED|VOLUME_NAME_GUID);
    if (!length || length >= 32768 || _wcsicmp(final_path,expected.c_str()) != 0)
        throw std::runtime_error("image_path_not_stable");
}
}

namespace {
LockedImage OpenPayload(const Request& request, bool attachment)
{
    const auto& path = request.unicode;
    if (path.size() < 4 || !((path[0] >= u'A' && path[0] <= u'Z') || (path[0] >= u'a' && path[0] <= u'z'))
        || path[1] != u':' || path[2] != u'\\' || path.find(u'/',0) != std::u16string::npos
        || path.find(u':',2) != std::u16string::npos || path.find(u"..") != std::u16string::npos)
        throw std::runtime_error("image_requires_local_absolute_path");
    // 不把用户的盘符路径传入微信：卷 GUID 不随盘符/SUBST 映射变化。
    const std::wstring drive{static_cast<wchar_t>(path[0]),L':',L'\\'};
    wchar_t volume[64]{};
    if (GetDriveTypeW(drive.c_str()) != DRIVE_FIXED
        || !GetVolumeNameForVolumeMountPointW(drive.c_str(),volume,64)
        || GetDriveTypeW(volume) != DRIVE_FIXED) throw std::runtime_error("image_path_not_stable");
    std::wstring stable(volume);
    LockedImage image;
    image.parents.reserve(64);
    // 从稳定的卷根开始锁住再向下走；不先遍历后补锁，防止检查本身出现 TOCTOU。
    auto lock_parent = [&] {
        if (image.parents.size() >= 64) throw std::runtime_error("image_path_not_stable");
        // 仅 FILE_READ_ATTRIBUTES 不参加 Windows 的数据共享检查，不能形成这把锁。
        Handle parent(CreateFileW(stable.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        CheckImagePathHandle(parent.value,stable,true);
        image.parents.push_back(parent.value);
        parent.value = INVALID_HANDLE_VALUE;
    };
    lock_parent();
    for (std::size_t start = 3; start < path.size();) {
        const auto end = path.find(u'\\',start);
        const auto part = path.substr(start,end == std::u16string::npos ? end : end-start);
        if (part.empty() || part == u"." || part == u".." || part.back() == u'.' || part.back() == u' ')
            throw std::runtime_error("image_path_not_stable");
        if (stable.back() != L'\\') stable += L'\\';
        stable.append(part.begin(),part.end());
        if (end == std::u16string::npos) break;
        lock_parent();
        start = end+1;
        if (start == path.size()) throw std::runtime_error("image_path_not_stable");
    }
    if (stable.size() > 4096) throw std::runtime_error("image_path_not_stable");
    image.path.assign(stable.begin(),stable.end());
    image.file = CreateFileW(stable.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    CheckImagePathHandle(image.file,stable,false);
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(image.file,&length) || length.QuadPart <= 0 || length.QuadPart > (attachment ? 100LL : 20LL)*1024*1024)
        throw std::runtime_error("image_file_invalid");
    if (attachment) {
        if (HashOpenFile(image.file,100ULL*1024*1024) != request.file_sha256)
            throw std::runtime_error("attachment_hash_mismatch");
        image.size = static_cast<std::uint64_t>(length.QuadPart);
        return image;
    }
    unsigned char head[8]{}; DWORD read = 0;
    if (!ReadFile(image.file,head,8,&read,nullptr) || read < 3) throw std::runtime_error("image_header_invalid");
    const unsigned char png[8] = {137,80,78,71,13,10,26,10};
    if (!(read == 8 && std::memcmp(head,png,8) == 0) && !(head[0] == 255 && head[1] == 216 && head[2] == 255)
        && !(head[0] == 'B' && head[1] == 'M')) throw std::runtime_error("image_format_unsupported");
    if (HashOpenFile(image.file,20*1024*1024) != request.image_sha256) throw std::runtime_error("image_hash_mismatch");
    image.size = static_cast<std::uint64_t>(length.QuadPart);
    return image;
}

} // namespace

LockedImage OpenImage(const Request& request) { return OpenPayload(request,false); }
LockedImage OpenFile(const Request& request)
{
    const auto name = request.unicode.substr(request.unicode.find_last_of(u'\\')+1);
    if (name.empty() || name.size() > 255) throw std::runtime_error("attachment_name_invalid");
    try { return OpenPayload(request,true); }
    catch (const std::runtime_error& error) {
        const std::string code(error.what());
        if (code.compare(0,6,"image_")==0) throw std::runtime_error("attachment_"+code.substr(6));
        throw;
    }
}

std::unique_ptr<PreparedCall> WindowsBackend::Prepare(const Request& request, const Approval& approval)
{
    // 哈希校验到最后一份观察记录结束之间，保护晚到的原生析构/释放代码。
    auto module=std::make_shared<NativeModuleReference>();
    if (!GetModuleHandleExW(0,L"Weixin.dll",&module->value)) throw std::runtime_error("wechat_module_missing");
    const auto base = Module(approval,module->value);
    Addresses address{base+offset::txt_message_vtbl,base+offset::img_msg_vtbl,base+offset::img_msg_vtb2,
        base+offset::param1_vtable,{base+offset::param2_1,base+offset::param2_2,base+offset::param2_3},0,base+0x84f9a78,base+0x8279578};
    address.context = ReadSendContextValue(base+offset::param2,
        [](std::uint64_t slot,void* value,std::size_t size,std::size_t& read) {
            return ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(slot),value,size,&read) != FALSE;
        });
    auto image = request.kind == "image" ? OpenImage(request) : request.kind == "file" ? OpenFile(request) : LockedImage{};
    return std::make_unique<NativePrepared>(request,base,address,std::move(image),NativeRetentionBudget(),std::move(module));
}
} // namespace send_fix

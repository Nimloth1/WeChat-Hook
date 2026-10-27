#include "send_native.h"
#include "global.h"
#include <bcrypt.h>
#include <objbase.h>
#include <algorithm>
#include <cstdio>
#include <vector>

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
struct WinHeap : Heap {
    void* Allocate(std::size_t bytes) override { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes); }
    void Free(void* pointer) noexcept override { HeapFree(GetProcessHeap(), 0, pointer); }
};
WinHeap process_heap;

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
struct NativeInvoker : Invoker {
    std::uint64_t base;
    explicit NativeInvoker(std::uint64_t module) : base(module) {}
    bool RetainsArguments() const override { return true; }
    bool InitText(std::uint64_t object) override { return CallInit(base+offset::txt_message_ctr,object); }
    bool CreateParams(std::uint64_t out,std::uint64_t n0,std::uint64_t n1,std::uint64_t n2,std::uint64_t scratch,std::uint64_t context) override {
        return CallCreate(base+offset::create_param2,out,n0,n1,n2,scratch,context);
    }
    bool Submit(std::uint64_t a,std::uint64_t b) override { return CallSubmit(base+offset::send_message,a,b); }
};

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

std::uint64_t Module(const Approval& approval)
{
    const auto module = GetModuleHandleW(L"Weixin.dll");
    if (!module) throw std::runtime_error("wechat_module_missing");
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
    for (auto relative : {offset::create_param2,static_cast<std::uint64_t>(offset::txt_message_ctr),offset::send_message})
        if (relative >= nt->OptionalHeader.SizeOfImage || !MemoryRange(base+relative,16,true))
            throw std::runtime_error("function_address_not_executable");
    for (auto relative : {offset::param1_vtable,offset::param2,offset::param2_1,offset::param2_2,offset::param2_3,
                          static_cast<std::uint64_t>(offset::txt_message_vtbl),offset::img_msg_vtbl,offset::img_msg_vtb2})
        if (relative >= nt->OptionalHeader.SizeOfImage || !MemoryRange(base+relative,8,false))
            throw std::runtime_error("data_address_not_readable");
    return base;
}

struct NativePrepared : PreparedCall {
    LockedImage image_file;
    Arena arena{process_heap};
    Addresses address;
    NativeInvoker invoke;
    Frame frame;
    NativePrepared(const Request& request, std::uint64_t base, const Addresses& a, LockedImage&& image)
        : image_file(std::move(image)), address(a), invoke(base), frame(BuildFrame(arena,address,request.recipient,
            request.kind == "text" ? request.value : "", request.kind == "image" ? &image_file.path : nullptr,
            image_file.size, request.kind == "image" ? Guid() : "")) {}
    Result Run() override {
        image_file.RetainOnNativeEntry();
        const auto result = ExecuteFrame(arena,frame,address,invoke);
        const char* error = result == FrameResult::unconfirmed ? "native_result_not_delivery_receipt"
            : result == FrameResult::constructor_fault ? "text_constructor_fault_no_retry"
            : result == FrameResult::constructor_layout_unknown ? "text_constructor_layout_unknown_no_retry"
            : result == FrameResult::params_fault ? "parameter_constructor_fault_no_retry" : "submit_fault_no_retry";
        return {202,"unconfirmed",error,true};
    }
};
} // namespace

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

LockedImage OpenImage(const Request& request)
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
    if (!GetFileSizeEx(image.file,&length) || length.QuadPart <= 0 || length.QuadPart > 20*1024*1024)
        throw std::runtime_error("image_file_invalid");
    unsigned char head[8]{}; DWORD read = 0;
    if (!ReadFile(image.file,head,8,&read,nullptr) || read < 3) throw std::runtime_error("image_header_invalid");
    const unsigned char png[8] = {137,80,78,71,13,10,26,10};
    if (!(read == 8 && std::memcmp(head,png,8) == 0) && !(head[0] == 255 && head[1] == 216 && head[2] == 255)
        && !(head[0] == 'B' && head[1] == 'M')) throw std::runtime_error("image_format_unsupported");
    if (HashOpenFile(image.file,20*1024*1024) != request.image_sha256) throw std::runtime_error("image_hash_mismatch");
    image.size = static_cast<std::uint64_t>(length.QuadPart);
    return image;
}

std::unique_ptr<PreparedCall> WindowsBackend::Prepare(const Request& request, const Approval& approval)
{
    const auto base = Module(approval);
    Addresses address{base+offset::txt_message_vtbl,base+offset::img_msg_vtbl,base+offset::img_msg_vtb2,
        base+offset::param1_vtable,{base+offset::param2_1,base+offset::param2_2,base+offset::param2_3},0};
    SIZE_T read = 0;
    if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+offset::param2),&address.context,8,&read)
        || read != 8 || !address.context || !MemoryRange(address.context,8,false)) throw std::runtime_error("send_context_unavailable");
    auto image = request.kind == "image" ? OpenImage(request) : LockedImage{};
    return std::make_unique<NativePrepared>(request,base,address,std::move(image));
}
} // namespace send_fix

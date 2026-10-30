#include "send_native.h"
#include <winioctl.h>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace send_fix;
namespace fs = std::filesystem;
static int checks = 0;
void CheckAt(bool value,int line) {
    ++checks;
    if (!value) throw std::runtime_error("image_assertion_failed_at_line_"+std::to_string(line));
}
#define Check(value) CheckAt((value),__LINE__)

struct TempDir {
    fs::path path;
    TempDir() {
        wchar_t root[32768]{};
        if (!GetTempPathW(32768,root)) throw std::runtime_error("temp_path_failed");
        path = fs::path(root)/(L"wechat-image-offline-"+std::to_wstring(GetCurrentProcessId()));
        if (!fs::create_directory(path)) throw std::runtime_error("temp_collision");
    }
    ~TempDir() { std::error_code error; fs::remove_all(path,error); }
};
void Write(const fs::path& path,const std::string& bytes) {
    std::ofstream file(path,std::ios::binary); file.write(bytes.data(),bytes.size());
    if (!file) throw std::runtime_error("fixture_write_failed");
}
Request Image(const fs::path& path,const std::string& bytes) {
    Request r; r.kind = "image"; r.recipient = "wxid_offline_fixture";
    r.value = path.u8string(); r.unicode = Utf16(r.value);
    r.image_sha256 = Sha256(bytes.data(),bytes.size()); return r;
}
bool Rejected(const Request& request) {
    try { auto image = OpenImage(request); return false; }
    catch (const std::runtime_error&) { return true; }
}
bool Junction(const fs::path& link,const fs::path& target) {
    // 合成 junction，无需符号链接权限，不启动 shell。
    const auto h = CreateFileW(link.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    struct Buffer {
        DWORD tag; WORD length,reserved,sub_offset,sub_length,print_offset,print_length;
        wchar_t names[8192];
    } data{};
    const auto sub = L"\\??\\"+target.wstring();
    const auto print = target.wstring();
    if (sub.size()+print.size()+2 > 8192) { CloseHandle(h); return false; }
    data.tag = IO_REPARSE_TAG_MOUNT_POINT;
    data.sub_length = static_cast<WORD>(sub.size()*2);
    data.print_offset = data.sub_length+2;
    data.print_length = static_cast<WORD>(print.size()*2);
    data.length = 8+data.print_offset+data.print_length+2;
    std::memcpy(data.names,sub.c_str(),data.sub_length+2);
    std::memcpy(reinterpret_cast<char*>(data.names)+data.print_offset,print.c_str(),data.print_length+2);
    DWORD unused = 0;
    const auto result = DeviceIoControl(h,FSCTL_SET_REPARSE_POINT,&data,data.length+8,nullptr,0,&unused,nullptr);
    CloseHandle(h); return result != FALSE;
}
bool CanWrite(const fs::path& path,bool directory = false) {
    const auto h = CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,directory ? FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT : 0,nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h); return true;
}
struct TestHeap : Heap {
    void* Allocate(std::size_t bytes) override { return std::calloc(1,bytes); }
    void Free(void* pointer) noexcept override { std::free(pointer); }
};

int main()
{
    try {
        Check(GetModuleHandleW(L"Weixin.dll") == nullptr);
        TempDir temp;
        const auto first = temp.path/L"first";
        const auto nested = first/L"nested";
        const auto other = temp.path/L"other";
        fs::create_directories(nested); fs::create_directory(other);
        const auto file = nested/L"\x4e2d\x6587.png";
        const std::string bytes("\x89PNG\r\n\x1a\nAPPROVED",16);
        Write(file,bytes); Write(other/L"other.png",std::string("\x89PNG\r\n\x1a\nDIFFERENT",17));
        const auto request = Image(file,bytes);
        {
            auto original = OpenImage(request);
            const auto handle = original.file;
            auto locked = std::move(original);
            Check(original.file == INVALID_HANDLE_VALUE && original.parents.empty());
            Check(locked.file == handle && locked.size == bytes.size());
            Check(locked.path.find(u"\\\\?\\Volume{") == 0 && locked.path != request.unicode);
            Check(locked.parents.size() >= 3 && HashOpenFile(locked.file,1024) == request.image_sha256);
            // 文件、直接父目录、更高祖先都不能被替换或改成重解析点。
            Check(!CanWrite(file) && !DeleteFileW(file.c_str()));
            Check(!CanWrite(nested,true) && !CanWrite(first,true));
            Check(!MoveFileW(nested.c_str(),(first/L"moved").c_str()));
            Check(!MoveFileW(first.c_str(),(temp.path/L"moved").c_str()));
            Check(!Junction(nested,other) && !Junction(first,other));
            // 后续真正传给私有函数的是稳定路径，重复打开仍为批准对象。
            const fs::path stable(std::wstring(locked.path.begin(),locked.path.end()));
            auto reopened = CreateFileW(stable.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
            Check(reopened != INVALID_HANDLE_VALUE);
            Check(HashOpenFile(reopened,1024) == request.image_sha256); CloseHandle(reopened);
            TestHeap heap; Arena arena(heap); Addresses address;
            auto frame = BuildFrame(arena,address,request.recipient,"",&locked.path,locked.size,"fixture-guid");
            WideString native_path{};
            std::memcpy(&native_path,static_cast<char*>(frame.object)+0xf0,sizeof(native_path));
            Check(native_path.length == locked.path.size());
            Check(std::u16string(native_path.data.heap,native_path.length) == locked.path);
        }
        Check(CanWrite(file) && CanWrite(first,true));
        Check(MoveFileW(first.c_str(),(temp.path/L"moved").c_str()));
        Check(MoveFileW((temp.path/L"moved").c_str(),first.c_str()));
        {
            // 校验前父目录就是 junction：必须拒绝，不能跟随到摘要正确的文件。
            const auto link = temp.path/L"link";
            const auto replacement = temp.path/L"replacement";
            fs::create_directory(link); fs::create_directory(replacement);
            Check(Junction(link,first) && Junction(replacement,other));
            Check(Rejected(Image(link/L"nested"/file.filename(),bytes)));
            Check(RemoveDirectoryW(link.c_str()));
            Check(MoveFileW(replacement.c_str(),link.c_str()));
            Check(Rejected(Image(link/L"other.png",bytes)));
            Check(RemoveDirectoryW(link.c_str()));
        }
        {
            // 消耗许可失败/尚未进入时，RAII 必须释放所有锁。
            auto wrong = request; wrong.image_sha256 = std::string(64,'0');
            Check(Rejected(wrong) && CanWrite(file) && CanWrite(nested,true));
        }
        {
            // 进入私有函数后，PreparedCall 销毁也不能释放异步路径锁。
            HANDLE retained_file = INVALID_HANDLE_VALUE; std::vector<HANDLE> retained_parents;
            {
                auto image = OpenImage(request);
                retained_file = image.file; retained_parents = image.parents;
                image.RetainOnNativeEntry();
            }
            Check(!CanWrite(file) && !CanWrite(first,true));
            Check(!MoveFileW(first.c_str(),(temp.path/L"moved").c_str()));
            Check(HashOpenFile(retained_file,1024) == request.image_sha256);
            // 仅测试进程主动清理模拟保留的句柄；生产由进程退出回收。
            CloseHandle(retained_file);
            for (auto parent : retained_parents) CloseHandle(parent);
            Check(CanWrite(file) && CanWrite(first,true));
        }
        {
            // 超过旧20MiB边界仍流式校验同一受锁文件，不改变图片内容。
            const auto big=temp.path/L"large.png";Write(big,bytes);
            auto h=CreateFileW(big.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);Check(h!=INVALID_HANDLE_VALUE);
            DWORD unused=0;Check(DeviceIoControl(h,FSCTL_SET_SPARSE,nullptr,0,nullptr,0,&unused,nullptr));
            LARGE_INTEGER size{};size.QuadPart=21LL*1024*1024;
            Check(SetFilePointerEx(h,size,nullptr,FILE_BEGIN) && SetEndOfFile(h));CloseHandle(h);
            auto r=Image(big,bytes);
            h=CreateFileW(big.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);Check(h!=INVALID_HANDLE_VALUE);
            r.image_sha256=HashOpenFile(h,~std::uint64_t(0));CloseHandle(h);
            auto image=OpenImage(r);Check(image.size==21ULL*1024*1024);
        }
        Check(GetModuleHandleW(L"Weixin.dll") == nullptr);
        std::cout << "PASS send_image checks=" << checks << "; parent junction rejected, stable path and lifetime locks; no WeChat calls\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL image checks=" << checks << ' ' << error.what() << " Win32=" << GetLastError() << '\n'; return 1;
    }
}

#include "send_native.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <winioctl.h>
using namespace send_fix;
namespace fs=std::filesystem;
static int checks=0;
void Check(bool value) {++checks;if(!value)throw std::runtime_error("file_check_"+std::to_string(checks));}
void Write(const fs::path& p,const std::string& bytes) {
    std::ofstream f(p,std::ios::binary);f.write(bytes.data(),bytes.size());if(!f)throw std::runtime_error("fixture_write");
}
Request File(const fs::path& path,const std::string& bytes) {
    return ParseRequest("file",nlohmann::json{{"request_id","offline-file-test-0001"},
        {"wxidorgid","12345678901@chatroom"},{"path",path.u8string()},
        {"file_sha256",Sha256(bytes.data(),bytes.size())}}.dump());
}
bool Reject(const Request& r) {try{auto value=OpenFile(r);return false;}catch(const std::exception&){return true;}}
bool Writable(const fs::path& p,bool directory=false) {
    auto h=CreateFileW(p.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,directory?FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT:0,nullptr);
    if(h==INVALID_HANDLE_VALUE)return false;CloseHandle(h);return true;
}
bool Junction(const fs::path& link,const fs::path& target) {
    auto h=CreateFileW(link.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr);
    if(h==INVALID_HANDLE_VALUE)return false;
    struct Buffer{DWORD tag;WORD length,reserved,sub_offset,sub_length,print_offset,print_length;wchar_t names[8192];}data{};
    const auto sub=L"\\??\\"+target.wstring(),print=target.wstring();
    data.tag=IO_REPARSE_TAG_MOUNT_POINT;data.sub_length=static_cast<WORD>(sub.size()*2);
    data.print_offset=data.sub_length+2;data.print_length=static_cast<WORD>(print.size()*2);
    data.length=8+data.print_offset+data.print_length+2;
    std::memcpy(data.names,sub.c_str(),data.sub_length+2);
    std::memcpy(reinterpret_cast<char*>(data.names)+data.print_offset,print.c_str(),data.print_length+2);
    DWORD unused=0;auto ok=DeviceIoControl(h,FSCTL_SET_REPARSE_POINT,&data,data.length+8,nullptr,0,&unused,nullptr);
    CloseHandle(h);return ok!=FALSE;
}
int main() {
    wchar_t root[32768]{};GetTempPathW(32768,root);
    const auto temp=fs::path(root)/(L"wechat-file-offline-"+std::to_wstring(GetCurrentProcessId()));
    try {
        Check(fs::create_directory(temp));const auto parent=temp/L"parent",other=temp/L"other";
        fs::create_directory(parent);fs::create_directory(other);
        const auto pdf=parent/L"\x4e2d\x6587\x7814\x62a5.pdf";
        const std::string bytes="%PDF-1.4\nOFFLINE FILE FIXTURE\n%%EOF\n";Write(pdf,bytes);
        auto r=File(pdf,bytes);
        {
            auto locked=OpenFile(r);Check(locked.size==bytes.size());
            Check(!Writable(pdf) && !Writable(parent,true) && !DeleteFileW(pdf.c_str()));
            Check(!MoveFileW(parent.c_str(),(temp/L"renamed").c_str()));
            Check(!Junction(parent,other));
            const fs::path stable(std::wstring(locked.path.begin(),locked.path.end()));
            auto h=CreateFileW(stable.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
            Check(h!=INVALID_HANDLE_VALUE);Check(HashOpenFile(h,100*1024*1024)==r.file_sha256);CloseHandle(h);
        }
        Check(Writable(pdf) && Writable(parent,true));
        r.file_sha256=std::string(64,'0');Check(Reject(r) && Writable(pdf));
        for(const auto& path:{std::string("relative.pdf"),std::string("\\\\server\\a.pdf"),pdf.u8string()+":stream",temp.u8string()}) {
            auto bad=File(fs::u8path(path),bytes);Check(Reject(bad));
        }
        for(const auto& data:{std::string("x"),std::string("PK\3\4DOCX"),std::string("GIF89a"),std::string("plain text")}) {
            Write(pdf,data);auto allowed=OpenFile(File(pdf,data));Check(allowed.size==data.size());
        }
        Write(pdf,"");Check(Reject(File(pdf,"")));
        Write(pdf,bytes);
        const auto link=temp/L"link";fs::create_directory(link);Check(Junction(link,parent));
        Check(Reject(File(link/pdf.filename(),bytes)));Check(RemoveDirectoryW(link.c_str()));
        // 稀疏/扩展文件只设长度，验证大文件在哈希前拒绝，不制作100MiB备份。
        auto h=CreateFileW(pdf.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);Check(h!=INVALID_HANDLE_VALUE);
        DWORD unused=0;Check(DeviceIoControl(h,FSCTL_SET_SPARSE,nullptr,0,nullptr,0,&unused,nullptr));
        LARGE_INTEGER length{};length.QuadPart=100LL*1024*1024+1;
        Check(SetFilePointerEx(h,length,nullptr,FILE_BEGIN) && SetEndOfFile(h));CloseHandle(h);
        auto big=File(pdf,bytes);
        h=CreateFileW(pdf.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);Check(h!=INVALID_HANDLE_VALUE);
        big.file_sha256=HashOpenFile(h,~std::uint64_t(0));CloseHandle(h);
        {auto allowed=OpenFile(big);Check(allowed.size==100ULL*1024*1024+1);}
        Write(pdf,bytes);
        Check(GetModuleHandleW(L"Weixin.dll")==nullptr);
        fs::remove_all(temp);
        std::cout<<"PASS send_file checks="<<checks<<"; exact hash, arbitrary bytes, ancestors locked, no native calls\n";return 0;
    }catch(const std::exception& e){std::error_code ec;fs::remove_all(temp,ec);std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}
}

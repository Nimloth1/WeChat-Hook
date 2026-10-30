#include "send_native.h"
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace send_fix;
using json=nlohmann::json;
namespace fs=std::filesystem;
static int checks=0;
void Check(bool v) {++checks;if(!v)throw std::runtime_error("video_check_"+std::to_string(checks));}
void Write(const fs::path& p,const std::string& s){std::ofstream f(p,std::ios::binary);f.write(s.data(),s.size());if(!f)throw std::runtime_error("fixture_write_failed");}
bool Writable(const fs::path& p){auto h=CreateFileW(p.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);if(h==INVALID_HANDLE_VALUE)return false;CloseHandle(h);return true;}
struct Call : PreparedCall {Result Run() override {return {202,"unconfirmed","fixture_only",true};}};
struct Preflight : Backend {
    std::unique_ptr<PreparedCall> Prepare(const Request& r,const Approval&) override {
        auto video=OpenVideo(r);auto thumbnail=OpenVideoThumbnail(r);return std::make_unique<Call>();
    }
};
int main() {
    wchar_t tmp[32768]{};GetTempPathW(32768,tmp);
    const auto root=fs::path(tmp)/(L"wechat-video-offline-"+std::to_wstring(GetCurrentProcessId()));
    try {
        Check(fs::create_directory(root));const auto video=root/L"\x4e2d\x6587.mp4",thumb=root/L"cover.jpg";
        const auto bytes=std::string("\0\0\0\x18" "ftypisom\0\0\0\0",16),jpeg=std::string("\xff\xd8\xff" "OFFLINE-JPEG");
        Write(video,bytes);Write(thumb,jpeg);
        const json body{{"request_id","offline-video-test-0001"},{"wxidorgid","12345678901@chatroom"},
            {"path",video.u8string()},{"file_sha256",Sha256(bytes.data(),bytes.size())},
            {"thumbnail_path",thumb.u8string()},{"thumbnail_sha256",Sha256(jpeg.data(),jpeg.size())},{"duration_seconds",2}};
        auto r=ParseRequest("video",body.dump());
        {auto v=OpenVideo(r);auto t=OpenVideoThumbnail(r);Check(!Writable(video) && !Writable(thumb));
         Check(v.size==bytes.size() && t.size==jpeg.size());}
        Check(Writable(video) && Writable(thumb));
        for(const auto& field : {"request_id","wxidorgid","path","file_sha256","thumbnail_path","thumbnail_sha256","duration_seconds"}) {
            auto b=body;b.erase(field);bool failed=false;try{ParseRequest("video",b.dump());}catch(...){failed=true;}Check(failed);
        }
        for(const json& seconds : {json(0),json(-1),json(86401),json(1.5),json(true),json("2"),json(UINT64_MAX)}) {
            auto b=body;b["duration_seconds"]=seconds;bool failed=false;try{ParseRequest("video",b.dump());}catch(...){failed=true;}Check(failed);
        }
        for(const auto& field : {"file_sha256","thumbnail_sha256"}) {
            auto b=body;b[field]="invalid";bool failed=false;try{ParseRequest("video",b.dump());}catch(...){failed=true;}Check(failed);
        }
        for(const auto& field : {"path","thumbnail_path"}) {
            auto b=body;b[field]=std::string("bad\0path",8);bool failed=false;try{ParseRequest("video",b.dump());}catch(...){failed=true;}Check(failed);
        }
        const std::string token(40,'a');Approval a{true,token,r.id,r.recipient,"video",Fingerprint(r),std::string(64,'f'),0,2};
        for(const auto& field : {"path","thumbnail_path","file_sha256","thumbnail_sha256","duration_seconds"}) {
            auto b=body;
            if(field==std::string("duration_seconds"))b[field]=3;
            else if(field==std::string("file_sha256") || field==std::string("thumbnail_sha256"))b[field]=std::string(64,'0');
            else b[field]=video.u8string()+"changed";
            Preflight f;int consumed=0;Controller c(a,f,[&](const Approval&){++consumed;return true;});
            Check(c.Dispatch("Bearer "+token,"video",b.dump()).http==403 && consumed==0);
        }
        for(int which=0;which<3;++which) {
            Write(video,which==0?"not mp4":bytes);Write(thumb,which==1?std::string("\x89PNG\r\n\x1a\nPNG",11):jpeg);
            auto b=body;
            if(which==0)b["file_sha256"]=Sha256("not mp4",7);
            if(which==1)b["thumbnail_sha256"]=Sha256("\x89PNG\r\n\x1a\nPNG",11);
            if(which==2)b["thumbnail_sha256"]=std::string(64,'0');
            auto bad=ParseRequest("video",b.dump());auto permit=a;permit.payload_sha256=Fingerprint(bad);
            Preflight f;int consumed=0;Controller c(permit,f,[&](const Approval&){++consumed;return true;});
            Check(c.Dispatch("Bearer "+token,"video",b.dump()).http==422 && consumed==0);
            Check(Writable(video) && Writable(thumb));
        }
        Write(video,bytes);Write(thumb,jpeg);
        Preflight f;int consumed=0;Controller c(a,f,[&](const Approval&){++consumed;return false;});
        Check(c.Dispatch("Bearer "+token,"video",body.dump()).http==423 && consumed==1 && Writable(video) && Writable(thumb));
        Check(GetModuleHandleW(L"Weixin.dll")==nullptr);
        fs::remove_all(root);
        std::cout<<"PASS send_video checks="<<checks<<"; both hashes bound, no native calls; header fixtures are not playable videos\n";
    }catch(const std::exception& e){std::error_code ec;fs::remove_all(root,ec);std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}

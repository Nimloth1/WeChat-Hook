#include "send_link.h"
#include "send_video.h"
#include <iostream>
#include <map>
using namespace send_fix;
static int checks=0;
void Check(bool v){++checks;if(!v)throw std::runtime_error("media_layout_"+std::to_string(checks));}
struct Memory : Heap {
    std::map<void*,std::size_t> allocations;
    void* Allocate(std::size_t n) override {auto p=::operator new(n);allocations.emplace(p,n);return p;}
    void Free(void* p) noexcept override {allocations.erase(p);::operator delete(p);}
    ~Memory(){for(auto p:allocations)::operator delete(p.first);}
};
int main(){
    try {
        Memory memory;Addresses addresses{};
        const std::u16string path=u"C:\\approved\\video.mp4",thumb=u"C:\\approved\\thumb.jpg";
        for(int i=0;i<100;++i){
            Arena arena(memory);
            auto frame=BuildFrame(arena,addresses,"12345678901@chatroom","",nullptr,0,"",true,false,"",true);
            Check(memory.allocations[frame.object]==0x8b8 && frame.link && !frame.image && !frame.file);
            for(auto offset:{0xb0,0x708,0x728,0x798})Put64(static_cast<char*>(frame.object)+16,offset+24,15);
            const auto title=std::string(80,'t'),description=std::string(6000,'d'),url=std::string("https://example.com/?x=1&y=2");
            auto strings=MakeLinkStrings(arena,title,description,url);FinishLinkFrame(frame,strings);
            Check(*reinterpret_cast<std::uint64_t*>(static_cast<char*>(frame.object)+16+0xd8)==0x500000031);
            auto video=BuildFrame(arena,addresses,"12345678901@chatroom","",&path,123,"",true,false,"video.mp4",false,true);
            Check(memory.allocations[video.object]==0x770 && video.video && !video.image && !video.file);
            for(auto offset:{0xb0,0x168})Put64(static_cast<char*>(video.object)+16,offset+24,15);
            for(auto offset:{0xe0,0x720})Put64(static_cast<char*>(video.object)+16,offset+24,7);
            auto thumbnail=MakeWide(arena,thumb,true);FinishVideoFrame(video,thumbnail,123,2);
            Check(*reinterpret_cast<std::uint64_t*>(static_cast<char*>(video.object)+16+0xd8)==43);
            Check(*reinterpret_cast<std::uint32_t*>(static_cast<char*>(video.object)+16+0x71c)==2);
        }
        Check(memory.allocations.empty());
        for(const auto& url: {"https://example.com/x?a=1&b=2","http://example.com:8080/"}){ValidateLink(u8"中文😀",u8"说明<&>",url);++checks;}
        std::cout<<"PASS media_layout checks="<<checks<<"; synthetic layouts only, real ABI tested separately on Windows\n";
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}

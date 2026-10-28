#include "send_context.h"
#include "send_layout.h"
#include <cstdlib>
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#endif

using namespace send_fix;
namespace {
int checks = 0;
void Check(bool value) { ++checks; if (!value) throw std::runtime_error("context_assertion_failed"); }
struct TestHeap : Heap {
    int live = 0;
    void* Allocate(std::size_t bytes) override { auto p=std::malloc(bytes); if(p)++live; return p; }
    void Free(void* p) noexcept override { if(p){--live;std::free(p);} }
};
struct Capture : Invoker {
    std::uint64_t value = 0;
    int init = 0, create = 0, submit = 0;
    bool RetainsArguments() const override { return false; }
    bool InitText(std::uint64_t) override { ++init; return true; }
    bool CreateParams(std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t,
        std::uint64_t,std::uint64_t scalar) override { ++create;value=scalar;return true; }
    bool Submit(std::uint64_t,std::uint64_t) override { ++submit;return true; }
};
}

int main()
{
    try {
#ifdef _WIN32
        if(GetModuleHandleW(L"Weixin.dll"))throw std::runtime_error("real_wechat_loaded");
#endif
        for(auto scalar : {std::uint64_t(0),std::uint64_t(1),std::uint64_t(2),
                std::uint64_t(0x100000001),std::uint64_t(0x123456789abcdef0),~std::uint64_t(0)}) {
            for(bool image : {false,true}) {
                int reads=0;
                const auto slot=reinterpret_cast<std::uint64_t>(&scalar);
                const auto value=ReadSendContextValue(slot,[&](std::uint64_t at,void* out,std::size_t size,std::size_t& bytes) {
                    ++reads;Check(at==slot && size==8);std::memcpy(out,&scalar,size);bytes=size;return true;
                });
                Check(reads==1 && value==scalar);
                TestHeap heap;
                {
                    Arena arena(heap);Addresses address{11,22,33,44,{55,66,77},value};
                    const std::u16string path=u"C:\\synthetic.png";
                    auto frame=BuildFrame(arena,address,"filehelper","hello",image?&path:nullptr,1,"synthetic");
                    Capture invoke;
                    Check(ExecuteFrame(arena,frame,address,invoke)==FrameResult::unconfirmed);
                    Check(invoke.value==scalar && invoke.create==1 && invoke.submit==1 && invoke.init==(image?0:1));
                }
                Check(heap.live==0);
            }
        }
        // Even a reader reporting success must provide exactly eight bytes.
        for(std::size_t bytes=0;bytes<=9;++bytes) {
            if(bytes==8)continue;
            int reads=0;bool rejected=false;
            try {
                ReadSendContextValue(17,[&](std::uint64_t at,void* out,std::size_t size,std::size_t& read) {
                    ++reads;Check(at==17 && size==8);std::memset(out,1,size);read=bytes;return true;
                });
            } catch(const std::runtime_error& error) { rejected=std::string(error.what())=="send_context_unavailable"; }
            Check(rejected && reads==1);
        }
        for(auto bytes : {std::size_t(0),std::size_t(8)}) {
            bool rejected=false;
            try {
                ReadSendContextValue(17,[&](std::uint64_t,void* out,std::size_t size,std::size_t& read) {
                    std::memset(out,1,size);read=bytes;return false;
                });
            } catch(const std::runtime_error& error) { rejected=std::string(error.what())=="send_context_unavailable"; }
            Check(rejected);
        }
#ifdef _WIN32
        const auto reader=[](std::uint64_t slot,void* value,std::size_t size,std::size_t& read) {
            return ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(slot),value,size,&read)!=FALSE;
        };
        for(auto scalar : {std::uint64_t(0),std::uint64_t(1),~std::uint64_t(0)})
            Check(ReadSendContextValue(reinterpret_cast<std::uint64_t>(&scalar),reader)==scalar);
        bool rejected=false;
        try { ReadSendContextValue(0,reader); }
        catch(const std::runtime_error& error) { rejected=std::string(error.what())=="send_context_unavailable"; }
        Check(rejected);
#endif
        std::cout<<"PASS "<<checks<<" context checks; text/image preserve opaque bits; failed/short reads rejected; no private calls\n";
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; }
}

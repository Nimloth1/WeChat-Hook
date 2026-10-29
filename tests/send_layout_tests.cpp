#include "send_layout.h"
#include <cstdlib>
#include <iostream>
#include <map>

using namespace send_fix;
static int checks = 0;
void Check(bool value) { ++checks; if (!value) throw std::runtime_error("layout_assertion_failed"); }

struct TestHeap : Heap {
    std::map<void*,std::size_t> live;
    int fail_at = -1, calls = 0;
    void* Allocate(std::size_t n) override {
        if (calls++ == fail_at) return nullptr;
        auto p = std::malloc(n);
        if (p) live.emplace(p,n);
        return p;
    }
    void Free(void* p) noexcept override { live.erase(p); std::free(p); }
    ~TestHeap() { for (auto item : live) std::free(item.first); }
};

struct FakeInvoker : Invoker {
    Frame& frame;
    Addresses& address;
    int stage = 0, init = 0, create = 0, submit = 0;
    bool retain = false;
    explicit FakeInvoker(Frame& f,Addresses& a) : frame(f),address(a) {}
    bool RetainsArguments() const override { return retain; }
    bool InitText(std::uint64_t object) override {
        ++init;
        Check(object == reinterpret_cast<std::uint64_t>(frame.object)+16);
        if (stage == 1) return false;
        if (stage == 2) Put64(reinterpret_cast<void*>(object),0xb0+24,31);
        return true;
    }
    bool CreateParams(std::uint64_t out,std::uint64_t n0,std::uint64_t n1,std::uint64_t n2,std::uint64_t scratch,std::uint64_t context) override {
        ++create;
        Check(out == reinterpret_cast<std::uint64_t>(frame.arg2));
        Check(n0 == reinterpret_cast<std::uint64_t>(frame.nodes[0]));
        Check(n1 == reinterpret_cast<std::uint64_t>(frame.nodes[1]));
        Check(n2 == reinterpret_cast<std::uint64_t>(frame.nodes[2]));
        Check(scratch == reinterpret_cast<std::uint64_t>(frame.scratch));
        Check(context == address.context);
        return stage != 3;
    }
    bool Submit(std::uint64_t a,std::uint64_t b) override {
        ++submit;
        Check(a == reinterpret_cast<std::uint64_t>(frame.arg1));
        Check(b == reinterpret_cast<std::uint64_t>(frame.arg2));
        return stage != 4;
    }
};

int main()
{
    try {
        for (auto length : {0,1,7,8,15,16,31,32,127,128,4096}) {
            TestHeap heap;
            {
                Arena arena(heap);
                const std::string text(length,'a');
                auto narrow = MakeNarrow(arena,text);
                auto data = length <= 15 ? narrow.data.local : narrow.data.heap;
                Check(narrow.length == text.size() && narrow.capacity >= text.size());
                Check(std::memcmp(data,text.data(),text.size()) == 0 && data[length] == 0);
                if (length > 15) {
                    Check(heap.live.at(data) == narrow.capacity+1);
                    data[narrow.capacity] = 0; // ASan 验证声明容量全部真实分配。
                }
                const std::u16string wide_text(length,u'中');
                auto wide = MakeWide(arena,wide_text);
                auto wide_data = length <= 7 ? wide.data.local : wide.data.heap;
                Check(wide.length == wide_text.size() && wide.capacity >= wide_text.size());
                Check(std::memcmp(wide_data,wide_text.data(),wide_text.size()*2) == 0 && wide_data[length] == 0);
                if (length > 7) {
                    Check(heap.live.at(wide_data) == (wide.capacity+1)*2);
                    wide_data[wide.capacity] = 0;
                }
                Check((length > 7) || wide.capacity == 7);
            }
            Check(heap.live.empty());
        }
        Check(Utf16(u8"C:\\中文\\报告😀.png") == u"C:\\中文\\报告😀.png");
        for (const std::string bad : {std::string("\xc0\x80",2),std::string("\xed\xa0\x80",3),
             std::string("\xf4\x90\x80\x80",4),std::string("a\0b",3),std::string("\xe4\xb8",2)}) {
            bool threw = false; try { Utf16(bad); } catch (...) { threw = true; } Check(threw);
        }
        Addresses address{11,22,33,44,{55,66,77},88};
        for (bool image : {false,true}) {
            for (int stage = 0; stage < 5; ++stage) {
                TestHeap heap;
                {
                    Arena arena(heap);
                    auto path = Utf16(u8"C:\\临时\\报告😀.png");
                    auto frame = BuildFrame(arena,address,"wxid_fixture_target",u8"中文文字😀\n第二行",
                        image ? &path : nullptr,12345,"12345678-1234-1234-1234-123456789012");
                    Check(arena.Bytes() < 128*1024);
                    FakeInvoker call(frame,address); call.stage = stage;
                    auto result = ExecuteFrame(arena,frame,address,call);
                    Check(call.init == (image ? 0 : 1));
                    Check(call.submit == ((image || stage > 2 || stage == 0) && stage != 3 ? 1 : 0));
                    if (stage == 0 || (image && (stage == 1 || stage == 2))) Check(result == FrameResult::unconfirmed);
                    if (image) {
                        WideString wide{}; NarrowString receiver{};
                        std::memcpy(&wide,static_cast<char*>(frame.object)+0xf0,32);
                        std::memcpy(&receiver,static_cast<char*>(frame.object)+0xc0,32);
                        Check(wide.length == path.size() && wide.length != std::string(u8"C:\\临时\\报告😀.png").size());
                        Check(wide.capacity >= wide.length && wide.data.heap[path.size()] == 0);
                        Check(receiver.capacity >= receiver.length);
                    } else if (stage == 0) {
                        NarrowString receiver{},text{};
                        auto object = static_cast<char*>(frame.object)+16;
                        std::memcpy(&receiver,object+0xb0,32); std::memcpy(&text,object+0x708,32);
                        Check(receiver.length == 19);
                        Check(text.length == std::string(u8"中文文字😀\n第二行").size());
                    }
                }
                Check(heap.live.empty());
            }
        }
        // 每个分配点失败都能回收已经分配的缓冲区，不进入任何私有函数。
        for (int failure = 0; failure < 16; ++failure) {
            TestHeap heap; heap.fail_at = failure;
            try {
                Arena arena(heap); auto path = Utf16(u8"C:\\临时\\报告😀.png");
                BuildFrame(arena,address,"wxid_fixture_target","",&path,12,"12345678-1234-1234-1234-123456789012");
            } catch (const std::bad_alloc&) {}
            Check(heap.live.empty());
        }
        // 实际异步所有权未知时保留参数，而不是提前释放；测试堆在用例末尾统一回收。
        TestHeap retained;
        {
            Arena arena(retained); auto frame = BuildFrame(arena,address,"wxid_fixture_target","x",nullptr,0,"");
            FakeInvoker call(frame,address); call.retain = true;
            ExecuteFrame(arena,frame,address,call);
        }
        Check(!retained.live.empty());
        // 原生对象交给配对析构前，验证大字符串的原始分配指针和完整容量。
        for (auto length : {15,16,4094,4095,4096,32768}) {
            TestHeap heap;
            {
                Arena arena(heap);
                auto value=MakeNarrow(arena,std::string(length,'n'),true);
                if(value.capacity>=15 && length>15) {
                    value.data.heap[value.capacity]=0;
                    if(value.capacity+1>=4096) {
                        void* raw=nullptr;std::memcpy(&raw,value.data.heap-8,sizeof(raw));
                        Check(heap.live.count(raw)==1 && (reinterpret_cast<std::uintptr_t>(value.data.heap)&31)==0);
                    } else Check(heap.live.count(value.data.heap)==1);
                }
            }
            Check(heap.live.empty());
        }
        for(bool image:{false,true}) {
            TestHeap heap;
            {
                Arena arena(heap);std::u16string path(2100,u'图');
                auto frame=BuildFrame(arena,address,"12345678901@chatroom","x",image?&path:nullptr,12,"offline-guid",true);
                std::uint64_t counts=0;std::memcpy(&counts,static_cast<char*>(frame.object)+8,8);
                Check(counts==0x100000001 && heap.live.at(frame.object)==(image?0x7c0:0x758));
                Check(frame.state && reinterpret_cast<char*>(frame.arg2)==static_cast<char*>(frame.state)+24);
                Check(std::memcmp(frame.state,frame.arg1+1,24)==0 && arena.Bytes()<128*1024);
            }
            Check(heap.live.empty());
        }
        std::cout << "PASS send_layout checks=" << checks << "; no WeChat module or process used\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL after checks=" << checks << ' ' << error.what() << '\n';
        return 1;
    }
}

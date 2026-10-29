#pragma once
// 离线 Windows 夹具：不 LoadLibrary、不初始化微信。只在合成进程内复制
// 固定输入的指令页；替换分配器、UUID、会话提供器和最外层调度队列。
// 排队后的真实消息工作体入口被显式替换为失败，绝不执行。
#include <map>
#include <mutex>
#include <vector>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <set>

struct NativeFixture {
    static inline NativeFixture* current = nullptr;
    static constexpr std::uintptr_t base = 0x180000000;
    HANDLE file = INVALID_HANDLE_VALUE, mapping = nullptr;
    unsigned char* raw = nullptr;
    void* handler = nullptr;
    std::size_t image_size = 0;
    std::vector<IMAGE_SECTION_HEADER> sections;
    std::mutex mutex;
    std::mutex page_mutex;
    std::map<void*,std::size_t> live;
    std::vector<std::uint64_t> queue;
    std::size_t allocations=0,frees=0,peak=0,live_bytes=0;
    std::atomic<std::size_t> private_entries{0};
    std::atomic<int> fail_at{-1};
    unsigned char* stubs=nullptr;
    std::size_t stub_count=0;
    PRUNTIME_FUNCTION unwind_table=nullptr;
    std::chrono::steady_clock::time_point start=std::chrono::steady_clock::now();
    unsigned char* At(std::uintptr_t r) const { return reinterpret_cast<unsigned char*>(base+r); }
    std::uintptr_t Q(std::uintptr_t p) const { return *reinterpret_cast<std::uintptr_t*>(p); }
    static LONG CALLBACK Fault(EXCEPTION_POINTERS* e) {
        if (e->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
        auto self=current; if (!self) return EXCEPTION_CONTINUE_SEARCH;
        auto address=e->ExceptionRecord->ExceptionInformation[1];
        if (address < base || address >= base+self->image_size) return EXCEPTION_CONTINUE_SEARCH;
        auto page=address & ~std::uintptr_t(4095); auto r=page-base;
        std::lock_guard<std::mutex> lock(self->page_mutex);
        MEMORY_BASIC_INFORMATION information{};
        if(VirtualQuery(reinterpret_cast<void*>(page),&information,sizeof(information))
            && information.State==MEM_COMMIT) return EXCEPTION_CONTINUE_EXECUTION;
        auto memory=VirtualAlloc(reinterpret_cast<void*>(page),4096,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
        if (!memory) return EXCEPTION_CONTINUE_SEARCH;
        for(auto& section:self->sections) if(r >= section.VirtualAddress && r < section.VirtualAddress+section.SizeOfRawData) {
            auto n=(std::min)(std::size_t(4096),std::size_t(section.VirtualAddress+section.SizeOfRawData-r));
            std::memcpy(memory,self->raw+section.PointerToRawData+r-section.VirtualAddress,n); break;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    static void* __fastcall Allocate(std::size_t n) {
        auto& self=*current; ++self.private_entries;
        if (self.fail_at.load() == 0) return nullptr;
        if (self.fail_at.load() > 0) --self.fail_at;
        if (!n || n > 128*1024) RaiseException(0xe0421001,0,0,nullptr);
        auto p=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,n);
        if (!p) RaiseException(0xe0421002,0,0,nullptr);
        std::lock_guard<std::mutex> lock(self.mutex);
        self.live.emplace(p,n); ++self.allocations; self.live_bytes+=n;
        self.peak=(std::max)(self.peak,self.live_bytes); return p;
    }
    static void __fastcall Free(void* p) {
        if (!p) return;
        auto& self=*current; std::lock_guard<std::mutex> lock(self.mutex);
        auto found=self.live.find(p);
        if (found == self.live.end()) RaiseException(0xe0421003,0,0,nullptr);
        self.live_bytes-=found->second; self.live.erase(found); ++self.frees;
        HeapFree(GetProcessHeap(),0,p);
    }
    static void* __fastcall Copy(void* to,const void* from,std::size_t n) { return std::memcpy(to,from,n); }
    static void* __fastcall UUID(void* out) {
        const char text[]="00000000-0000-0000-0000-000000000001";
        auto p=static_cast<char*>(Allocate(48)); std::memcpy(p,text,sizeof(text));
        auto value=static_cast<std::uint64_t*>(out); value[0]=reinterpret_cast<std::uint64_t>(p);
        value[1]=0;value[2]=36;value[3]=47;return out;
    }
    static std::uint64_t* __fastcall SessionGet(std::uint64_t,std::uint64_t* out) { out[0]=base+0x1000;out[1]=0;return out; }
    static std::uint64_t __fastcall Session() { return base+0x2000; }
    static std::uint64_t* __fastcall Queue(std::uint64_t,std::uint64_t* out,std::uint64_t,std::uint64_t closure) {
        auto task=reinterpret_cast<std::uint64_t*>(closure+56);
        current->queue.push_back(*task); *task=0;out[0]=out[1]=0;return out;
    }
    static void __fastcall Forbidden() { RaiseException(0xe0421010,0,0,nullptr); }
    static EXCEPTION_DISPOSITION __cdecl SkipNativeEH(EXCEPTION_RECORD*,void*,CONTEXT*,void*) {
        // 不初始化私有 CRT，也不宣称验证了它的异常清理；模拟未知/未清理状态。
        return ExceptionContinueSearch;
    }
    void EnableUnwind() {
        auto dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(raw);
        auto nt=reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw+dos->e_lfanew);
        const auto directory=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        auto table=reinterpret_cast<PRUNTIME_FUNCTION>(At(directory.VirtualAddress));
        const auto count=static_cast<DWORD>(directory.Size/sizeof(RUNTIME_FUNCTION));
        std::set<DWORD> handlers;
        for(DWORD i=0;i<count;++i) {
            auto info=At(table[i].UnwindData & ~DWORD(3));
            if((info[0]>>3)&3) {
                auto offset=(4+2*info[2]+3)&~3;
                handlers.insert(*reinterpret_cast<DWORD*>(info+offset));
            }
        }
        for(auto r:handlers) Patch(r,reinterpret_cast<void*>(&SkipNativeEH));
        if(!RtlAddFunctionTable(table,count,base)) throw std::runtime_error("fixture_unwind_registration_failed");
        unwind_table=table;
    }
    void Patch(std::uintptr_t r,void* target) {
        // 绝对跳转，不依赖分配地址或 rel32 范围。
        auto p=At(r); volatile auto touch=*p; (void)touch;
        if(stub_count>=256) throw std::runtime_error("fixture_stub_budget");
        auto stub=stubs+16*stub_count++;
        unsigned char jump[12]={0x48,0xb8}; std::memcpy(jump+2,&target,8);jump[10]=0xff;jump[11]=0xe0;
        std::memcpy(stub,jump,12);
        auto relative=static_cast<std::int32_t>(stub-(p+5));
        p[0]=0xe9;std::memcpy(p+1,&relative,4); FlushInstructionCache(GetCurrentProcess(),p,5);
    }
    explicit NativeFixture(const std::filesystem::path& path) {
        if (current || GetModuleHandleW(L"Weixin.dll")) throw std::runtime_error("fixture_requires_isolation");
        file=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
        LARGE_INTEGER size{};
        if(file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file,&size) || size.QuadPart != 183094832
            || send_fix::HashOpenFile(file,200*1024*1024) != "f487e4f56930456a25fb0d7b058c77e2dcd364e268d49bdfff4dc0e3be26ba36")
            throw std::runtime_error("fixture_native_hash_mismatch");
        mapping=CreateFileMappingW(file,nullptr,PAGE_READONLY,0,0,nullptr);
        raw=static_cast<unsigned char*>(MapViewOfFile(mapping,FILE_MAP_READ,0,0,0));
        if(!raw) throw std::runtime_error("fixture_map_failed");
        auto dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(raw);
        auto nt=reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw+dos->e_lfanew);
        image_size=nt->OptionalHeader.SizeOfImage;
        if(image_size > 256*1024*1024 || nt->OptionalHeader.ImageBase != base) throw std::runtime_error("fixture_image_invalid");
        auto first=IMAGE_FIRST_SECTION(nt); sections.assign(first,first+nt->FileHeader.NumberOfSections);
        if(!VirtualAlloc(reinterpret_cast<void*>(base),image_size,MEM_RESERVE,PAGE_NOACCESS)) throw std::runtime_error("fixture_base_busy");
        current=this;handler=AddVectoredExceptionHandler(1,Fault);
        if(!handler) throw std::runtime_error("fixture_veh_failed");
        stubs=static_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(0x170000000),4096,
            MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));
        if(!stubs) throw std::runtime_error("fixture_stubs_busy");
        Patch(0x680d0fc,reinterpret_cast<void*>(&Allocate));Patch(0x680d138,reinterpret_cast<void*>(&Free));
        Patch(0x680d140,reinterpret_cast<void*>(&Free));Patch(0x68960d0,reinterpret_cast<void*>(&Copy));
        Patch(0x4df240,reinterpret_cast<void*>(&UUID));Patch(0x410c0,reinterpret_cast<void*>(&Session));
        Patch(0x426b0,reinterpret_cast<void*>(&SessionGet));Patch(0x2bbcb0,reinterpret_cast<void*>(&Queue));
        for(auto r:{0x1678320,0x16bed80,0x16bd660,0x6860478}) Patch(r,reinterpret_cast<void*>(&Forbidden));
        // 生产加载器已提交这些只读表；夹具惰性映射也须在边界检查前提交。
        for(auto r:{0x8279358,0x84f96b8,0x84f9748}) {volatile auto value=*At(r-8);(void)value;}
    }
    ~NativeFixture() {
        // 先前建立的原生控制块必须都完成析构/回收；失败用例在独立进程结束。
        if(unwind_table) RtlDeleteFunctionTable(unwind_table);
        if(handler) RemoveVectoredExceptionHandler(handler);
        VirtualFree(reinterpret_cast<void*>(base),0,MEM_RELEASE);current=nullptr;
        if(stubs) VirtualFree(stubs,0,MEM_RELEASE);
        if(raw) UnmapViewOfFile(raw);if(mapping) CloseHandle(mapping);if(file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
    send_fix::Addresses Addresses() const {
        return {base+0x8279358,base+0x84f96b8,base+0x84f9748,base+0x84ec9c8,
            {base+0x8595f58,base+0x8595e98,base+0x8595dd8},1};
    }
    std::uint64_t TakeTask() { if(queue.empty()) throw std::runtime_error("no_synthetic_task");auto t=queue.back();queue.pop_back();return t; }
    std::uint64_t CopyTask(std::uint64_t t) { return reinterpret_cast<std::uint64_t(__fastcall*)(std::uint64_t)>(base+0x1678180)(t); }
    void DeleteTask(std::uint64_t t) { reinterpret_cast<void(__fastcall*)(std::uint64_t,int)>(base+0x1678660)(t,1); }
    void Release(std::uint64_t control) {
        if(InterlockedDecrement(reinterpret_cast<volatile LONG*>(control+8)) == 0) {
            reinterpret_cast<void(__fastcall*)(std::uint64_t)>(Q(Q(control)))(control);
            if(InterlockedDecrement(reinterpret_cast<volatile LONG*>(control+12)) == 0)
                reinterpret_cast<void(__fastcall*)(std::uint64_t)>(Q(Q(control)+8))(control);
        }
    }
    std::size_t Live() { std::lock_guard<std::mutex> lock(mutex);return live.size(); }
    void Budget() { if(std::chrono::steady_clock::now()-start > std::chrono::seconds(150)) throw std::runtime_error("fixture_timeout"); }
};

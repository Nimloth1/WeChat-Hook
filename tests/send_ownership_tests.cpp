#include "../src/send_native.cpp" // 实际生产准备、分配、观察器、回收器；不注入目标进程。
#include "native_ownership_fixture.h"
#include <iostream>
#include <thread>
#include <condition_variable>

using namespace send_fix;
namespace fs=std::filesystem;
static std::atomic<bool> fail_observer{false};
void* operator new(std::size_t n,const std::nothrow_t&) noexcept {
    if(n==sizeof(OwnershipRecord) && fail_observer.exchange(false)) return nullptr;
    try{return ::operator new(n);}catch(...){return nullptr;}
}
static std::size_t checks=0;
void CheckAt(bool ok,int line) { ++checks;if(!ok) throw std::runtime_error("ownership_line_"+std::to_string(line)); }
#define Check(ok) CheckAt((ok),__LINE__)
Request Text(int n,std::size_t length=17) {
    return ParseRequest("text",nlohmann::json{{"request_id","offline-ownership-"+std::to_string(n)},
        {"wxidorgid","12345678901@chatroom"},{"msg",std::string(length,'x')}}.dump());
}
Request Link(int n) {
    std::string description;for(int i=0;i<1900;++i)description+=u8"能";
    return ParseRequest("link",nlohmann::json{{"request_id","offline-owned-link-"+std::to_string(n)},
        {"wxidorgid","12345678901@chatroom"},{"title",u8"离线链接标题 <&> 😀"},
        {"description",description},{"url","https://example.com/report?a=1&b=2"}}.dump());
}
std::string NarrowAt(std::uint64_t object,std::size_t offset) {
    NarrowString s{};std::memcpy(&s,reinterpret_cast<void*>(object+offset),32);
    return {s.capacity>15?s.data.heap:s.data.local,static_cast<std::size_t>(s.length)};
}
struct Temporary {
    fs::path directory,file,video,thumbnail;
    std::string bytes=std::string("\x89PNG\r\n\x1a\nAPPROVED",16);
    std::string video_bytes=std::string("\0\0\0\x18" "ftypisom\0\0\0\0",16);
    std::string thumbnail_bytes=std::string("\xff\xd8\xff" "JPEG-OFFLINE");
    Temporary() {
        wchar_t temp[32768]{};Check(GetTempPathW(32768,temp)!=0);
        directory=fs::path(temp)/(L"wechat-owned-offline-"+std::to_wstring(GetCurrentProcessId()));
        Check(fs::create_directory(directory));file=directory/L"image.png";
        std::ofstream f(file,std::ios::binary);f.write(bytes.data(),bytes.size());Check(bool(f));
        video=directory/L"video.mp4";thumbnail=directory/L"thumbnail.jpg";
        std::ofstream v(video,std::ios::binary);v.write(video_bytes.data(),video_bytes.size());Check(bool(v));
        std::ofstream t(thumbnail,std::ios::binary);t.write(thumbnail_bytes.data(),thumbnail_bytes.size());Check(bool(t));
    }
    ~Temporary(){std::error_code error;fs::remove_all(directory,error);}
    Request Image(int n) const {
        return ParseRequest("image",nlohmann::json{{"request_id","offline-owned-image-"+std::to_string(n)},
            {"wxidorgid","12345678901@chatroom"},{"path",file.u8string()},
            {"image_sha256",Sha256(bytes.data(),bytes.size())}}.dump());
    }
    Request File(int n) const {
        return ParseRequest("file",nlohmann::json{{"request_id","offline-owned-file-"+std::to_string(n)},
            {"wxidorgid","12345678901@chatroom"},{"path",file.u8string()},
            {"file_sha256",Sha256(bytes.data(),bytes.size())}}.dump());
    }
    Request Video(int n) const {
        return ParseRequest("video",nlohmann::json{{"request_id","offline-owned-video-"+std::to_string(n)},
            {"wxidorgid","12345678901@chatroom"},{"path",video.u8string()},
            {"file_sha256",Sha256(video_bytes.data(),video_bytes.size())},{"thumbnail_path",thumbnail.u8string()},
            {"thumbnail_sha256",Sha256(thumbnail_bytes.data(),thumbnail_bytes.size())},{"duration_seconds",2}}.dump());
    }
    bool VideoWritable() const {
        for(const auto& path : {video,thumbnail}) {
            auto h=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
            if(h==INVALID_HANDLE_VALUE) return false;CloseHandle(h);
        }
        return true;
    }
    bool Writable() const {
        auto h=CreateFileW(file.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,0,nullptr);
        if(h==INVALID_HANDLE_VALUE) return false;CloseHandle(h);return true;
    }
};
struct FixtureBackend : Backend {
    NativeFixture& f; RetentionBudget& budget;
    FixtureBackend(NativeFixture& value,RetentionBudget& b):f(value),budget(b){}
    std::unique_ptr<PreparedCall> Prepare(const Request& r,const Approval&) override {
        auto image=r.kind=="image"?OpenImage(r):r.kind=="file"?OpenFile(r):LockedImage{};
        return std::make_unique<NativePrepared>(r,NativeFixture::base,f.Addresses(),std::move(image),budget);
    }
};
std::uint64_t Clone(NativeFixture& f,std::uint64_t object) {
    std::uint64_t pair[2]{};
    Check(CallClone(f.Q(f.Q(object)+32),object,pair));
    Check(pair[0]==pair[1]+16 && pair[1]!=0);return pair[1];
}

static HANDLE dtor_entered=nullptr,dtor_continue=nullptr;
static void __fastcall DelayedDestroy(std::uint64_t) {
    SetEvent(dtor_entered);WaitForSingleObject(dtor_continue,10000);
}
static void __fastcall TestDelete(std::uint64_t p) { NativeFixture::Free(reinterpret_cast<void*>(p)); }

int wmain(int argc,wchar_t** argv) {
    try {
        if(argc<2) throw std::runtime_error("requires_exact_native_sample_path");
        const std::string full_mode=argc>2?fs::path(argv[2]).string():"normal";
        const bool file_mode=full_mode.compare(0,5,"file-")==0;
        const bool link_mode=full_mode.compare(0,5,"link-")==0;
        const bool video_mode=full_mode.compare(0,6,"video-")==0;
        const std::string mode=video_mode?full_mode.substr(6):file_mode || link_mode?full_mode.substr(5):full_mode;
        NativeFixture f(argv[1]);NativeOwnership();
        Check(GetModuleHandleW(L"Weixin.dll")==nullptr);
        RetentionBudget budget(16*1024*1024,256);
        Temporary temp;
        if(mode!="normal") {
            f.EnableUnwind();
            const auto r=video_mode?temp.Video(90000):link_mode?Link(90000):file_mode?temp.File(90000):temp.Image(90000);
            std::shared_ptr<NativeModuleReference> module;
            if(mode=="metadata-fault") {
                wchar_t directory[32768]{};Check(GetSystemDirectoryW(directory,32768)>0);
                module=std::make_shared<NativeModuleReference>();
                module->value=LoadLibraryW((fs::path(directory)/L"msimg32.dll").c_str());Check(module->value!=nullptr);
            }
            std::uintptr_t entry=mode=="params-fault"?offset::create_param2:mode=="submit-fault"?offset::send_message:
                mode=="cleanup-fault"?native_state_destroy_rva:mode=="ctor-fault"?(video_mode?0x18efd70:link_mode?0x2b52b90:file_mode?0x6b2d30:offset::txt_message_ctr):0;
            if(entry) f.Patch(entry,reinterpret_cast<void*>(&NativeFixture::Forbidden));
            {
                auto value=mode=="ctor-fault" && !file_mode && !link_mode && !video_mode?Text(90000):r;
                auto image=value.kind=="image"?OpenImage(value):value.kind=="file"?OpenFile(value):value.kind=="video"?OpenVideo(value):LockedImage{};
                auto thumbnail=value.kind=="video"?OpenVideoThumbnail(value):LockedImage{};
                NativePrepared p(value,NativeFixture::base,f.Addresses(),std::move(image),budget,module,std::move(thumbnail));
                auto result=p.Run();Check(result.native_entered && result.http==202);
                if(mode=="destroy-fault") {
                    f.Patch(0xa7f0,reinterpret_cast<void*>(&NativeFixture::Forbidden));f.DeleteTask(f.TakeTask());
                } else if(mode=="clone-fault") {
                    f.Patch(video_mode?0x1778b10:link_mode?0x2b54890:file_mode?0x18e41f0:0x1778170,reinterpret_cast<void*>(&NativeFixture::Forbidden));
                    const auto task=f.TakeTask();const auto object=f.Q(f.Q(task+8));
                    std::uint64_t pair[2]{};Check(CallClone(f.Q(f.Q(object)+32),object,pair));
                } else if(mode=="metadata-fault") {
                    const auto task=f.TakeTask();const auto object=f.Q(f.Q(task+8));
                    fail_observer=true;const auto child=Clone(f,object);
                    f.DeleteTask(task);f.Release(child);
                }
            }
            Check(NativeOwnership().Poisoned());NativeOwnership().Collect();
            if(module) {module.reset();Check(GetModuleHandleW(L"msimg32.dll")!=nullptr);}
            Check(budget.Usage().bytes==128*1024);
            if(video_mode) Check(!temp.VideoWritable());
            else if(!link_mode && (mode!="ctor-fault" || file_mode)) Check(!temp.Writable());
            bool refused=false;
            try{NativePrepared p(Text(90001),NativeFixture::base,f.Addresses(),LockedImage{},budget);}
            catch(const std::runtime_error& e){refused=std::string(e.what())=="native_ownership_fault_requires_investigation";}
            Check(refused);
            std::cout<<"PASS ownership_fault mode="<<full_mode<<" checks="<<checks<<"; quarantined, no retry\n"<<std::flush;
            // 故障状态不提供重置入口；独立测试进程由 OS 统一回收保守保留量。
            ExitProcess(0);
        }
        {
            // 准备和消耗失败都不调用本次请求的原生入口。
            FixtureBackend backend(f,budget);auto r=Text(1);
            Approval a{true,std::string(40,'a'),r.id,r.recipient,r.kind,Fingerprint(r),std::string(64,'f'),0,2};
            Controller c([&]{return a;},backend,[](const Approval&){return false;});
            const auto before=f.private_entries.load();
            auto result=c.Dispatch("Bearer "+a.token,"text",nlohmann::json{{"request_id",r.id},{"wxidorgid",r.recipient},{"msg",r.value}}.dump());
            Check(result.http==423 && f.private_entries.load()==before && f.Live()==0 && budget.Usage().bytes==0);
        }
        for(auto size:{1,15,16,1999,2000}) {
            NativePrepared p(Text(2,size),NativeFixture::base,f.Addresses(),LockedImage{},budget);
            const auto result=p.Run();
            if(result.error!="native_result_not_delivery_receipt")std::cerr<<"text_frame_result="<<result.error<<'\n';
            Check(result.error=="native_result_not_delivery_receipt");
            auto task=f.TakeTask();auto copy=f.CopyTask(task);f.DeleteTask(task);
            NativeOwnership().Collect();Check(f.Live()>0);
            f.DeleteTask(copy);NativeOwnership().Collect();Check(f.Live()==0);
        }
        Check(budget.Usage().bytes==0);
        {
            // 无关的系统 DLL 仅用于测试模块引用的 RAII，不调用它的业务接口。
            Check(GetModuleHandleW(L"msimg32.dll")==nullptr);
            wchar_t directory[32768]{};Check(GetSystemDirectoryW(directory,32768)>0);
            auto module=std::make_shared<NativeModuleReference>();
            module->value=LoadLibraryW((fs::path(directory)/L"msimg32.dll").c_str());Check(module->value!=nullptr);
            {NativePrepared p(Text(12),NativeFixture::base,f.Addresses(),LockedImage{},budget,module);p.Run();}
            module.reset();Check(GetModuleHandleW(L"msimg32.dll")!=nullptr);
            f.DeleteTask(f.TakeTask());NativeOwnership().Collect();
            Check(GetModuleHandleW(L"msimg32.dll")==nullptr && f.Live()==0);
        }
        {
            // 空闲时无需另一个请求推动回收，定时器只等实际析构完成通知。
            auto r=temp.Image(10);
            {NativePrepared p(r,NativeFixture::base,f.Addresses(),OpenImage(r),budget);p.Run();}
            f.DeleteTask(f.TakeTask());
            const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(3);
            while(!temp.Writable() && std::chrono::steady_clock::now()<until) Sleep(10);
            Check(temp.Writable() && budget.Usage().bytes==0 && f.Live()==0);
        }
        {
            // 跨越原生大块字符串边界：2000 个中文字符，UTF-8 >4096 字节。
            auto r=Text(3);r.value=std::string();for(int i=0;i<2000;++i)r.value+=u8"图";r.unicode=Utf16(r.value);
            NativePrepared p(r,NativeFixture::base,f.Addresses(),LockedImage{},budget);
            Check(p.Run().error=="native_result_not_delivery_receipt");f.DeleteTask(f.TakeTask());NativeOwnership().Collect();Check(f.Live()==0);
        }
        {
            // 仅参数所有权用例：合成长路径不做真实路径查找，业务体仍被禁用。
            auto r=temp.Image(13);auto image=OpenImage(r);
            image.path=u"C:\\synthetic\\"+std::u16string(2100,u'图')+u".png";
            {NativePrepared p(r,NativeFixture::base,f.Addresses(),std::move(image),budget);Check(p.Run().http==202);}
            auto task=f.TakeTask();auto child=Clone(f,f.Q(f.Q(task+8)));
            f.DeleteTask(task);f.Release(child);NativeOwnership().Collect();
            Check(f.Live()==0 && budget.Usage().handles==0);
        }
        {
            auto r=temp.Image(4);
            {NativePrepared p(r,NativeFixture::base,f.Addresses(),OpenImage(r),budget);Check(p.Run().http==202);}
            auto task=f.TakeTask();const auto object=f.Q(f.Q(task+8));
            auto child=Clone(f,object);auto grandchild=Clone(f,child+16);
            f.DeleteTask(task);NativeOwnership().Collect();Check(!temp.Writable() && budget.Usage().handles>0);
            // 原对象已析构，后代仍按批准的路径实际读取同一份图片。
            WideString path{};std::memcpy(&path,reinterpret_cast<void*>(grandchild+0xf0),sizeof(path));
            auto stable=std::wstring(reinterpret_cast<wchar_t*>(path.data.heap),path.length);
            Handle h(CreateFileW(stable.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr));
            Check(h.value!=INVALID_HANDLE_VALUE && HashOpenFile(h.value,1024)==r.image_sha256);
            CloseHandle(h.value);h.value=INVALID_HANDLE_VALUE;
            f.Release(child);NativeOwnership().Collect();Check(!temp.Writable());
            f.Release(grandchild);NativeOwnership().Collect();Check(temp.Writable() && f.Live()==0 && budget.Usage().handles==0);
        }
        {
            auto r=temp.Image(11);
            {NativePrepared p(r,NativeFixture::base,f.Addresses(),OpenImage(r),budget);p.Run();}
            auto task=f.TakeTask();const auto object=f.Q(f.Q(task+8));
            std::mutex mutex;std::vector<std::uint64_t> children;std::vector<std::thread> threads;
            // 多线程调用原生克隆；Check 的计数不跨线程修改。
            std::atomic<bool> failed{false};
            for(int t=0;t<8;++t)threads.emplace_back([&]{
                for(int n=0;n<20;++n){std::uint64_t pair[2]{};
                    if(!CallClone(f.Q(f.Q(object)+32),object,pair) || !pair[1]){failed=true;return;}
                    std::lock_guard<std::mutex> lock(mutex);children.push_back(pair[1]);}
            });
            for(auto& thread:threads)thread.join();threads.clear();
            Check(!failed && children.size()==160);
            f.DeleteTask(task);NativeOwnership().Collect();Check(!temp.Writable());
            for(int t=0;t<8;++t)threads.emplace_back([&,t]{for(std::size_t i=t;i<children.size();i+=8)f.Release(children[i]);});
            for(auto& thread:threads)thread.join();NativeOwnership().Collect();
            Check(f.Live()==0 && temp.Writable() && budget.Usage().handles==0);
        }
        {
            // 合法外部弱引用晚于消息销毁：还原原生虚表后再释放观察器记录。
            NativePrepared p(Text(5),NativeFixture::base,f.Addresses(),LockedImage{},budget);p.Run();
            auto task=f.TakeTask();const auto control=f.Q(f.Q(task+8)+8);
            const auto original=NativeFixture::base+0x8279358;
            InterlockedIncrement(reinterpret_cast<volatile LONG*>(control+12));
            f.DeleteTask(task);NativeOwnership().Collect();Check(f.Q(control)==original);
            if(InterlockedDecrement(reinterpret_cast<volatile LONG*>(control+12))==0)
                reinterpret_cast<void(__fastcall*)(std::uint64_t)>(f.Q(original+8))(control);
            Check(f.Live()==0);
        }
        {
            // 强计数归零但具体析构仍阻塞，回收器必须等待完成通知。
            dtor_entered=CreateEventW(nullptr,TRUE,FALSE,nullptr);dtor_continue=CreateEventW(nullptr,TRUE,FALSE,nullptr);
            std::uint64_t table[5]={0,reinterpret_cast<std::uint64_t>(&DelayedDestroy),reinterpret_cast<std::uint64_t>(&TestDelete),0,0};
            auto control=reinterpret_cast<std::uint64_t>(NativeFixture::Allocate(32));
            Put64(reinterpret_cast<void*>(control),0,reinterpret_cast<std::uint64_t>(table+1));Put64(reinterpret_cast<void*>(control),8,0x100000001);
            auto record=new OwnershipRecord;record->lease=std::make_shared<RequestLease>(LockedImage{},budget);
            NativeOwnership().Observe(record,control,false);
            std::thread thread([&]{f.Release(control);});
            Check(WaitForSingleObject(dtor_entered,5000)==WAIT_OBJECT_0);
            NativeOwnership().Collect();Check(NativeOwnership().Pending()==1 && f.Live()==1);
            SetEvent(dtor_continue);thread.join();NativeOwnership().Collect();Check(f.Live()==0 && budget.Usage().bytes==0);
            CloseHandle(dtor_entered);CloseHandle(dtor_continue);
        }
        // 逐一打断调用方原生分配，尚未构造时应配对释放已有分配。
        for(int i=0;i<10;++i) {
            f.fail_at=i;
            {NativePrepared p(Text(6),NativeFixture::base,f.Addresses(),LockedImage{},budget);auto result=p.Run();
             if(result.error=="native_result_not_delivery_receipt")f.DeleteTask(f.TakeTask());}
            f.fail_at=-1;NativeOwnership().Collect();
            Check(!NativeOwnership().Poisoned() && f.Live()==0 && budget.Usage().bytes==0);
        }
        {
            const auto old=temp.file;temp.file=temp.directory/L"\x4e2d\x6587\x7814\x62a5.pdf";
            fs::rename(old,temp.file);
            auto r=temp.File(44);
            {NativePrepared p(r,NativeFixture::base,f.Addresses(),OpenFile(r),budget);
             Check(p.Run().error=="native_result_not_delivery_receipt");}
            auto task=f.TakeTask(); const auto object=f.Q(f.Q(task+8));
            Check(f.Q(object+0xd8)==0x600000031 && f.Q(object+0x188)==temp.bytes.size());
            auto child=Clone(f,object); auto grandchild=Clone(f,child+16);
            f.DeleteTask(task); NativeOwnership().Collect(); Check(!temp.Writable());
            WideString path{};std::memcpy(&path,reinterpret_cast<void*>(grandchild+0xf0),32);
            NarrowString name{},ext{};std::memcpy(&name,reinterpret_cast<void*>(grandchild+0x178),32);
            std::memcpy(&ext,reinterpret_cast<void*>(grandchild+0x118),32);
            Check(std::string(name.capacity>15?name.data.heap:name.data.local,name.length)==u8"中文研报.pdf"
                && std::string(ext.data.local,ext.length)=="pdf");
            auto stable=std::wstring(reinterpret_cast<wchar_t*>(path.data.heap),path.length);
            Handle h(CreateFileW(stable.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr));
            Check(h.value!=INVALID_HANDLE_VALUE && HashOpenFile(h.value,1024)==r.file_sha256);
            CloseHandle(h.value);h.value=INVALID_HANDLE_VALUE;
            f.Release(child);NativeOwnership().Collect();Check(!temp.Writable());
            f.Release(grandchild);NativeOwnership().Collect();Check(temp.Writable() && f.Live()==0 && budget.Usage().handles==0);
            fs::rename(temp.file,old);temp.file=old;
        }
        {
            auto r=Link(45);
            {NativePrepared p(r,NativeFixture::base,f.Addresses(),LockedImage{},budget);
             Check(p.Run().error=="native_result_not_delivery_receipt");}
            auto task=f.TakeTask();auto object=f.Q(f.Q(task+8));
            Check(f.Q(object+0xd8)==0x500000031);
            Check(NarrowAt(object,0xb0)==r.recipient && NarrowAt(object,0x708)==r.title
                && NarrowAt(object,0x728)==r.description && NarrowAt(object,0x798)==r.value);
            auto child=Clone(f,object),grandchild=Clone(f,child+16);
            f.DeleteTask(task);NativeOwnership().Collect();
            Check(NarrowAt(grandchild+16,0x708)==r.title && NarrowAt(grandchild+16,0x728)==r.description
                && NarrowAt(grandchild+16,0x798)==r.value);
            f.Release(child);NativeOwnership().Collect();Check(budget.Usage().bytes==128*1024);
            f.Release(grandchild);NativeOwnership().Collect();Check(f.Live()==0 && budget.Usage().bytes==0);
        }
        // 各扩展名使用同一附件对象；原生克隆保持实际文件名/扩展名和内容摘要。
        for(const auto& extension : {"docx","xlsx","pptx","zip","txt","csv","mp3","wav","m4a","mp4"}) {
            const auto original=temp.file;temp.file=temp.directory/(std::string("offline.")+extension);
            fs::rename(original,temp.file);auto r=temp.File(46);
            {NativePrepared p(r,NativeFixture::base,f.Addresses(),OpenFile(r),budget);
             Check(p.Run().error=="native_result_not_delivery_receipt");}
            auto task=f.TakeTask(),child=Clone(f,f.Q(f.Q(task+8)));
            Check(NarrowAt(child+16,0x108)==extension && NarrowAt(child+16,0x168)==temp.file.filename().u8string());
            f.DeleteTask(task);NativeOwnership().Collect();Check(!temp.Writable());
            f.Release(child);NativeOwnership().Collect();Check(temp.Writable() && f.Live()==0 && budget.Usage().handles==0);
            fs::rename(temp.file,original);temp.file=original;
        }
        {
            auto r=temp.Video(47);
            {NativePrepared p(r,NativeFixture::base,f.Addresses(),OpenVideo(r),budget,{},OpenVideoThumbnail(r));
             Check(p.Run().error=="native_result_not_delivery_receipt");}
            auto task=f.TakeTask(),object=f.Q(f.Q(task+8));
            auto child=Clone(f,object),grandchild=Clone(f,child+16);
            Check(f.Q(object+0xd8)==43 && *reinterpret_cast<std::uint32_t*>(object+0x71c)==2);
            f.DeleteTask(task);NativeOwnership().Collect();Check(!temp.VideoWritable());
            for(auto offset : {0xe0,0x720}) {
                WideString value{};std::memcpy(&value,reinterpret_cast<void*>(grandchild+16+offset),32);
                auto path=std::wstring(reinterpret_cast<wchar_t*>(value.data.heap),value.length);
                Handle h(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr));
                Check(h.value!=INVALID_HANDLE_VALUE && HashOpenFile(h.value,1024)==(offset==0xe0?r.file_sha256:r.thumbnail_sha256));
            }
            f.Release(child);NativeOwnership().Collect();Check(!temp.VideoWritable());
            f.Release(grandchild);NativeOwnership().Collect();Check(temp.VideoWritable() && f.Live()==0 && budget.Usage().handles==0);
        }
        DWORD baseline=0;Check(GetProcessHandleCount(GetCurrentProcess(),&baseline));
        for(int i=0;i<10000;++i) {
            f.Budget();auto r=i%5==0?temp.Video(100+i):i%5==1?Link(100+i):i%5==2?temp.File(100+i):i%5==3?temp.Image(100+i):Text(100+i);
            {auto image=r.kind=="image"?OpenImage(r):r.kind=="file"?OpenFile(r):r.kind=="video"?OpenVideo(r):LockedImage{};
             auto thumbnail=r.kind=="video"?OpenVideoThumbnail(r):LockedImage{};
             NativePrepared p(r,NativeFixture::base,f.Addresses(),std::move(image),budget,{},std::move(thumbnail));
             Check(p.Run().error=="native_result_not_delivery_receipt");}
            auto task=f.TakeTask();auto copy=f.CopyTask(task);
            auto child=r.kind=="file" || r.kind=="link" || r.kind=="video"?Clone(f,f.Q(f.Q(task+8))):0;
            f.DeleteTask(task);f.DeleteTask(copy);if(child)f.Release(child);
            NativeOwnership().Collect();Check(f.Live()==0 && budget.Usage().bytes==0 && budget.Usage().handles==0);
        }
        DWORD after=0;Check(GetProcessHandleCount(GetCurrentProcess(),&after));
        Check(after<=baseline+1 && NativeOwnership().Pending()==0 && !NativeOwnership().Poisoned());
        Check(f.allocations==f.frees && GetModuleHandleW(L"Weixin.dll")==nullptr);
        std::cout<<"PASS production_ownership checks="<<checks<<" cycles=10000 allocations="<<f.allocations
            <<" frees="<<f.frees<<" peak_native_parameter_bytes="<<f.peak<<" handle_delta="<<static_cast<long>(after)-static_cast<long>(baseline)
            <<"; original constructors/copy/destructors, queued business body forbidden\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<" checks="<<checks<<'\n';return 1;}
}

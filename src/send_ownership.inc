// 仅由 send_native.cpp 的匿名命名空间包含；不启动/连接微信。
// 固定 4.1.10.27 所有权契约，所有原生入口均在持久消耗许可后使用。
constexpr std::uint64_t native_allocate_rva = 0x680d0fc;
constexpr std::uint64_t native_free_rva = 0x680d138;
constexpr std::uint64_t native_state_destroy_rva = 0x1678000;

struct RequestLease {
    LockedImage image;
    LockedImage thumbnail;
    RetentionBudget::Reservation reservation;
    std::shared_ptr<NativeModuleReference> module;
    std::atomic<bool> quarantined{false};
    RequestLease(LockedImage&& value, RetentionBudget& budget,std::shared_ptr<NativeModuleReference> reference={},LockedImage&& preview=LockedImage{})
        : image(std::move(value)),thumbnail(std::move(preview)),reservation(budget.Reserve(128*1024,
              image.parents.size() + (image.file != INVALID_HANDLE_VALUE ? 1 : 0)
              + thumbnail.parents.size() + (thumbnail.file != INVALID_HANDLE_VALUE ? 1 : 0))),module(std::move(reference)) {}
    void Quarantine() noexcept {
        if (!quarantined.exchange(true)) {
            image.RetainOnNativeEntry();
            thumbnail.RetainOnNativeEntry();
            reservation.RetainOnNativeEntry();
            if (module) module->retained.store(true);
        }
    }
};

struct OwnershipRecord {
    OwnershipRecord* next = nullptr;
    std::uint64_t control = 0, original_control = 0, original_image = 0;
    std::uint64_t expected_control = 0, expected_image = 0;
    std::uint64_t control_table[5]{}, image_table[8]{}; // 含 [-1] RTTI；保留其余槽。
    std::shared_ptr<RequestLease> lease;
    std::atomic<bool> destroyed{false};
    bool image = false;
};
class OwnershipRuntime;
std::atomic<OwnershipRuntime*> existing_ownership{nullptr};

void __fastcall ObservedMessageDestroy(std::uint64_t control) noexcept;
void* __fastcall ObservedImageClone(std::uint64_t object,std::uint64_t* out) noexcept;

class OwnershipRuntime {
    std::mutex mutex_;
    std::mutex collector_mutex_;
    OwnershipRecord* records_ = nullptr;
    HANDLE timer_ = nullptr;
    std::atomic<bool> poisoned_{false};
    static VOID CALLBACK Timer(PVOID context,BOOLEAN) noexcept {
        static_cast<OwnershipRuntime*>(context)->Collect();
    }
public:
    OwnershipRuntime() {
        // 定时器只收取已收到析构完成通知的记录，时间本身不是释放条件。
        if (!CreateTimerQueueTimer(&timer_,nullptr,Timer,this,500,500,WT_EXECUTEDEFAULT))
            throw std::runtime_error("native_collector_start_failed");
    }
    bool Poisoned() const noexcept { return poisoned_.load(); }
    void Poison(const std::shared_ptr<RequestLease>& lease) noexcept {
        poisoned_.store(true);
        if (lease) lease->Quarantine();
    }
    OwnershipRecord* Find(std::uint64_t control) {
        for (auto p=records_;p;p=p->next) if (p->control == control) return p;
        return nullptr;
    }
    void Observe(OwnershipRecord* record,std::uint64_t control,bool image) {
        // 调用方仍持有强引用，记录/影子表完全建立后才交给消费者。
        if (!MemoryRange(control,32,false)) throw std::runtime_error("ownership_control_unreadable");
        record->control = control;
        record->image = image;
        record->original_control = *reinterpret_cast<std::uint64_t*>(control);
        if ((record->expected_control && record->expected_control != record->original_control)
            || record->original_control < 8 || !MemoryRange(record->original_control-8,40,false))
            throw std::runtime_error("ownership_control_type_mismatch");
        const auto table = reinterpret_cast<const std::uint64_t*>(record->original_control);
        std::memcpy(record->control_table,table-1,sizeof(record->control_table));
        record->control_table[1] = reinterpret_cast<std::uint64_t>(&ObservedMessageDestroy);
        if (image) {
            record->original_image = *reinterpret_cast<std::uint64_t*>(control+16);
            if ((record->expected_image && record->expected_image != record->original_image)
                || record->original_image < 8 || !MemoryRange(record->original_image-8,64,false))
                throw std::runtime_error("ownership_image_type_mismatch");
            std::memcpy(record->image_table,reinterpret_cast<const std::uint64_t*>(record->original_image)-1,
                sizeof(record->image_table));
            record->image_table[5] = reinterpret_cast<std::uint64_t>(&ObservedImageClone);
        }
        std::lock_guard<std::mutex> lock(mutex_);
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(control+12)); // 本模块的一份弱引用。
        record->next = records_;
        records_ = record;
        *reinterpret_cast<std::uint64_t*>(control) = reinterpret_cast<std::uint64_t>(record->control_table+1);
        if (image) *reinterpret_cast<std::uint64_t*>(control+16) = reinterpret_cast<std::uint64_t>(record->image_table+1);
    }
    void Destroy(std::uint64_t control) noexcept {
        OwnershipRecord* record = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            record = Find(control);
        }
        if (!record) { poisoned_.store(true); return; }
        const auto function = *reinterpret_cast<std::uint64_t*>(record->original_control);
        if (!CallInit(function,control)) { Poison(record->lease); return; }
        // 不能以强计数为零代替这一步：另一个线程可能还在执行成员析构。
        record->destroyed.store(true,std::memory_order_release);
    }
    void* Clone(std::uint64_t object,std::uint64_t* out) noexcept {
        std::shared_ptr<RequestLease> lease;
        std::uint64_t function = 0, expected_control = 0, expected_image = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto record = Find(object-16);
            if (!record) { poisoned_.store(true); return out; }
            lease = record->lease;
            function = reinterpret_cast<const std::uint64_t*>(record->original_image)[4];
            expected_control=record->original_control;
            expected_image=record->original_image;
        }
        // 在原生克隆前预留记录。内存不足时保守保留文件锁、禁止后续请求，
        // 仍让原生函数自行处理本次克隆，不把空指针伪装成成功结果。
        std::unique_ptr<OwnershipRecord> child(new(std::nothrow) OwnershipRecord);
        if (!child) Poison(lease);
        if (!CallClone(function,object,out)) { Poison(lease); return out; }
        if (!out[0] || !out[1] || out[0] != out[1]+16) { Poison(lease); return out; }
        if (child) {
            child->lease = lease;
            child->expected_control=expected_control;
            child->expected_image=expected_image;
            try { Observe(child.get(),out[1],true); child.release(); }
            catch (...) { Poison(lease); }
        }
        return out;
    }
    void Collect() noexcept {
        std::lock_guard<std::mutex> collecting(collector_mutex_);
        OwnershipRecord* ready = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto link=&records_;*link;) {
                auto record=*link;
                if (!record->destroyed.load(std::memory_order_acquire)) { link=&record->next; continue; }
                *link=record->next;
                record->next=ready;
                ready=record;
            }
        }
        while (ready) {
            auto record=ready;
            ready=record->next;
            // 强引用已结束且具体析构已返回；弱引用仍保护控制块。
            // 先还原虚表，避免其他合法弱引用在未来访问已释放的影子表。
            *reinterpret_cast<std::uint64_t*>(record->control)=record->original_control;
            const auto last=InterlockedDecrement(reinterpret_cast<volatile LONG*>(record->control+12)) == 0;
            if (last && !CallInit(reinterpret_cast<const std::uint64_t*>(record->original_control)[1],record->control)) {
                Poison(record->lease);
                // 释放入口可能已经产生副作用，不能再次读取或重试该控制块。
            }
            delete record;
        }
    }
    std::size_t Pending() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t n=0; for(auto p=records_;p;p=p->next) ++n; return n;
    }
};

OwnershipRuntime& NativeOwnership()
{
    // DLL 启动入口已经固定本模块。常量大小的运行时随进程退出由 OS 回收，
    // 避免 C++ 静态析构与线程池定时器在进程退出时互相竞争。
    static auto runtime=[] {
        auto value=new OwnershipRuntime;
        existing_ownership.store(value);
        return value;
    }();
    return *runtime;
}
void __fastcall ObservedMessageDestroy(std::uint64_t control) noexcept { NativeOwnership().Destroy(control); }
void* __fastcall ObservedImageClone(std::uint64_t object,std::uint64_t* out) noexcept { return NativeOwnership().Clone(object,out); }

struct NativeHeap : Heap {
    std::uint64_t base;
    std::shared_ptr<RequestLease> lease;
    NativeHeap(std::uint64_t value,std::shared_ptr<RequestLease> owner) : base(value),lease(std::move(owner)) {}
    void* Allocate(std::size_t bytes) override {
        void* result = nullptr;
        if (!CallAllocate(base+native_allocate_rva,bytes,result)) {
            NativeOwnership().Poison(lease);
            throw std::runtime_error("native_allocator_fault_no_retry");
        }
        return result;
    }
    void Free(void* pointer) noexcept override {
        if (!CallInit(base+native_free_rva,reinterpret_cast<std::uint64_t>(pointer))) NativeOwnership().Poison(lease);
    }
};

struct NativePrepared : PreparedCall {
    Request request;
    std::uint64_t base;
    Addresses address;
    std::shared_ptr<RequestLease> lease;
    std::string uuid;
    NativePrepared(const Request& value,std::uint64_t module,const Addresses& addresses,LockedImage&& image,
        RetentionBudget& budget=NativeRetentionBudget(),std::shared_ptr<NativeModuleReference> reference={},LockedImage&& thumbnail=LockedImage{})
        : request(value),base(module),address(addresses),lease(std::make_shared<RequestLease>(std::move(image),budget,std::move(reference),std::move(thumbnail))),
          uuid(value.kind == "file" || value.kind == "image" ? Guid() : "") {
        if (NativeOwnership().Poisoned()) throw std::runtime_error("native_ownership_fault_requires_investigation");
    }
    Result Run() override {
        if (NativeOwnership().Poisoned())
            return {202,"unconfirmed","native_ownership_fault_no_retry",true};
        NativeHeap heap(base,lease);
        Arena arena(heap);
        // 到这里 Controller 已持久消耗许可；Prepare 不分配原生对象、不调用私有函数。
        std::unique_ptr<OwnershipRecord> record(new OwnershipRecord);
        record->lease=lease;
        record->expected_control=request.kind == "video" ? address.video_vtable : request.kind == "link" ? address.link_vtable : request.kind == "file" ? address.file_vtable :
            request.kind == "image" ? address.image_vtable : address.text_vtable;
        record->expected_image=request.kind == "video" ? address.video_vtable2 : request.kind == "link" ? address.link_vtable2 : request.kind == "file" ? address.file_vtable2 : address.image_vtable2;
        Frame frame;
        LinkStrings link_strings;
        WideString thumbnail{};
        try {
            frame=BuildFrame(arena,address,request.recipient,request.kind == "text" ? request.value : "",
                request.kind == "image" || request.kind == "file" || request.kind == "video" ? &lease->image.path : nullptr,lease->image.size,uuid,true,
                request.kind == "file",request.value.substr(request.value.find_last_of('\\')+1),request.kind == "link",request.kind == "video");
            if(frame.link) link_strings=MakeLinkStrings(arena,request.title,request.description,request.value);
            if(frame.video) thumbnail=MakeWide(arena,lease->thumbnail.path,true);
        } catch (...) {
            if (NativeOwnership().Poisoned()) arena.RetainOnNativeEntry();
            return {202,"unconfirmed","native_frame_allocation_failed_no_retry",true};
        }
        arena.RetainOnNativeEntry(); // 后续若异常，不能猜测半构造状态；仅正常路径配对释放。
        auto fault = [&](const char* error) {
            NativeOwnership().Poison(lease);
            return Result{202,"unconfirmed",error,true};
        };
        if (frame.video) {
            if (!CallInit(base+0x18efd70,reinterpret_cast<std::uint64_t>(frame.object)+16))
                return fault("video_constructor_fault_no_retry");
            try { FinishVideoFrame(frame,thumbnail,lease->image.size,request.duration_seconds); }
            catch (...) { return fault("video_constructor_layout_unknown_no_retry"); }
        } else if (frame.link) {
            if (!CallInit(base+0x2b52b90,reinterpret_cast<std::uint64_t>(frame.object)+16))
                return fault("link_constructor_fault_no_retry");
            try { FinishLinkFrame(frame,link_strings); }
            catch (...) { return fault("link_constructor_layout_unknown_no_retry"); }
        } else if (frame.file) {
            NarrowString empty_uuid{}; empty_uuid.capacity=15;
            // 复用两参数 SEH 调用桥，此处仅执行构造器，并非发送。
            if (!CallSubmit(base+0x6b2d30,reinterpret_cast<std::uint64_t>(frame.object)+16,
                reinterpret_cast<std::uint64_t>(&empty_uuid))) return fault("file_constructor_fault_no_retry");
            try { FinishFileFrame(frame,lease->image.size); }
            catch (...) { return fault("file_constructor_layout_unknown_no_retry"); }
        } else if (!frame.image) {
            if (!CallInit(base+offset::txt_message_ctr,reinterpret_cast<std::uint64_t>(frame.object)+16))
                return fault("text_constructor_fault_no_retry");
            try { FinishTextFrame(frame); }
            catch (...) { return fault("text_constructor_layout_unknown_no_retry"); }
        }
        try {
            NativeOwnership().Observe(record.get(),reinterpret_cast<std::uint64_t>(frame.object),frame.image || frame.link || frame.video);
            record.release();
        } catch (...) { return fault("ownership_observer_failed_no_retry"); }
        if (!CallCreate(base+offset::create_param2,reinterpret_cast<std::uint64_t>(frame.arg2),
            reinterpret_cast<std::uint64_t>(frame.nodes[0]),reinterpret_cast<std::uint64_t>(frame.nodes[1]),
            reinterpret_cast<std::uint64_t>(frame.nodes[2]),reinterpret_cast<std::uint64_t>(frame.scratch),address.context))
            return fault("parameter_constructor_fault_no_retry");
        if (!CallSubmit(base+offset::send_message,reinterpret_cast<std::uint64_t>(frame.arg1),reinterpret_cast<std::uint64_t>(frame.arg2)))
            return fault("submit_fault_no_retry");
        // 参数复制完成后，仅撤销源组合状态的一份所有权。队列、消息克隆继续拥有各自引用。
        if (!CallInit(base+native_state_destroy_rva,reinterpret_cast<std::uint64_t>(frame.state)))
            return fault("source_destructor_fault_no_retry");
        for (auto p : {static_cast<void*>(frame.arg1),frame.state,frame.scratch,
            static_cast<void*>(frame.nodes[0]),static_cast<void*>(frame.nodes[1]),static_cast<void*>(frame.nodes[2])}) {
            heap.Free(p);
            if (NativeOwnership().Poisoned()) return fault("native_temporary_free_fault_no_retry");
        }
        NativeOwnership().Collect();
        if (NativeOwnership().Poisoned()) return fault("native_ownership_fault_no_retry");
        return {202,"unconfirmed","native_result_not_delivery_receipt",true};
    }
};

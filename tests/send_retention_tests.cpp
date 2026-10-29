#include "../src/send_native.cpp" // 实际 NativePrepared/Arena/LockedImage，只有私有 Invoker 和堆是替身。
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <thread>

using namespace send_fix;
namespace {
int checks = 0;
void Check(bool value) { if (!value) throw std::runtime_error("check_"+std::to_string(checks+1)); ++checks; }
struct TestHeap : Heap {
    std::map<void*,std::size_t> live;
    std::size_t freed = 0;
    void* Allocate(std::size_t bytes) override {
        auto p = std::calloc(1,bytes); if (!p) return nullptr;
        try { live.emplace(p,bytes); } catch (...) { std::free(p); throw; } return p;
    }
    void Free(void* p) noexcept override { live.erase(p); ++freed; std::free(p); }
    ~TestHeap() { for (auto pair : live) std::free(pair.first); } // 合成消费者已结束，清理测试自身保留量。
};
struct FakeInvoker : Invoker {
    int entered = 0;
    bool fail = false;
    bool RetainsArguments() const override { return true; }
    bool InitText(std::uint64_t) override { ++entered; return !fail; }
    bool CreateParams(std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t) override
    { ++entered; return !fail; }
    bool Submit(std::uint64_t,std::uint64_t) override { ++entered; return !fail; }
};
Request Text(int id) { return ParseRequest("text",nlohmann::json{{"request_id","offline-retain-"+std::to_string(id)},
    {"wxidorgid","1234567890@chatroom"},{"msg",u8"离线资源测试"}}.dump()); }
Approval Permit(const Request& r) { return {true,std::string(40,'a'),r.id,r.recipient,r.kind,Fingerprint(r),
    std::string(64,'f'),0,2}; }
struct FixtureBackend : Backend {
    TestHeap& heap; RetentionBudget& budget; FakeInvoker& invoke;
    FixtureBackend(TestHeap& h, RetentionBudget& b, FakeInvoker& i) : heap(h),budget(b),invoke(i) {}
    std::unique_ptr<PreparedCall> Prepare(const Request& r,const Approval&) override {
        return std::make_unique<NativePrepared>(r,0,Addresses{},LockedImage{},heap,budget,&invoke);
    }
    RetentionUsage Retention() override { return budget.Usage(); }
};
std::size_t FrameBytes(const Request& r) {
    TestHeap heap; Arena arena(heap); BuildFrame(arena,Addresses{},r.recipient,r.value,nullptr,0,""); return arena.Bytes();
}
}
int main() {
    try {
        const auto request = Text(1); const auto bytes = FrameBytes(request);
        {
            // 未进入私有函数的准备/撤销可以完整回收；进入后不猜测异步生命周期。
            TestHeap heap; FakeInvoker invoke; RetentionBudget budget(bytes,0);
            { NativePrepared call(request,0,Addresses{},LockedImage{},heap,budget,&invoke);
              Check(budget.Usage().bytes == bytes); Check(!heap.live.empty()); }
            Check(budget.Usage().bytes == 0 && heap.live.empty() && invoke.entered == 0);
            { NativePrepared call(request,0,Addresses{},LockedImage{},heap,budget,&invoke); call.Run(); }
            Check(budget.Usage().bytes == bytes && !heap.live.empty());
            const auto freed = heap.freed; const auto held = heap.live.size();
            try { NativePrepared rejected(Text(2),0,Addresses{},LockedImage{},heap,budget,&invoke); Check(false); }
            catch (const std::runtime_error& error) { Check(std::string(error.what()) == "native_retention_budget_exceeded"); }
            Check(heap.live.size() == held && heap.freed > freed && budget.Usage().bytes == bytes);
        }
        {
            // 原审核的 8 条文字 + 4 条图片在此之前已应被累计预算阻止，不随新许可归零。
            TestHeap heap; FakeInvoker invoke; RetentionBudget budget(bytes*6,0);
            FixtureBackend backend(heap,budget,invoke); Approval approval; int consumed = 0;
            Controller controller([&] { return approval; },backend,[&](const Approval&) { ++consumed; return true; });
            for (int i=1;i<=6;++i) {
                auto r=Text(i); approval=Permit(r);
                auto result=controller.Dispatch("Bearer "+approval.token,"text",
                    nlohmann::json{{"request_id",r.id},{"wxidorgid",r.recipient},{"msg",r.value}}.dump());
                Check(result.http == 202 && result.native_entered);
            }
            const auto native_calls=invoke.entered; auto last=Text(7); approval=Permit(last);
            const auto body=nlohmann::json{{"request_id",last.id},{"wxidorgid",last.recipient},{"msg",last.value}}.dump();
            auto result=controller.Dispatch("Bearer "+approval.token,"text",body);
            Check(result.http == 503 && result.error == "native_retention_budget_exceeded" && !result.native_entered);
            Check(consumed == 6 && invoke.entered == native_calls && approval.request_id == last.id);
            Check(controller.Status().configured && !controller.Status().consumed);
            FixtureBackend another(heap,budget,invoke);
            Controller recreated([&] { return approval; },another,[&](const Approval&) { ++consumed; return true; });
            Check(recreated.Dispatch("Bearer "+approval.token,"text",body).http == 503 && consumed == 6);
            Check(budget.Usage().bytes == bytes*6);
        }
        {
            // 消耗前撤销：释放预留和所有参数，下一份许可可以使用同一额度。
            TestHeap heap; FakeInvoker invoke; RetentionBudget budget(bytes,0); FixtureBackend backend(heap,budget,invoke);
            auto approval=Permit(request); bool allow=false; int consumed=0;
            Controller c([&] { return approval; },backend,[&](const Approval&) { if (!allow) return false; ++consumed; return true; });
            const auto body=nlohmann::json{{"request_id",request.id},{"wxidorgid",request.recipient},{"msg",request.value}}.dump();
            Check(c.Dispatch("Bearer "+approval.token,"text",body).http == 423);
            Check(budget.Usage().bytes == 0 && heap.live.empty() && invoke.entered == 0 && consumed == 0);
            allow=true; Check(c.Dispatch("Bearer "+approval.token,"text",body).http == 202 && consumed == 1);
        }
        {
            // 使用真实许可文件和真实 ConsumeApproval：额度不足时不创建持久消耗标记。
            wchar_t root[32768]{}; Check(GetTempPathW(32768,root) != 0);
            const auto directory=std::filesystem::path(root)/(L"wechat-retain-offline-"+std::to_wstring(GetCurrentProcessId()));
            Check(std::filesystem::create_directory(directory));
            struct Cleanup { std::filesystem::path path; ~Cleanup() { std::error_code e; std::filesystem::remove_all(path,e); } } cleanup{directory};
            const auto path=directory/L"synthetic-approval.json"; const auto approval=Permit(request);
            const auto value=nlohmann::json{{"version",approval.version},{"enabled",true},{"token",approval.token},
                {"request_id",approval.request_id},{"recipient",approval.recipient},{"kind",approval.kind},
                {"payload_sha256",approval.payload_sha256},{"module_sha256",approval.module_sha256},{"expires_utc",0}}.dump();
            { std::ofstream file(path,std::ios::binary); file << value; Check(bool(file)); }
            TestHeap heap; FakeInvoker invoke; RetentionBudget budget(0,0); FixtureBackend backend(heap,budget,invoke); int consumed=0;
            Controller c([&] { return LoadApproval(path.wstring()); },backend,
                [&](const Approval& a) { ++consumed; return ConsumeApproval(path.wstring(),a); });
            const auto body=nlohmann::json{{"request_id",request.id},{"wxidorgid",request.recipient},{"msg",request.value}}.dump();
            Check(c.Dispatch("Bearer "+approval.token,"text",body).http == 503);
            Check(consumed == 0 && invoke.entered == 0 && LoadApproval(path.wstring()).enabled);
            const auto marker=path.wstring()+L".used-"+std::wstring(request.id.begin(),request.id.end());
            Check(!std::filesystem::exists(marker) && heap.live.empty());
            std::ifstream file(path,std::ios::binary); const std::string after((std::istreambuf_iterator<char>(file)),{});
            Check(after == value);
        }
        for (bool enter : {false,true}) {
            TestHeap heap; FakeInvoker invoke; RetentionBudget budget(128*1024,3);
            auto image_request=ParseRequest("image",R"({"request_id":"offline-image-retention","wxidorgid":"1234567890@chatroom","path":"C:\\fixture\\image.png","image_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})");
            HANDLE handles[3]{};
            for (auto& h : handles) { h=CreateEventW(nullptr,TRUE,FALSE,nullptr); Check(h != nullptr); }
            {
                LockedImage image; image.file=handles[0]; image.parents={handles[1],handles[2]};
                image.path=u"C:\\fixture\\image.png"; image.size=12;
                NativePrepared call(image_request,0,Addresses{},std::move(image),heap,budget,&invoke);
                Check(budget.Usage().handles == 3);
                if (enter) call.Run();
            }
            Check(budget.Usage().handles == (enter?3:0));
            for (auto h : handles) { DWORD flags=0; Check((GetHandleInformation(h,&flags)!=FALSE) == enter); if (enter) CloseHandle(h); }
            if (enter) {
                const auto before=invoke.entered;
                bool rejected=false;
                try { auto reservation=budget.Reserve(1,1); }
                catch (const std::runtime_error&) { rejected=true; }
                Check(rejected && invoke.entered == before);
            } else Check(heap.live.empty());
        }
        {
            // 图片文件和所有父目录句柄共用同一上限；超限时实际析构关闭本次全部句柄。
            TestHeap heap; FakeInvoker invoke; RetentionBudget budget(128*1024,0);
            auto image_request=ParseRequest("image",R"({"request_id":"offline-image-rejected","wxidorgid":"1234567890@chatroom","path":"C:\\fixture\\image.png","image_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})");
            HANDLE handles[3]{};
            for (auto& h : handles) { h=CreateEventW(nullptr,TRUE,FALSE,nullptr); Check(h != nullptr); }
            bool rejected=false;
            try {
                LockedImage image; image.file=handles[0]; image.parents={handles[1],handles[2]};
                image.path=u"C:\\fixture\\image.png"; image.size=12;
                NativePrepared call(image_request,0,Addresses{},std::move(image),heap,budget,&invoke);
            } catch (const std::runtime_error& error) { rejected=std::string(error.what()) == "native_retention_budget_exceeded"; }
            Check(rejected && heap.live.empty() && invoke.entered == 0);
            Check(budget.Usage().bytes == 0 && budget.Usage().handles == 0);
            for (auto h : handles) { DWORD flags=0; Check(GetHandleInformation(h,&flags) == FALSE); }
        }
        {
            TestHeap heap; FakeInvoker invoke; invoke.fail=true; RetentionBudget budget(bytes,0);
            { NativePrepared call(request,0,Addresses{},LockedImage{},heap,budget,&invoke);
              Check(call.Run().error == "text_constructor_fault_no_retry"); }
            Check(budget.Usage().bytes == bytes && !heap.live.empty());
        }
        {
            // 同一生产进程的不同 backend 使用同一计数器，不能由 controller 重建清零。
            WindowsBackend first,second;
            auto reservation=NativeRetentionBudget().Reserve(1,1);
            Check(first.Retention().bytes == 1 && second.Retention().handles == 1);
            Check(first.Retention().byte_limit == 16*1024*1024 && first.Retention().handle_limit == 256);
        }
        Check(NativeRetentionBudget().Usage().bytes == 0 && NativeRetentionBudget().Usage().handles == 0);
        std::cout << "PASS native_retention checks=" << checks << "; actual preparation/retention, no real native calls\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}

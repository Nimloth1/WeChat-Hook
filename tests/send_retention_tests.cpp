#include "../src/send_native.cpp"
#include <iostream>
#include <filesystem>
#include <fstream>
using namespace send_fix;
static int checks=0;
void Check(bool ok) { if(!ok) throw std::runtime_error("preflight_"+std::to_string(checks+1));++checks; }
Request Text(int n) { return ParseRequest("text",nlohmann::json{{"request_id","offline-preflight-"+std::to_string(n)},
    {"wxidorgid","12345678901@chatroom"},{"msg","hello"}}.dump()); }
struct FixtureBackend : Backend {
    RetentionBudget& budget;
    explicit FixtureBackend(RetentionBudget& b):budget(b){}
    std::unique_ptr<PreparedCall> Prepare(const Request& r,const Approval&) override {
        return std::make_unique<NativePrepared>(r,0,Addresses{},LockedImage{},budget);
    }
};
int main() {
    try {
        Check(GetModuleHandleW(L"Weixin.dll")==nullptr);
        for(int i=0;i<1000;++i) {
            RetentionBudget budget(128*1024,0);
            { NativePrepared p(Text(i),0,Addresses{},LockedImage{},budget);Check(budget.Usage().bytes==128*1024); }
            Check(budget.Usage().bytes==0);
        }
        {
            RetentionBudget budget(128*1024,0);FixtureBackend backend(budget);const auto r=Text(1001);
            Approval a{true,std::string(40,'a'),r.id,r.recipient,r.kind,Fingerprint(r),std::string(64,'f'),0,2};
            int consumed=0;
            Controller c([&]{return a;},backend,[&](const Approval&){++consumed;return false;});
            auto result=c.Dispatch("Bearer "+a.token,"text",nlohmann::json{{"request_id",r.id},{"wxidorgid",r.recipient},{"msg",r.value}}.dump());
            Check(result.http==423 && consumed==1 && budget.Usage().bytes==0);
        }
        {
            RetentionBudget budget(128*1024,3);HANDLE handles[3]{};
            for(auto& h:handles){h=CreateEventW(nullptr,TRUE,FALSE,nullptr);Check(h!=nullptr);}
            { LockedImage image;image.file=handles[0];image.parents={handles[1],handles[2]};
              NativePrepared p(Text(1002),0,Addresses{},std::move(image),budget);Check(budget.Usage().handles==3); }
            Check(budget.Usage().handles==0 && budget.Usage().bytes==0);
            for(auto h:handles){DWORD flags=0;Check(!GetHandleInformation(h,&flags));}
        }
        {
            RetentionBudget budget(128*1024,0);
            NativePrepared p(Text(1003),0,Addresses{},LockedImage{},budget);
            try{NativePrepared rejected(Text(1004),0,Addresses{},LockedImage{},budget);Check(false);}
            catch(const std::runtime_error& e){Check(std::string(e.what())=="native_retention_budget_exceeded");}
            Check(budget.Usage().bytes==128*1024);
        }
        {
            // 真实临时许可与 ConsumeApproval：额度不足不能消耗许可或创建标记。
            wchar_t root[32768]{};Check(GetTempPathW(32768,root)!=0);
            const auto directory=std::filesystem::path(root)/(L"wechat-preflight-offline-"+std::to_wstring(GetCurrentProcessId()));
            Check(std::filesystem::create_directory(directory));
            struct Cleanup{std::filesystem::path p;~Cleanup(){std::error_code e;std::filesystem::remove_all(p,e);}} cleanup{directory};
            const auto path=directory/L"synthetic-approval.json";const auto r=Text(1005);
            Approval a{true,std::string(40,'a'),r.id,r.recipient,r.kind,Fingerprint(r),std::string(64,'f'),0,2};
            const auto value=nlohmann::json{{"version",2},{"enabled",true},{"token",a.token},{"request_id",a.request_id},
                {"recipient",a.recipient},{"kind",a.kind},{"payload_sha256",a.payload_sha256},
                {"module_sha256",a.module_sha256},{"expires_utc",0}}.dump();
            {std::ofstream f(path,std::ios::binary);f<<value;Check(bool(f));}
            RetentionBudget budget(128*1024,0);int consumed=0;
            NativePrepared pending(Text(1006),0,Addresses{},LockedImage{},budget);
            for(int i=0;i<2;++i){
                FixtureBackend backend(budget);
                Controller c([&]{return LoadApproval(path.wstring());},backend,[&](const Approval& permit){++consumed;return ConsumeApproval(path.wstring(),permit);});
                auto result=c.Dispatch("Bearer "+a.token,"text",nlohmann::json{{"request_id",r.id},{"wxidorgid",r.recipient},{"msg",r.value}}.dump());
                Check(result.http==503 && result.error=="native_retention_budget_exceeded" && !result.native_entered);
                Check(consumed==0 && LoadApproval(path.wstring()).enabled && !c.Attempted());
            }
            Check(!std::filesystem::exists(path.wstring()+L".used-"+std::wstring(r.id.begin(),r.id.end())));
            std::ifstream f(path,std::ios::binary);std::string after((std::istreambuf_iterator<char>(f)),{});Check(after==value);
        }
        {
            RetentionBudget budget(128*1024,0);HANDLE handles[3]{};
            for(auto& h:handles){h=CreateEventW(nullptr,TRUE,FALSE,nullptr);Check(h!=nullptr);}
            bool rejected=false;
            try{LockedImage image;image.file=handles[0];image.parents={handles[1],handles[2]};
                NativePrepared p(Text(1007),0,Addresses{},std::move(image),budget);}
            catch(const std::runtime_error& e){rejected=std::string(e.what())=="native_retention_budget_exceeded";}
            Check(rejected && budget.Usage().bytes==0 && budget.Usage().handles==0);
            for(auto h:handles){DWORD flags=0;Check(!GetHandleInformation(h,&flags));}
        }
        {
            WindowsBackend first,second;
            {auto held=NativeRetentionBudget().Reserve(1,1);
             Check(first.Retention().bytes==1 && second.Retention().handles==1);
             Check(first.Retention().byte_limit==16*1024*1024 && second.Retention().handle_limit==256);}
            Check(first.Retention().bytes==0 && second.Retention().handles==0);
        }
        Check(NativeOwnership().Pending()==0 && !NativeOwnership().Poisoned());
        Check(GetModuleHandleW(L"Weixin.dll")==nullptr);
        std::cout<<"PASS native_preflight checks="<<checks<<"; actual NativePrepared; no private calls\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}

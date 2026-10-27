#include "httplib.h"
#include "send_api.h"
#include "send_native.h"
#include "send_routes.h"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

using namespace send_fix;
using json = nlohmann::json;
static int checks = 0;
void CheckAt(bool value,int line) { ++checks; if (!value) throw std::runtime_error("api_assertion_failed_at_line_"+std::to_string(line)); }
#define Check(value) CheckAt((value),__LINE__)
const std::string fixture_token(40,'a'); // 只用于测试进程，不生成真实许可。

std::string Body(const std::string& text = u8"离线合成内容😀") {
    return json{{"request_id","offline-request-0001"},{"wxidorgid","wxid_offline_fixture"},{"msg",text}}.dump();
}
Approval Permit(const std::string& body = Body()) {
    auto request = ParseRequest("text",body);
    return {true,fixture_token,request.id,request.recipient,"text",Fingerprint(request),std::string(64,'f'),std::time(nullptr)+300};
}
struct FakeBackend : Backend {
    std::atomic<int> prepare{0},run{0};
    int failure = 0;
    struct Call : PreparedCall {
        FakeBackend& parent;
        explicit Call(FakeBackend& p) : parent(p) {}
        Result Run() override {
            ++parent.run;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            if (parent.failure == 3) throw std::runtime_error("fixture_native_fault");
            // 故意尝试虚报成功，controller 必须强制保持 unconfirmed。
            return {200,"sent","",true};
        }
    };
    std::unique_ptr<PreparedCall> Prepare(const Request&,const Approval&) override {
        ++prepare;
        if (failure == 1) throw std::bad_alloc();
        if (failure == 2) throw std::runtime_error("fixture_preflight_failure");
        return std::make_unique<Call>(*this);
    }
};

struct TempDir {
    std::filesystem::path path;
    TempDir() {
        wchar_t root[32768]{};
        if (!GetTempPathW(32768,root)) throw std::runtime_error("temp_path_failed");
        path = std::filesystem::path(root)/(L"wechat-send-offline-"+std::to_wstring(GetCurrentProcessId()));
        if (!std::filesystem::create_directory(path)) throw std::runtime_error("temp_collision");
    }
    ~TempDir() { std::error_code error; std::filesystem::remove_all(path,error); }
};
void Write(const std::filesystem::path& path,const std::string& bytes) {
    std::ofstream file(path,std::ios::binary); file.write(bytes.data(),bytes.size());
    if (!file) throw std::runtime_error("fixture_write_failed");
}
json PermitJson(const Approval& a) {
    return {{"version",1},{"enabled",true},{"token",a.token},{"request_id",a.request_id},
        {"recipient",a.recipient},{"kind",a.kind},{"payload_sha256",a.payload_sha256},
        {"module_sha256",a.module_sha256},{"expires_utc",a.expires}};
}

int main()
{
    try {
        Check(GetModuleHandleW(L"Weixin.dll") == nullptr);
        Check(Sha256("abc",3) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        const std::string auth = "Bearer "+fixture_token;
        {
            FakeBackend backend; int consumed = 0;
            Controller controller({},backend,[&](const Approval&) { ++consumed; return true; });
            Check(controller.Dispatch(auth,"text",Body()).http == 423);
            Check(backend.prepare == 0 && backend.run == 0 && consumed == 0);
        }
        {
            FakeBackend backend; Controller c(Permit(),backend,[](const Approval&) {return true;});
            for (const auto& input : {"{}","[]","null","{",R"({"request_id":"offline-request-0001","wxidorgid":"wxid_offline_fixture","msg":123})",
                R"({"request_id":"offline-request-0001","wxidorgid":"wxid_offline_fixture","msg":"x","extra":true})"})
                Check(c.Dispatch(auth,"text",input).http == 400);
            for (const auto& bad : {std::string(""),std::string(" \n\t"),std::string("a\0b",3),std::string(2001,'x')})
                Check(c.Dispatch(auth,"text",Body(bad)).http == 400);
            Check(c.Dispatch("Bearer incorrect","text",Body()).http == 403);
            Check(c.Dispatch(auth,"text",Body("different content")).http == 403);
            auto wrong = json::parse(Body()); wrong["wxidorgid"] = u8"中文联系人";
            Check(c.Dispatch(auth,"text",wrong.dump()).http == 400); // 不把显示名当内部接收人 ID。
            Check(backend.prepare == 0 && backend.run == 0);
        }
        {
            auto a = Permit(); a.expires = std::time(nullptr)-1;
            FakeBackend backend; Controller c(a,backend,[](const Approval&) {return true;});
            Check(c.Dispatch(auth,"text",Body()).http == 403 && backend.prepare == 0);
        }
        for (int failure : {1,2,3,4}) {
            FakeBackend backend; backend.failure = failure;
            Controller c(Permit(),backend,[&](const Approval&) {return failure != 4;});
            const auto response = c.Dispatch(auth,"text",Body());
            Check(response.http == (failure == 1 ? 503 : failure == 2 ? 422 : failure == 4 ? 423 : 202));
            Check(backend.run == (failure == 3 ? 1 : 0));
            Check(Response(response)["IsSent"].is_null() && Response(response)["DeliveryConfirmed"] == false);
            if (failure == 3) {
                auto replay = c.Dispatch(auth,"text",Body());
                Check(replay.replayed && replay.http == 202 && backend.run == 1);
            }
        }
        {
            FakeBackend backend; std::atomic<int> consumed{0};
            Controller c(Permit(),backend,[&](const Approval&) {++consumed;return true;});
            std::vector<std::thread> callers;
            for (int i = 0; i < 32; ++i) callers.emplace_back([&] {c.Dispatch(auth,"text",Body());});
            for (auto& caller : callers) caller.join();
            Check(backend.run == 1 && backend.prepare == 1 && consumed == 1);
            auto result = c.Dispatch(auth,"text",Body());
            Check(result.http == 202 && result.state == "unconfirmed" && result.replayed);
            Check(Response(result)["ret"] != 0 && Response(result)["IsSent"].is_null());
            Check(c.Dispatch(auth,"text",Body("different content")).http == 409 && backend.run == 1);
        }
        TempDir temp;
        {
            const auto path = temp.path/L"send-approval.json";
            Check(!LoadApproval(path.wstring()).enabled);
            for (const auto& invalid : {std::string("{}"),std::string("invalid"),std::string(8193,'x')}) {
                Write(path,invalid); Check(!LoadApproval(path.wstring()).enabled);
            }
            auto approval = Permit(); Write(path,PermitJson(approval).dump());
            Check(LoadApproval(path.wstring()).enabled);
            FakeBackend backend;
            Controller c(LoadApproval(path.wstring()),backend,[&](const Approval& a) {return ConsumeApproval(path.wstring(),a);});
            Check(c.Dispatch(auth,"text",Body()).http == 202 && backend.run == 1);
            Check(!LoadApproval(path.wstring()).enabled);
            Check(!ConsumeApproval(path.wstring(),approval));
            Controller restarted(LoadApproval(path.wstring()),backend,[&](const Approval& a) {return ConsumeApproval(path.wstring(),a);});
            Check(restarted.Dispatch(auth,"text",Body()).http == 423 && backend.run == 1);
        }
        {
            const auto path = temp.path/L"approval-race.json";
            const auto a = Permit(); Write(path,PermitJson(a).dump());
            FakeBackend first_backend, second_backend;
            Controller first(LoadApproval(path.wstring()),first_backend,[&](const Approval& p) {return ConsumeApproval(path.wstring(),p);});
            Controller second(LoadApproval(path.wstring()),second_backend,[&](const Approval& p) {return ConsumeApproval(path.wstring(),p);});
            std::thread one([&] {first.Dispatch(auth,"text",Body());});
            std::thread two([&] {second.Dispatch(auth,"text",Body());});
            one.join(); two.join();
            Check(first_backend.run + second_backend.run == 1);
            Check(!LoadApproval(path.wstring()).enabled);
        }
        {
            const auto path = temp.path/L"approval-changed.json";
            const auto a = Permit(); Write(path,PermitJson(a).dump());
            auto changed = PermitJson(a); changed["recipient"] = "wxid_different_fixture";
            Write(path,changed.dump());
            Check(!ConsumeApproval(path.wstring(),a));
        }
        {
            const auto name = temp.path/std::filesystem::path(L"\x4e2d\x6587\x62a5\x544a.png");
            const std::string image("\x89PNG\r\n\x1a\nfixture",15);
            Write(name,image);
            const auto utf8 = name.u8string();
            auto body = json{{"request_id","offline-image-0001"},{"wxidorgid","wxid_offline_fixture"},
                {"path",utf8},{"image_sha256",Sha256(image.data(),image.size())}}.dump();
            auto request = ParseRequest("image",body);
            std::uint64_t size = 0; auto file = OpenImage(request,size);
            Check(file != INVALID_HANDLE_VALUE && size == image.size());
            auto writer = CreateFileW(name.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
            Check(writer == INVALID_HANDLE_VALUE); if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
            CloseHandle(file);
            request.image_sha256 = std::string(64,'0'); bool failed = false;
            try { CloseHandle(OpenImage(request,size)); } catch (...) { failed = true; } Check(failed);
            for (const auto& path : {std::string("relative.png"),std::string("\\\\server\\image.png"),std::string("C:\\..\\x.png")}) {
                request.value = path; request.unicode = Utf16(path); failed = false;
                try { CloseHandle(OpenImage(request,size)); } catch (...) {failed = true;} Check(failed);
            }
            Write(name,"GIF89a fixture"); request.value = utf8; request.unicode = Utf16(utf8); failed = false;
            try { CloseHandle(OpenImage(request,size)); } catch (...) {failed = true;} Check(failed);
        }
        {
            // 真正生产后端在没有微信模块时必须停止；不主动 LoadLibrary 微信。
            WindowsBackend backend; Controller c(Permit(),backend,[](const Approval&) {return true;});
            const auto result = c.Dispatch(auth,"text",Body());
            Check(result.http == 422 && !c.Attempted() && result.error == "wechat_module_missing");
            Check(GetModuleHandleW(L"Weixin.dll") == nullptr);
        }
        {
            FakeBackend backend; Controller c(Permit(),backend,[](const Approval&) {return true;});
            httplib::Server server;
            RegisterSendRoutes(server,c);
            const auto port = server.bind_to_any_port("127.0.0.1"); Check(port > 0);
            httplib::Server collision; Check(!collision.bind_to_port("127.0.0.1",port));
            std::thread listener([&] {server.listen_after_bind();});
            server.wait_until_ready();
            httplib::Client client("127.0.0.1",port);
            client.set_connection_timeout(2,0); client.set_read_timeout(3,0);
            const auto status = client.Get("/QueryDB/status");
            auto request = client.Post("/SendTextMsg",Body(),"application/json");
            const auto sql = client.Post("/QueryDB/execute","{}","application/json");
            const auto file = client.Post("/send_file_msg","{}","application/json");
            const httplib::Headers headers{{"Authorization",auth}};
            auto invalid = client.Post("/SendTextMsg",headers,"{}","application/json");
            auto sent = client.Post("/SendTextMsg",headers,Body(),"application/json");
            auto duplicate = client.Post("/SendTextMsg",headers,Body(),"application/json");
            auto oversized = client.Post("/SendTextMsg",headers,std::string(32769,'x'),"application/json");
            server.stop(); listener.join(); collision.stop();
            Check(status && status->status == 200 && json::parse(status->body)["IsLogin"].is_null());
            Check(request && request->status == 403);
            Check(sql && sql->status == 404 && file && file->status == 501);
            Check(invalid && invalid->status == 400);
            Check(sent && sent->status == 202 && duplicate && duplicate->status == 202 && backend.run == 1);
            Check(json::parse(sent->body)["IsSent"].is_null());
            Check(oversized && oversized->status == 413 && backend.run == 1);
        }
        {
            FakeBackend backend; Controller locked({},backend,[](const Approval&) {return true;});
            httplib::Server server; RegisterSendRoutes(server,locked);
            const auto port = server.bind_to_any_port("127.0.0.1"); Check(port > 0);
            std::thread listener([&] {server.listen_after_bind();}); server.wait_until_ready();
            httplib::Client client("127.0.0.1",port);
            client.set_connection_timeout(2,0); client.set_read_timeout(3,0);
            const auto result = client.Post("/SendTextMsg",Body(),"application/json");
            server.stop(); listener.join();
            Check(result && result->status == 423 && backend.prepare == 0 && backend.run == 0);
        }
        Check(GetModuleHandleW(L"Weixin.dll") == nullptr);
        std::cout << "PASS send_api checks=" << checks << "; fake backend only; no WeChat private function called\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL checks=" << checks << ' ' << error.what() << '\n';
        return 1;
    }
}

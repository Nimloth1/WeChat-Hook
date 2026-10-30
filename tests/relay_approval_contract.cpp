// 只解析合成许可及调用Controller的替身后端；不链接send_native.cpp，不加载/连接微信。
// macOS适配系统I/O和SHA256；Windows使用真实WinAPI和bcrypt。
#include "send_native.h"
#include <filesystem>
#include <iostream>

namespace {
struct Prepared final : send_fix::PreparedCall {
    int& calls;
    explicit Prepared(int& value) : calls(value) {}
    send_fix::Result Run() override {
        ++calls;
        return {202, "unconfirmed", "offline_backend_only", true};
    }
};
struct Backend final : send_fix::Backend {
    int calls = 0;
    std::unique_ptr<send_fix::PreparedCall> Prepare(const send_fix::Request&, const send_fix::Approval&) override {
        return std::make_unique<Prepared>(calls);
    }
};
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    try {
        const auto path = std::filesystem::path(argv[1]).wstring();
        nlohmann::json request;
        std::cin >> request;
        Backend backend;
        send_fix::Controller controller([&] { return send_fix::LoadApproval(path); }, backend,
            [&](const send_fix::Approval& approval) { return send_fix::ConsumeApproval(path, approval); });
        nlohmann::json result;
        if (request.at("operation") == "status") {
            const auto approval = send_fix::LoadApproval(path);
            result = {{"configured", controller.Status().configured},
                {"lifetime_valid", send_fix::ApprovalLifetimeValid(approval)},
                {"version", approval.version}, {"expires_utc", approval.expires}};
        } else if (request.at("operation") == "dispatch") {
            const auto value = controller.Dispatch(request.at("authorization"), request.at("kind"),
                request.at("body").dump());
            result = {{"http", value.http}, {"response", send_fix::Response(value)}};
        } else return 3;
        result["backend_calls"] = backend.calls;
        std::cout << result.dump() << '\n';
        return 0;
    } catch (...) {
        std::cerr << "offline_contract_fixture_failed\n";
        return 4;
    }
}

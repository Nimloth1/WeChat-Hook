// 合成许可/生产Controller/替身发送；默认不链接send_native.cpp。
// RELAY_NATIVE_IMAGE_PREFLIGHT构建只调用生产OpenImage，不加载/连接微信。
// macOS适配系统I/O和SHA256；Windows使用真实WinAPI和bcrypt。
#include "send_native.h"
#include <filesystem>
#include <iostream>

namespace {
struct Prepared final : send_fix::PreparedCall {
    int& calls;
#ifdef RELAY_NATIVE_IMAGE_PREFLIGHT
    std::unique_ptr<send_fix::LockedImage> image;
#endif
    explicit Prepared(int& value) : calls(value) {}
    send_fix::Result Run() override {
        ++calls;
        return {202, "unconfirmed", "native_result_not_delivery_receipt", true};
    }
};
struct Backend final : send_fix::Backend {
    int calls = 0;
    std::string prepare_error;
    std::unique_ptr<send_fix::PreparedCall> Prepare(const send_fix::Request& request, const send_fix::Approval&) override {
        if (!prepare_error.empty()) throw std::runtime_error(prepare_error);
        auto result = std::make_unique<Prepared>(calls);
#ifdef RELAY_NATIVE_IMAGE_PREFLIGHT
        if (request.kind == "image") {
            // 只执行文件预检；不调用 WindowsBackend::Prepare 或任何微信函数。
            result->image = std::make_unique<send_fix::LockedImage>(send_fix::OpenImage(request));
        }
#endif
        return result;
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
        backend.prepare_error = request.value("prepare_error", "");
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

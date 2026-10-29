#pragma once
#include "json.hpp"
#include "send_layout.h"
#include <atomic>
#include <ctime>
#include <functional>
#include <memory>
#include <mutex>

namespace send_fix {
struct Request {
    std::string kind, id, recipient, value, image_sha256;
    std::u16string unicode;
};
struct Result {
    int http = 423;
    std::string state = "not_attempted";
    std::string error = "approval_required";
    bool native_entered = false;
    bool replayed = false;
};
struct Approval {
    bool enabled = false;
    std::string token, request_id, recipient, kind, payload_sha256, module_sha256;
    std::time_t expires = 0;
    int version = 1;
};
bool ApprovalLifetimeValid(const Approval& approval);
bool IsHexHash(const std::string& value);
std::string Sha256(const void* data, std::size_t size);
std::string Fingerprint(const Request& request);
Request ParseRequest(const std::string& kind, const std::string& body);
nlohmann::json Response(const Result& result);

struct PreparedCall {
    virtual ~PreparedCall() = default;
    virtual Result Run() = 0;
};
struct Backend {
    virtual ~Backend() = default;
    virtual std::unique_ptr<PreparedCall> Prepare(const Request& request, const Approval& approval) = 0;
};

struct AuthorizationState {
    bool configured = false, consumed = false, busy = false;
};

class Controller {
    std::function<Approval()> load_;
    Approval last_approval_;
    Backend& backend_;
    std::function<bool(const Approval&)> consume_;
    std::mutex mutex_;
    std::atomic<bool> attempted_{false};
    std::string last_fingerprint_;
    Result last_result_;
public:
    Controller(Approval approval, Backend& backend, std::function<bool(const Approval&)> consume)
        : Controller([approval=std::move(approval)] { return approval; },backend,std::move(consume)) {}
    Controller(std::function<Approval()> load, Backend& backend, std::function<bool(const Approval&)> consume)
        : load_(std::move(load)), backend_(backend), consume_(std::move(consume)) {}
    Result Dispatch(const std::string& authorization, const std::string& kind, const std::string& body);
    AuthorizationState Status();
    bool Attempted() { return Status().consumed; }
    bool Configured() { return Status().configured; }
};
} // namespace send_fix

#include "send_api.h"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>

namespace send_fix {
bool IsHexHash(const std::string& value)
{
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

std::string Sha256(const void* data, std::size_t size)
{
    if (size > 1024 * 1024) throw std::invalid_argument("hash_input_too_large");
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("sha256_unavailable");
    unsigned char hash[32]{};
    const auto status = BCryptHash(algorithm, nullptr, 0,
        static_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(size), hash, 32);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) throw std::runtime_error("sha256_failed");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto byte : hash) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}

Request ParseRequest(const std::string& kind, const std::string& body)
{
    if (body.size() > 32768 || (kind != "text" && kind != "image"))
        throw std::invalid_argument("invalid_request");
    const auto value = nlohmann::json::parse(body);
    const char* payload = kind == "text" ? "msg" : "path";
    if (!value.is_object() || value.size() != (kind == "text" ? 3 : 4)
        || !value.contains("request_id") || !value["request_id"].is_string()
        || !value.contains("wxidorgid") || !value["wxidorgid"].is_string()
        || !value.contains(payload) || !value[payload].is_string()
        || (kind == "image" && (!value.contains("image_sha256") || !value["image_sha256"].is_string())))
        throw std::invalid_argument("invalid_request_fields");
    Request result{kind, value["request_id"].get<std::string>(), value["wxidorgid"].get<std::string>(),
        value[payload].get<std::string>(), kind == "image" ? value["image_sha256"].get<std::string>() : "", {}};
    const auto identifier = [](const std::string& input, std::size_t low, std::size_t high) {
        return input.size() >= low && input.size() <= high
            && std::all_of(input.begin(), input.end(), [](char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '@' || c == '.';
            });
    };
    if (!identifier(result.id, 16, 64) || !identifier(result.recipient, 1, 128))
        throw std::invalid_argument("request_id_or_recipient_id_invalid");
    result.unicode = Utf16(result.value);
    if (result.unicode.empty() || result.unicode.size() > (kind == "text" ? 2000 : 4096))
        throw std::invalid_argument("payload_length_invalid");
    if (kind == "text" && std::all_of(result.value.begin(), result.value.end(), [](char c) {
        return c == ' ' || c == '\n' || c == '\r' || c == '\t';
    })) throw std::invalid_argument("empty_message");
    if (kind == "image" && !IsHexHash(result.image_sha256)) throw std::invalid_argument("invalid_image_hash");
    return result;
}

std::string Fingerprint(const Request& request)
{
    const auto text = nlohmann::json{{"kind",request.kind},{"recipient",request.recipient},
        {"value",request.value},{"image_sha256",request.image_sha256}}.dump();
    return Sha256(text.data(), text.size());
}

nlohmann::json Response(const Result& result)
{
    return {{"ret", result.native_entered ? 1 : -result.http}, {"state",result.state},
        {"error",result.error},{"NativeEntered",result.native_entered},
        {"IsSent",nullptr},{"DeliveryConfirmed",false},{"Replayed",result.replayed}};
}

Result Controller::Dispatch(const std::string& authorization, const std::string& kind, const std::string& body)
{
    if (!approval_.enabled || approval_.token.size() < 32 || approval_.token.size() > 128)
        return {};
    const std::string expected = "Bearer " + approval_.token;
    unsigned char difference = authorization.size() == expected.size() ? 0 : 1;
    for (std::size_t i = 0; i < expected.size(); ++i)
        difference |= static_cast<unsigned char>(expected[i])
            ^ static_cast<unsigned char>(i < authorization.size() ? authorization[i] : 0);
    if (difference) return {403,"not_attempted","authorization_failed"};
    Request request;
    try { request = ParseRequest(kind, body); }
    catch (...) { return {400,"not_attempted","invalid_request"}; }
    std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) return {409,"not_attempted","send_in_progress_no_new_attempt"};
    const auto fingerprint = Fingerprint(request);
    if (attempted_) {
        if (request.id != approval_.request_id || fingerprint != last_fingerprint_)
            return {409,"not_attempted","one_shot_already_used"};
        auto result = last_result_;
        result.replayed = true;
        return result;
    }
    if (approval_.expires <= std::time(nullptr) || approval_.expires > std::time(nullptr) + 600
        || request.id != approval_.request_id || request.recipient != approval_.recipient
        || request.kind != approval_.kind || fingerprint != approval_.payload_sha256
        || !IsHexHash(approval_.module_sha256)) return {403,"not_attempted","request_not_approved"};
    std::unique_ptr<PreparedCall> prepared;
    try { prepared = backend_.Prepare(request, approval_); }
    catch (const std::bad_alloc&) { return {503,"not_attempted","allocation_failed"}; }
    catch (const std::exception& error) {
        // 仅返回本代码定义的固定错误码，不泄露路径、正文、凭据或底层异常全文。
        const std::string code(error.what());
        for (const char* known : {"wechat_module_missing","module_path_failed","wechat_module_hash_mismatch",
            "module_version_failed","wechat_version_not_4_1_10_27","module_header_failed","module_architecture_failed",
            "function_address_not_executable","data_address_not_readable","send_context_unavailable",
            "image_requires_local_absolute_path","image_path_not_stable","image_file_invalid","image_header_invalid",
            "image_format_unsupported","image_hash_mismatch","file_size_invalid","file_read_failed",
            "file_changed","hash_failed","guid_failed"})
            if (code == known) return {422,"not_attempted",code};
        return {422,"not_attempted","native_preflight_failed"};
    }
    catch (...) { return {422,"not_attempted","native_preflight_failed"}; }
    if (!prepared) return {422,"not_attempted","native_preflight_failed"};
    try { if (!consume_(approval_)) return {423,"not_attempted","durable_approval_consume_failed"}; }
    catch (...) { return {423,"not_attempted","durable_approval_consume_failed"}; }
    last_fingerprint_ = fingerprint;
    // 一次性许可已经落盘消耗，任何异常、超时、重启都不得自动重试。
    attempted_ = true;
    last_result_ = {202,"unconfirmed","native_result_not_delivery_receipt",true};
    try { last_result_ = prepared->Run(); }
    catch (...) { last_result_ = {202,"unconfirmed","native_exception_no_retry",true}; }
    // 后端不能通过回调把私有函数返回值升级成发送或送达证明。
    last_result_.http = 202;
    last_result_.state = "unconfirmed";
    last_result_.native_entered = true;
    return last_result_;
}
} // namespace send_fix

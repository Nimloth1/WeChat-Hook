#pragma once
#include <cstddef>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace send_fix {
struct RetentionUsage {
    std::size_t bytes = 0, handles = 0, byte_limit = 0, handle_limit = 0;
};

// 只约束本模块显式保留的参数分配和句柄，不是微信 RSS 或私有函数分配的上限。
class RetentionBudget {
    std::mutex mutex_;
    RetentionUsage usage_;
    void Release(std::size_t bytes, std::size_t handles) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        usage_.bytes -= bytes;
        usage_.handles -= handles;
    }
public:
    class Reservation {
        RetentionBudget* budget_;
        std::size_t bytes_, handles_;
        bool retained_ = false;
        friend class RetentionBudget;
        Reservation(RetentionBudget& budget, std::size_t bytes, std::size_t handles)
            : budget_(&budget), bytes_(bytes), handles_(handles) {}
    public:
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;
        Reservation(Reservation&& other) noexcept
            : budget_(other.budget_), bytes_(other.bytes_), handles_(other.handles_), retained_(other.retained_)
        { other.budget_ = nullptr; }
        ~Reservation() { if (budget_ && !retained_) budget_->Release(bytes_,handles_); }
        // 进入私有调用后，即使异常或调用失败也不推断异步使用结束。
        void RetainOnNativeEntry() noexcept { retained_ = true; }
    };

    RetentionBudget(std::size_t bytes, std::size_t handles) : usage_{0,0,bytes,handles} {}
    RetentionBudget(const RetentionBudget&) = delete;
    RetentionBudget& operator=(const RetentionBudget&) = delete;
    Reservation Reserve(std::size_t bytes, std::size_t handles) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (bytes > usage_.byte_limit-usage_.bytes || handles > usage_.handle_limit-usage_.handles)
            throw std::runtime_error("native_retention_budget_exceeded");
        usage_.bytes += bytes;
        usage_.handles += handles;
        return Reservation(*this,bytes,handles);
    }
    RetentionUsage Usage() {
        std::lock_guard<std::mutex> lock(mutex_);
        return usage_;
    }
};
} // namespace send_fix

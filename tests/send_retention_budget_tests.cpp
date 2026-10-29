#include "send_retention.h"
#include <atomic>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <vector>
using namespace send_fix;
int main() {
    int checks=0;
    const auto check=[&](bool ok) { if (!ok) throw std::runtime_error("check_"+std::to_string(checks+1)); ++checks; };
    try {
        RetentionBudget budget(128,4);
        { auto a=budget.Reserve(64,2); auto b=std::move(a); check(budget.Usage().bytes == 64); }
        check(budget.Usage().bytes == 0 && budget.Usage().handles == 0);
        { auto a=budget.Reserve(128,4); a.RetainOnNativeEntry(); }
        check(budget.Usage().bytes == 128 && budget.Usage().handles == 4);
        for (auto amount : {std::size_t(1),std::numeric_limits<std::size_t>::max()}) {
            bool rejected=false;
            try { auto a=budget.Reserve(amount,0); } catch (const std::runtime_error&) { rejected=true; }
            check(rejected); rejected=false;
            try { auto a=budget.Reserve(0,amount); } catch (const std::runtime_error&) { rejected=true; }
            check(rejected);
        }
        check(budget.Usage().bytes == 128 && budget.Usage().handles == 4);
        for (int round=0;round<10;++round) {
            RetentionBudget shared(7,7); std::atomic<int> accepted{0}; std::vector<std::thread> workers;
            for (int i=0;i<32;++i) workers.emplace_back([&] { try { auto a=shared.Reserve(1,1);
                a.RetainOnNativeEntry(); ++accepted; } catch (const std::runtime_error&) {} });
            for (auto& worker : workers) worker.join();
            check(accepted == 7 && shared.Usage().bytes == 7 && shared.Usage().handles == 7);
        }
        std::cout << "PASS retention_budget checks=" << checks << '\n'; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}

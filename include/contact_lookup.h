#pragma once
#include "json.hpp"
#include <atomic>
#include <string>
#include <vector>

namespace contact_lookup {
inline constexpr char Target[] = u8"金浩枫";
inline constexpr char Route[] = "/ReadOnlyContact/FindJinHaofeng";
// Only these SQLite operations are available to the query core. No exec/open/backup/key/write API.
struct Sqlite {
    int (*prepare)(void*, const char*, int, void**, const char**);
    int (*readonly)(void*);
    int (*parameters)(void*);
    int (*bind)(void*, int, const char*, int, void(*)(void*));
    int (*step)(void*);
    int (*columns)(void*);
    int (*type)(void*, int);
    const unsigned char* (*text)(void*, int);
    int (*bytes)(void*, int);
    int (*finalize)(void*);
    int (*autocommit)(void*);
};
struct Candidate { std::string id, nickname, remark, alias; };
struct Result {
    std::string state, error;
    std::vector<Candidate> candidates;
};
// Caller exclusively owns/synchronizes the connection and holds an explicit transaction
// unchanged for the whole call. The core refuses autocommit/read_uncommitted; it never
// issues transaction-control SQL. SQLite errors may themselves end/roll back a transaction.
// Adapter must prove NO pending writes anywhere on this connection (main/attached/temp)
// and no writes during the call; the core cannot establish this from autocommit/readonly.
// After any failure, caller must re-check transaction state; never retry/replay host writes.
Result Find(Sqlite& api, void* database);
nlohmann::json Json(const Result& result);
struct Backend {
    virtual ~Backend() = default;
    virtual Result FindTarget() = 0;
};
// The build has no send implementation, even when a query token has been supplied.
class Controller {
    Backend& backend_;
    std::string token_;
    std::atomic<bool> attempted_{false};
public:
    Controller(Backend& backend, std::string token) : backend_(backend), token_(std::move(token)) {}
    nlohmann::json Dispatch(const std::string& authorization, const std::string& body, int& http);
    bool Attempted() const { return attempted_.load(); }
};
} // namespace contact_lookup

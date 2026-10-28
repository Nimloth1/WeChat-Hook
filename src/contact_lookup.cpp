#include "contact_lookup.h"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <stdexcept>

namespace contact_lookup {
namespace {
using Rows = std::vector<std::vector<std::string>>;
enum class Shape { normal, table_info, integer_metadata };
Rows Read(Sqlite& api, void* db, const char* sql, bool bind, int columns, std::size_t limit, Shape shape=Shape::normal)
{
    if (api.autocommit(db)!=0) throw std::runtime_error("caller_transaction_required");
    void* statement = nullptr;
    const char* tail = nullptr;
    const auto prepared = api.prepare(db,sql,-1,&statement,&tail);
    struct Statement {
        Sqlite& api; void* value;
        ~Statement() { if (value) api.finalize(value); }
    } cleanup{api,statement};
    if (prepared != 0 || !statement) throw std::runtime_error("prepare_failed");
    if (!tail || *tail || api.readonly(statement) != 1 || api.parameters(statement) != (bind ? 1 : 0)
        || api.columns(statement) != (shape==Shape::table_info ? 6 : columns)) throw std::runtime_error("statement_policy_failed");
    // SQLITE_STATIC is safe: Target has static storage and remains valid until finalization.
    if (bind && api.bind(statement,1,Target,static_cast<int>(sizeof(Target)-1),nullptr) != 0)
        throw std::runtime_error("bind_failed");
    Rows rows;
    const auto deadline = std::chrono::steady_clock::now()+std::chrono::seconds(2);
    int code = 0;
    while ((code=api.step(statement)) == 100) {
        if (rows.size() >= limit) throw std::runtime_error("result_budget_exceeded");
        if (std::chrono::steady_clock::now() > deadline) throw std::runtime_error("query_deadline_exceeded");
        std::vector<std::string> row;
        for (int col=0; col<columns; ++col) {
            // table_info's six fields include integer metadata; only copy name/type (1/2).
            const auto index=shape==Shape::table_info ? col+1 : col;
            const int type=api.type(statement,index);
            if (type == 5) { row.emplace_back(); continue; }
            if (type != (shape==Shape::integer_metadata ? 1 : 3)) throw std::runtime_error("column_type_invalid");
            const auto text=api.text(statement,index);
            const auto bytes=api.bytes(statement,index);
            if (bytes < 0 || bytes > 4096 || (!text && bytes)) throw std::runtime_error("column_budget_exceeded");
            row.emplace_back(bytes ? reinterpret_cast<const char*>(text) : "",bytes);
            if (row.back().find('\0') != std::string::npos) throw std::runtime_error("embedded_nul");
        }
        rows.push_back(std::move(row));
    }
    if (code != 101) throw std::runtime_error("step_failed_"+std::to_string(code));
    const auto finalized=api.finalize(statement);
    cleanup.value=nullptr;
    if (finalized != 0) throw std::runtime_error("finalize_failed");
    if (api.autocommit(db)!=0) throw std::runtime_error("caller_transaction_required");
    return rows;
}
std::string Lower(std::string value)
{
    for (auto& c:value) if (c >= 'A' && c <= 'Z') c=static_cast<char>(c+'a'-'A');
    return value;
}
bool Identifier(const std::string& id)
{
    if (id.empty() || id.size()>128 || id.find('@') != std::string::npos) return false;
    for (const unsigned char c:id)
        if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='_' || c=='-' || c=='.')) return false;
    return true;
}
}

Result Find(Sqlite& api, void* database)
{
    try {
        if (!database || !api.prepare || !api.readonly || !api.parameters || !api.bind || !api.step
            || !api.columns || !api.type || !api.text || !api.bytes || !api.finalize || !api.autocommit)
            throw std::runtime_error("sqlite_api_incomplete");
        // This is a read of connection state, never a PRAGMA assignment. Keep a snapshot
        // across all subsequent statements without changing a borrowed connection's transaction.
        const auto isolation=Read(api,database,"PRAGMA read_uncommitted",false,1,1,Shape::integer_metadata);
        if (isolation.size()!=1 || isolation[0][0]!="0") throw std::runtime_error("read_uncommitted_not_allowed");
        // Require an ordinary main-schema table, not a view or virtual table.
        const auto tables=Read(api,database,
            "SELECT type,sql FROM main.sqlite_master WHERE name='contact' COLLATE NOCASE LIMIT 2",false,2,2);
        if (tables.size()!=1 || tables[0][0]!="table" || Lower(tables[0][1]).rfind("create table",0)!=0)
            throw std::runtime_error("contact_table_unsupported");
        const auto schema=Read(api,database,
            "PRAGMA main.table_info('contact')",false,2,65,Shape::table_info);
        if (schema.empty() || schema.size()>64) throw std::runtime_error("contact_schema_unsupported");
        std::vector<std::string> names;
        for (const auto& col:schema) names.push_back(Lower(col[0]));
        const auto has=[&](const char* name) { return std::count(names.begin(),names.end(),name)==1; };
        const char* sql=nullptr;
        if (has("username") && has("nick_name") && has("remark") && has("alias")) {
            sql="SELECT username,nick_name,remark,alias FROM main.contact "
                "WHERE remark COLLATE BINARY=?1 OR nick_name COLLATE BINARY=?1 LIMIT 6";
        } else if (has("username") && has("nickname") && has("remark") && has("alias")) {
            sql="SELECT UserName,NickName,Remark,Alias FROM main.Contact "
                "WHERE Remark COLLATE BINARY=?1 OR NickName COLLATE BINARY=?1 LIMIT 6";
        } else throw std::runtime_error("contact_schema_unsupported");
        const auto rows=Read(api,database,sql,true,4,6);
        if (rows.size()>5) throw std::runtime_error("too_many_matches");
        Result result{"not_found",{}, {}};
        for (const auto& row:rows) {
            if (!Identifier(row[0]) || (row[1]!=Target && row[2]!=Target)
                || row[1].size()>512 || row[2].size()>512 || row[3].size()>128)
                throw std::runtime_error("candidate_invalid");
            // Reject invalid UTF-8 before returning any partial candidate list.
            nlohmann::json(row).dump();
            if (std::any_of(result.candidates.begin(),result.candidates.end(),[&](const Candidate& c){return c.id==row[0];}))
                throw std::runtime_error("duplicate_identifier");
            result.candidates.push_back({row[0],row[1],row[2],row[3]});
        }
        if (!result.candidates.empty()) result.state=result.candidates.size()==1 ? "candidate_needs_confirmation" : "ambiguous";
        return result;
    } catch (const std::exception& error) { return {"failed",error.what(),{}}; }
}

nlohmann::json Json(const Result& result)
{
    nlohmann::json rows=nlohmann::json::array();
    for (const auto& c:result.candidates) rows.push_back({{"id",c.id},{"nickname",c.nickname},{"remark",c.remark},{"alias",c.alias}});
    return {{"target",Target},{"state",result.state},{"error",result.error},{"candidates",rows},
        {"IdentityConfirmed",false},{"SendingSupported",false},{"RuntimeCompatibilityVerified",false}};
}

nlohmann::json Controller::Dispatch(const std::string& authorization,const std::string& body,int& http)
{
    http=423;
    if (token_.size()<32 || token_.size()>128 || authorization!="Bearer "+token_)
        return Json({"not_attempted","query_approval_required",{}});
    http=400;
    try {
        if (body.size()>128) throw std::runtime_error("request_too_large");
        // JSON escape variants are allowed; duplicate keys and all additional fields are rejected.
        int keys=0;
        const auto value=nlohmann::json::parse(body,[&](int,nlohmann::json::parse_event_t event,nlohmann::json&){
            if (event==nlohmann::json::parse_event_t::key) ++keys;
            return true;
        });
        if (!value.is_object() || value.size()!=1 || keys!=1 || !value.contains("name")
            || !value["name"].is_string() || value["name"]!=Target) throw std::runtime_error("only_fixed_target_allowed");
    } catch (...) { return Json({"not_attempted","only_fixed_target_allowed",{}}); }
    if (attempted_.exchange(true)) { http=409; return Json({"not_attempted","attempt_already_consumed",{}}); }
    try {
        const auto result=backend_.FindTarget();
        http=result.state=="failed" ? 503 : 200;
        return Json(result);
    } catch (...) { http=503; return Json({"failed","backend_failed_no_retry",{}}); }
}
} // namespace contact_lookup

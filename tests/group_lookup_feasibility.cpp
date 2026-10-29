// Offline experiment only. No CLI input, native offsets, process access, keys or send code.
#include <sqlite3.h>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr char Target[]=u8"PAYL能化观察";
int checks=0;
void Check(bool ok,const char* why)
{
    ++checks;
    if (!ok) throw std::runtime_error(why);
}
void Exec(sqlite3* db,const char* sql)
{
    Check(sqlite3_exec(db,sql,nullptr,nullptr,nullptr)==SQLITE_OK,"fixture SQL");
}
struct Statement {
    sqlite3_stmt* value=nullptr;
    ~Statement() { if(value) sqlite3_finalize(value); }
    Statement(sqlite3* db,const char* sql,int parameters) {
        const char* tail=nullptr;
        const auto rc=sqlite3_prepare_v2(db,sql,-1,&value,&tail);
        if(rc!=SQLITE_OK || !value || !tail || *tail || !sqlite3_stmt_readonly(value)
            || sqlite3_bind_parameter_count(value)!=parameters) {
            if(value) sqlite3_finalize(value);
            value=nullptr;
            throw std::runtime_error("prepare_or_policy_failed");
        }
    }
    Statement(const Statement&)=delete;
    Statement& operator=(const Statement&)=delete;
    void Finish() {
        auto old=value; value=nullptr;
        if(sqlite3_finalize(old)!=SQLITE_OK) throw std::runtime_error("finalize_failed");
    }
};
std::string Text(sqlite3_stmt* s,int column,int maximum)
{
    if(sqlite3_column_type(s,column)!=SQLITE_TEXT) throw std::runtime_error("column_type_invalid");
    const auto* bytes=sqlite3_column_text(s,column);
    const int size=sqlite3_column_bytes(s,column);
    if(!bytes || size<0 || size>maximum) throw std::runtime_error("column_budget_exceeded");
    std::string text(reinterpret_cast<const char*>(bytes),size);
    if(text.find('\0')!=std::string::npos) throw std::runtime_error("embedded_nul");
    return text;
}
bool GroupID(const std::string& id)
{
    const std::string suffix="@chatroom";
    if(id.size()<=suffix.size() || id.size()>128
        || id.compare(id.size()-suffix.size(),suffix.size(),suffix)!=0) return false;
    return std::all_of(id.begin(),id.end()-static_cast<std::ptrdiff_t>(suffix.size()),[](unsigned char c) {
        return (c>='0' && c<='9') || (c>='a' && c<='z') || (c>='A' && c<='Z') || c=='_' || c=='-' || c=='.';
    });
}
struct Result { std::string state,error,id; };
using SchemaHook=void(*)(void*);
// This function is deliberately private to the synthetic experiment. Callers own all
// connections, built-in functions, transactions and callbacks here. It is NOT an adapter
// that accepts a borrowed WeChat handle or establishes these prerequisites at runtime.
Result Find(sqlite3* db,SchemaHook hook=nullptr,void* context=nullptr,bool before_step=false)
{
    try {
        if(!db || sqlite3_get_autocommit(db)) throw std::runtime_error("owned_read_transaction_required");
        {
            Statement isolation(db,"PRAGMA read_uncommitted",0);
            if(sqlite3_step(isolation.value)!=SQLITE_ROW || sqlite3_column_int(isolation.value,0)!=0
                || sqlite3_step(isolation.value)!=SQLITE_DONE) throw std::runtime_error("isolation_unsupported");
            isolation.Finish();
        }
        {
            Statement table(db,"SELECT type,sql FROM main.sqlite_master WHERE name='contact' COLLATE NOCASE LIMIT 2",0);
            if(sqlite3_step(table.value)!=SQLITE_ROW || Text(table.value,0,16)!="table")
                throw std::runtime_error("contact_table_unsupported");
            auto sql=Text(table.value,1,16384);
            for(auto& c:sql) if(c>='A' && c<='Z') c=static_cast<char>(c+'a'-'A');
            if(sql.rfind("create table",0)!=0 || sqlite3_step(table.value)!=SQLITE_DONE)
                throw std::runtime_error("contact_table_unsupported");
            table.Finish(); // This main-schema read establishes the retained snapshot.
        }
        bool username=false,modern=false,legacy=false;
        {
            Statement schema(db,"PRAGMA main.table_info('contact')",0);
            int rc=0,count=0;
            while((rc=sqlite3_step(schema.value))==SQLITE_ROW) {
                if(++count>64) throw std::runtime_error("schema_budget_exceeded");
                auto column=Text(schema.value,1,128);
                for(auto& c:column) if(c>='A' && c<='Z') c=static_cast<char>(c+'a'-'A');
                if(column=="username") username=true;
                if(column=="nick_name") modern=true;
                if(column=="nickname") legacy=true;
            }
            if(rc!=SQLITE_DONE) throw std::runtime_error("schema_step_failed");
            schema.Finish();
        }
        if(!username || modern==legacy) throw std::runtime_error("contact_schema_unsupported");
        if(hook && !before_step) hook(context); // Test-only DDL/failure window, never a real callback.
        if(sqlite3_get_autocommit(db)) throw std::runtime_error("owned_read_transaction_required");
        const char* sql=modern
            ? "SELECT username,nick_name FROM main.contact WHERE nick_name COLLATE BINARY=?1 LIMIT 6"
            : "SELECT UserName,NickName FROM main.Contact WHERE NickName COLLATE BINARY=?1 LIMIT 6";
        Statement statement(db,sql,1);
        if(sqlite3_bind_text(statement.value,1,Target,sizeof(Target)-1,SQLITE_STATIC)!=SQLITE_OK)
            throw std::runtime_error("bind_failed");
        if(hook && before_step) hook(context);
        std::vector<std::string> ids;
        int rc=0,rows=0;
        while((rc=sqlite3_step(statement.value))==SQLITE_ROW) {
            if(++rows>=6) throw std::runtime_error("named_row_budget_exceeded");
            const auto id=Text(statement.value,0,128),name=Text(statement.value,1,512);
            if(name!=Target) throw std::runtime_error("candidate_invalid");
            // Avoid GLOB/LIKE/substr: those SQL functions can be overridden on a connection.
            // Only inspect the suffix in our own code; matching friend names are not candidates.
            const std::string suffix="@chatroom";
            if(id.size()<suffix.size() || id.compare(id.size()-suffix.size(),suffix.size(),suffix)!=0) continue;
            if(!GroupID(id)) throw std::runtime_error("candidate_invalid");
            ids.push_back(id);
        }
        if(rc!=SQLITE_DONE) throw std::runtime_error("candidate_step_failed_"+std::to_string(rc));
        statement.Finish();
        if(sqlite3_get_autocommit(db)) throw std::runtime_error("owned_read_transaction_required");
        // Never choose the first row or expose IDs from an ambiguous/failed result.
        if(ids.size()>1) return {"ambiguous",{}, {}};
        return ids.empty() ? Result{"not_found",{}, {}} : Result{"candidate_needs_confirmation",{},ids[0]};
    } catch(const std::exception& error) { return {"failed",error.what(),{}}; }
}
struct Fixture {
    sqlite3* db=nullptr;
    explicit Fixture(bool legacy=false) {
        Check(sqlite3_open(":memory:",&db)==SQLITE_OK,"fixture open");
        Exec(db,legacy ? "CREATE TABLE Contact(UserName TEXT,NickName TEXT,Remark TEXT)"
            : "CREATE TABLE contact(username TEXT,nick_name TEXT,remark TEXT)");
    }
    ~Fixture() {
        if(sqlite3_next_stmt(db,nullptr) || sqlite3_close(db)!=SQLITE_OK) std::abort();
    }
    void Add(const std::string& id,const std::string& name,const std::string& remark="") {
        sqlite3_stmt* s=nullptr;
        Check(sqlite3_prepare_v2(db,"INSERT INTO contact VALUES(?1,?2,?3)",-1,&s,nullptr)==SQLITE_OK,"insert prepare");
        int col=0;
        for(const auto* text:{&id,&name,&remark})
            Check(sqlite3_bind_text(s,++col,text->data(),static_cast<int>(text->size()),SQLITE_STATIC)==SQLITE_OK,"insert bind");
        Check(sqlite3_step(s)==SQLITE_DONE,"insert done");
        Check(sqlite3_finalize(s)==SQLITE_OK,"insert finalize");
    }
    Result Lookup() {
        Exec(db,"PRAGMA query_only=ON; BEGIN");
        const int before=sqlite3_total_changes(db);
        auto result=Find(db);
        Check(before==sqlite3_total_changes(db),"no DML changes (not proof of zero filesystem writes)");
        Check(sqlite3_next_stmt(db,nullptr)==nullptr,"all statements finalized");
        Exec(db,"ROLLBACK; PRAGMA query_only=OFF");
        return result;
    }
};
void ExactAndAmbiguous()
{
    for(bool legacy:{false,true}) {
        Fixture f(legacy);
        f.Add("wxid_friend",Target);
        f.Add("100@chatroom",std::string(Target)+" ");
        f.Add("101@chatroom","payl能化观察");
        f.Add("102@chatroom","other",Target); // Do not treat a personal remark as group name.
        f.Add("103@CHATROOM",Target);
        f.Add("104@chatroom.other",Target);
        Check(f.Lookup().state=="not_found","friends, prefixes, case and remarks do not match");
        f.Add("105@chatroom",Target);
        auto one=f.Lookup();
        Check(one.state=="candidate_needs_confirmation" && one.id=="105@chatroom","only exact named group is candidate");
        f.Add("106@chatroom",Target);
        auto two=f.Lookup();
        Check(two.state=="ambiguous" && two.id.empty(),"two groups never auto-selected");
    }
    Fixture empty;
    Check(empty.Lookup().state=="not_found","empty contact table");
    Fixture no_functions;
    Check(sqlite3_create_function(no_functions.db,"glob",2,SQLITE_UTF8,nullptr,
        [](sqlite3_context*,int,sqlite3_value**) { std::abort(); },nullptr,nullptr)==SQLITE_OK,"overridden GLOB observer");
    no_functions.Add("109@chatroom",Target);
    Check(no_functions.Lookup().id=="109@chatroom","query never invokes overridden GLOB function");
    for(const auto& id:{std::string("@chatroom"),std::string("a@b@chatroom"),std::string("bad id@chatroom"),
        std::string(121,'a')+"@chatroom",std::string("a\0x@chatroom",12)}) {
        Fixture bad; bad.Add(id,Target);
        auto result=bad.Lookup();
        Check(result.state=="failed" && result.id.empty(),"invalid group identifiers never escape");
    }
    Fixture duplicate;
    duplicate.Add("107@chatroom",Target); duplicate.Add("107@chatroom",Target);
    Check(duplicate.Lookup().state=="ambiguous","duplicate rows do not establish uniqueness");
}
int side_effects=0;
void SideEffect(sqlite3_context* context,int,sqlite3_value**)
{
    ++side_effects;
    sqlite3_result_text(context,"999@chatroom",-1,SQLITE_STATIC);
}
void RejectionsAndBudgets()
{
    Fixture f;
    Check(Find(f.db).error=="owned_read_transaction_required","no autocommit query");
    Exec(f.db,"PRAGMA read_uncommitted=ON; BEGIN");
    Check(Find(f.db).error=="isolation_unsupported","read_uncommitted refused");
    Exec(f.db,"ROLLBACK; PRAGMA read_uncommitted=OFF");
    Check(sqlite3_create_function(f.db,"side_effect",0,SQLITE_UTF8,nullptr,SideEffect,nullptr,nullptr)==SQLITE_OK,"observer installed on fixture only");
    Exec(f.db,"DROP TABLE contact; CREATE VIEW contact AS SELECT side_effect() AS username,'PAYL能化观察' AS nick_name");
    Check(f.Lookup().error=="contact_table_unsupported" && side_effects==0,"view rejected without invoking its function");
    Exec(f.db,"DROP VIEW contact; CREATE TABLE contact(username TEXT,unknown_name TEXT)");
    Check(f.Lookup().error=="contact_schema_unsupported","unknown schema refused");
    Exec(f.db,"DROP TABLE contact; CREATE TABLE contact(username TEXT,nick_name TEXT)");
    Exec(f.db,"CREATE TEMP TABLE contact(username TEXT,nick_name TEXT); INSERT INTO temp.contact VALUES('999@chatroom','PAYL能化观察')");
    Check(f.Lookup().state=="not_found","temp table cannot shadow main");
    Fixture nul;
    nul.Add("108@chatroom",std::string(Target)+std::string("\0extra",6));
    Check(nul.Lookup().state=="not_found","binary name match excludes embedded NUL extension");
    Fixture many;
    for(int i=0;i<100;++i) many.Add(std::to_string(i)+"@chatroom",Target);
    auto over=many.Lookup();
    Check(over.error=="named_row_budget_exceeded" && over.id.empty(),"sixth exact-name row fails without selection");
}
struct Swap { sqlite3* writer; };
void Replace(void* pointer)
{
    auto& state=*static_cast<Swap*>(pointer);
    Exec(state.writer,"BEGIN; DROP TABLE contact; CREATE VIEW contact AS SELECT side_effect() AS username,'PAYL能化观察' AS nick_name; COMMIT");
}
void SnapshotAndFailure()
{
    for(bool before_step:{false,true}) {
        std::filesystem::path directory;
        for(int i=0;i<64 && directory.empty();++i) {
            auto path=std::filesystem::temp_directory_path()/("group-lookup-fixture-"+std::to_string(std::random_device{}()));
            if(std::filesystem::create_directory(path)) directory=path;
        }
        Check(!directory.empty(),"unique synthetic directory");
        struct Cleanup {
            std::filesystem::path path;
            ~Cleanup() { std::error_code error; std::filesystem::remove_all(path,error); }
        } cleanup{directory};
        sqlite3* writer=nullptr; sqlite3* reader=nullptr;
        const auto path=(directory/"contact.db").string();
        Check(sqlite3_open(path.c_str(),&writer)==SQLITE_OK,"writer open");
        Exec(writer,"PRAGMA journal_mode=WAL; CREATE TABLE contact(username TEXT,nick_name TEXT); INSERT INTO contact VALUES('200@chatroom','PAYL能化观察')");
        Check(sqlite3_open_v2(path.c_str(),&reader,SQLITE_OPEN_READONLY|SQLITE_OPEN_PRIVATECACHE,nullptr)==SQLITE_OK,"independent reader open");
        Check(sqlite3_create_function(reader,"side_effect",0,SQLITE_UTF8,nullptr,SideEffect,nullptr,nullptr)==SQLITE_OK,"observer installed");
        Exec(reader,"PRAGMA query_only=ON; BEGIN");
        Swap swap{writer};
        auto old=Find(reader,Replace,&swap,before_step);
        Check(old.id=="200@chatroom" && side_effects==0,"schema replacement retains same read snapshot");
        Check(sqlite3_next_stmt(reader,nullptr)==nullptr,"snapshot statements finalized");
        Exec(reader,"ROLLBACK; BEGIN");
        auto next=Find(reader);
        Check(next.state=="failed" && next.id.empty() && side_effects==0,"new snapshot rejects substituted view");
        Exec(reader,"ROLLBACK");
        Check(sqlite3_close(reader)==SQLITE_OK,"reader closes without taking over writer");
        Check(sqlite3_close(writer)==SQLITE_OK,"writer closes");
        Check(std::filesystem::remove_all(directory)>0,"synthetic database and WAL sidecars removed");
    }

    Fixture interrupted;
    interrupted.Add("300@chatroom",Target);
    Exec(interrupted.db,"PRAGMA query_only=ON; BEGIN");
    auto result=Find(interrupted.db,[](void* pointer) {
        // Only this synthetic connection. Never alter host callbacks to impose timeouts.
        sqlite3_progress_handler(static_cast<sqlite3*>(pointer),1,[](void*){return 1;},nullptr);
    },interrupted.db);
    sqlite3_progress_handler(interrupted.db,0,nullptr,nullptr);
    Check(result.state=="failed" && result.id.empty(),"interrupted query is failure, not not_found or partial candidate");
    Check(sqlite3_next_stmt(interrupted.db,nullptr)==nullptr,"interrupted statements finalized");
}
}
int main(int argc,char**)
{
    try {
        Check(argc==1,"experiment accepts no real database path or target argument");
        std::cout<<"group_lookup_feasibility SQLite "<<sqlite3_libversion()<<'\n';
        ExactAndAmbiguous(); RejectionsAndBudgets(); SnapshotAndFailure();
        std::cout<<"group_lookup_feasibility: "<<checks<<" assertions passed; synthetic fixtures only; real group ID NOT obtained\n";
    } catch(const std::exception& error) { std::cerr<<"FAILED: "<<error.what()<<'\n'; return 1; }
}

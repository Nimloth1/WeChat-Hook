#include "contact_lookup.h"
#include <sqlite3.h>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <filesystem>
#include <random>
#include <cstring>

namespace {
int checks=0;
void Check(bool passed,const char* name)
{
    ++checks;
    if (!passed) { std::cerr<<"FAILED: "<<name<<'\n'; std::exit(1); }
}
contact_lookup::Sqlite Api()
{
    return {
        [](void* db,const char* sql,int size,void** stmt,const char** tail) {
            return sqlite3_prepare_v2(static_cast<sqlite3*>(db),sql,size,reinterpret_cast<sqlite3_stmt**>(stmt),tail);
        },
        [](void* s){return sqlite3_stmt_readonly(static_cast<sqlite3_stmt*>(s));},
        [](void* s){return sqlite3_bind_parameter_count(static_cast<sqlite3_stmt*>(s));},
        [](void* s,int n,const char* text,int size,void(*destroy)(void*)) {
            return sqlite3_bind_text(static_cast<sqlite3_stmt*>(s),n,text,size,destroy);
        },
        [](void* s){return sqlite3_step(static_cast<sqlite3_stmt*>(s));},
        [](void* s){return sqlite3_column_count(static_cast<sqlite3_stmt*>(s));},
        [](void* s,int n){return sqlite3_column_type(static_cast<sqlite3_stmt*>(s),n);},
        [](void* s,int n){return sqlite3_column_text(static_cast<sqlite3_stmt*>(s),n);},
        [](void* s,int n){return sqlite3_column_bytes(static_cast<sqlite3_stmt*>(s),n);},
        [](void* s){return sqlite3_finalize(static_cast<sqlite3_stmt*>(s));},
        [](void* db){return sqlite3_get_autocommit(static_cast<sqlite3*>(db));}
    };
}
struct Fixture {
    sqlite3* db=nullptr;
    explicit Fixture(bool legacy=false) {
        Check(sqlite3_open(":memory:",&db)==SQLITE_OK,"fixture open");
        Exec(legacy ? "CREATE TABLE Contact(UserName TEXT,NickName TEXT,Remark TEXT,Alias TEXT)"
            : "CREATE TABLE contact(username TEXT,nick_name TEXT,remark TEXT,alias TEXT)");
        Exec("BEGIN"); // Fixture owns this transaction; the core must not manage it.
    }
    ~Fixture() { Check(sqlite3_next_stmt(db,nullptr)==nullptr,"statements finalized"); sqlite3_close(db); }
    void Exec(const char* sql) { Check(sqlite3_exec(db,sql,nullptr,nullptr,nullptr)==SQLITE_OK,"fixture SQL"); }
    void Add(const char* id,const char* nickname,const char* remark,const char* alias="") {
        sqlite3_stmt* s=nullptr;
        Check(sqlite3_prepare_v2(db,"INSERT INTO contact VALUES(?1,?2,?3,?4)",-1,&s,nullptr)==SQLITE_OK,"insert prepare");
        int n=0;
        for (const char* text:{id,nickname,remark,alias}) {
            ++n;
            Check((text ? sqlite3_bind_text(s,n,text,-1,SQLITE_TRANSIENT) : sqlite3_bind_null(s,n))==SQLITE_OK,"insert bind");
        }
        Check(sqlite3_step(s)==SQLITE_DONE,"insert step");
        sqlite3_finalize(s);
    }
    contact_lookup::Result Find() {
        auto api=Api();
        const auto before=sqlite3_total_changes(db);
        const auto result=contact_lookup::Find(api,db);
        Check(sqlite3_total_changes(db)==before,"query does not write rows");
        return result;
    }
};
int DenyWrites(void* count,int operation,const char* first,const char* second,const char*,const char*)
{
    if (operation==SQLITE_SELECT || operation==SQLITE_READ || operation==SQLITE_FUNCTION) return SQLITE_OK;
    if (operation==SQLITE_PRAGMA && first
        && ((second && std::string(first)=="table_info" && std::string(second)=="contact")
            || (!second && std::string(first)=="read_uncommitted"))) return SQLITE_OK;
    ++*static_cast<int*>(count);
    return SQLITE_DENY;
}
struct FakeBackend : contact_lookup::Backend {
    std::atomic<int> calls{0};
    contact_lookup::Result FindTarget() override { ++calls; return {"not_found",{}, {}}; }
};
void ControllerTests()
{
    FakeBackend backend;
    const std::string token(48,'t');
    contact_lookup::Controller locked(backend,{}),controller(backend,token);
    const auto body=nlohmann::json{{"name",contact_lookup::Target}}.dump();
    int http=0;
    locked.Dispatch("Bearer "+token,body,http);
    Check(http==423 && backend.calls==0,"default locked");
    controller.Dispatch("wrong",body,http);
    Check(http==423 && backend.calls==0,"bad token never reaches DB");
    for (const auto& input:{"{}","[]","null","{\"name\":1}","{\"name\":\"other\"}",
        "{\"name\":\"金浩枫\",\"SQL\":\"DELETE FROM contact\"}",
        "{\"name\":\"other\",\"name\":\"金浩枫\"}","{\"name\":\"金浩枫\",\"name\":\"金浩枫\"}"}) {
        controller.Dispatch("Bearer "+token,input,http);
        Check(http==400 && backend.calls==0,"reject alternate target/extra SQL/duplicate keys");
    }
    controller.Dispatch("Bearer "+token,std::string(129,'x'),http);
    Check(http==400 && backend.calls==0,"body budget");
    std::vector<std::thread> workers;
    std::atomic<int> successes{0},conflicts{0};
    for (int i=0;i<16;++i) workers.emplace_back([&] {
        int code=0;
        controller.Dispatch("Bearer "+token,body,code);
        if (code==200) ++successes;
        if (code==409) ++conflicts;
    });
    for (auto& worker:workers) worker.join();
    Check(successes==1 && conflicts==15 && backend.calls==1,"single attempt under contention");
    Check(controller.Attempted(),"attempt remains consumed");
}

sqlite3* swap_writer=nullptr;
int swap_mode=0,side_effect_calls=0;
bool swapped=false;
void SwapContact()
{
    Check(sqlite3_exec(swap_writer,
        "BEGIN; DROP TABLE contact; CREATE VIEW contact AS "
        "SELECT username,nick_name,remark,review_side_effect() AS alias FROM other; COMMIT",
        nullptr,nullptr,nullptr)==SQLITE_OK,"other connection commits view replacement");
    swapped=true;
}
void SideEffect(sqlite3_context* context,int,sqlite3_value**)
{
    ++side_effect_calls;
    sqlite3_result_text(context,"synthetic_side_effect",-1,SQLITE_STATIC);
}
void SnapshotTests()
{
    // WAL allows the writer's DDL commit while the reader still holds its old snapshot.
    // Each case owns a fresh, tiny synthetic file; never use a real database path.
    for (bool transaction:{false,true}) for (int mode:{0,1}) {
        std::filesystem::path directory;
        for(int tries=0;tries<64 && directory.empty();++tries) {
            auto candidate=std::filesystem::temp_directory_path()
                /("contact-lookup-fixture-"+std::to_string(std::random_device{}()));
            if(std::filesystem::create_directory(candidate)) directory=std::move(candidate);
        }
        Check(!directory.empty(),"private fixture directory created");
        sqlite3* reader=nullptr;
        sqlite3* writer=nullptr;
        const auto path=(directory/"contact.db").u8string();
        Check(sqlite3_open(path.c_str(),&reader)==SQLITE_OK,"snapshot reader open");
        Check(sqlite3_open(path.c_str(),&writer)==SQLITE_OK,"snapshot writer open");
        Check(sqlite3_exec(writer,
            "PRAGMA journal_mode=WAL; CREATE TABLE contact(username TEXT,nick_name TEXT,remark TEXT,alias TEXT);"
            "CREATE TABLE other(username TEXT,nick_name TEXT,remark TEXT,alias TEXT);"
            "INSERT INTO other VALUES('wxid_other_table','金浩枫','','other_alias')",
            nullptr,nullptr,nullptr)==SQLITE_OK,"snapshot fixture initialized");
        Check(sqlite3_create_function(reader,"review_side_effect",0,SQLITE_UTF8,nullptr,SideEffect,nullptr,nullptr)==SQLITE_OK,"fixture side-effect observer");
        if(transaction) Check(sqlite3_exec(reader,"BEGIN",nullptr,nullptr,nullptr)==SQLITE_OK,"caller begins snapshot transaction");
        swap_writer=writer; swap_mode=mode; swapped=false; side_effect_calls=0;
        auto api=Api();
        api.finalize=[](void* pointer) {
            auto statement=static_cast<sqlite3_stmt*>(pointer);
            const bool schema=std::strstr(sqlite3_sql(statement),"PRAGMA main.table_info")!=nullptr;
            const auto result=sqlite3_finalize(statement);
            if(schema && swap_mode==0 && !swapped) SwapContact();
            return result;
        };
        api.step=[](void* pointer) {
            auto statement=static_cast<sqlite3_stmt*>(pointer);
            if(swap_mode==1 && !swapped && std::strstr(sqlite3_sql(statement),"SELECT username,")!=nullptr) SwapContact();
            return sqlite3_step(statement);
        };
        const auto result=contact_lookup::Find(api,reader);
        std::cout<<"snapshot transaction="<<transaction<<" swap_mode="<<mode
            <<" state="<<result.state<<" error="<<result.error<<" swapped="<<swapped
            <<" side_effect_calls="<<side_effect_calls<<'\n';
#ifdef CONTACT_LOOKUP_REPRO_BASELINE
        if(!transaction) {
            Check(swapped && side_effect_calls==1 && result.candidates.size()==1
                && result.candidates[0].id=="wxid_other_table","old head view bypass reproduced");
        } else
#else
        if(!transaction) {
            Check(result.error=="caller_transaction_required" && result.candidates.empty()
                && !swapped && side_effect_calls==0,"autocommit refused before schema/data read");
        } else
#endif
        {
            Check(swapped && result.state=="not_found" && result.candidates.empty()
                && side_effect_calls==0,"both swap windows remain on original table snapshot");
            Check(sqlite3_get_autocommit(reader)==0,"caller transaction left active");
            Check(sqlite3_exec(reader,"ROLLBACK",nullptr,nullptr,nullptr)==SQLITE_OK,"caller ends transaction");
            auto original=Api();
            Check(sqlite3_exec(reader,"BEGIN",nullptr,nullptr,nullptr)==SQLITE_OK,"new caller transaction");
            Check(contact_lookup::Find(original,reader).error=="contact_table_unsupported","new snapshot sees and rejects replacement view");
            Check(side_effect_calls==0,"view UDF never entered after rejection");
            Check(sqlite3_exec(reader,"ROLLBACK",nullptr,nullptr,nullptr)==SQLITE_OK,"caller ends new transaction");
        }
        Check(sqlite3_next_stmt(reader,nullptr)==nullptr,"snapshot statements finalized");
        Check(sqlite3_close(reader)==SQLITE_OK,"snapshot reader close");
        Check(sqlite3_close(writer)==SQLITE_OK,"snapshot writer close");
        swap_writer=nullptr;
        Check(std::filesystem::remove_all(directory)>0,"synthetic database and WAL cleaned");
    }
}
}
int main()
{
    using namespace contact_lookup;
    std::cout<<"SQLite "<<sqlite3_libversion()<<'\n';
#ifdef CONTACT_LOOKUP_REPRO_BASELINE
    SnapshotTests();
    return 0;
#endif
    { Fixture f; Check(f.Find().state=="not_found","empty"); }
    for (bool legacy:{false,true}) {
        Fixture f(legacy);
        f.Add("wxid_synthetic_only","another",Target,"synthetic_alias");
        f.Add("wxid_unrelated","unrelated","unrelated");
        int denied=0;
        Check(sqlite3_set_authorizer(f.db,DenyWrites,&denied)==SQLITE_OK,"install fixture read-only authorizer");
        const auto r=f.Find();
        if (r.state=="failed") std::cerr<<Json(r).dump()<<'\n';
        Check(r.state=="candidate_needs_confirmation" && r.candidates.size()==1,"exact remark both schemas");
        Check(r.candidates[0].id=="wxid_synthetic_only" && r.candidates[0].alias=="synthetic_alias","minimal fields");
        Check(denied==0,"core issues only reads");
        const auto out=Json(r);
        Check(out["IdentityConfirmed"]==false && out["SendingSupported"]==false,"identity never auto confirmed");
        sqlite3_set_authorizer(f.db,nullptr,nullptr);
    }
    { Fixture f; f.Add("wxid_x",Target,nullptr); Check(f.Find().candidates.size()==1,"nickname match/null remark"); }
    { Fixture f; f.Add("wxid_x","金浩枫2",nullptr); f.Add("wxid_y"," 金浩枫",nullptr); Check(f.Find().state=="not_found","no fuzzy matching"); }
    { Fixture f; f.Add("wxid_x",Target,""); f.Add("wxid_y",Target,""); Check(f.Find().state=="ambiguous","same name is ambiguous"); }
    { Fixture f; for(int i=0;i<6;++i) f.Add(("wxid_"+std::to_string(i)).c_str(),Target,""); const auto r=f.Find(); Check(r.error=="too_many_matches" && r.candidates.empty(),"sixth row rejects partial output"); }
    { Fixture f; f.Add("wxid_x",Target,""); f.Add("wxid_x",Target,""); Check(f.Find().error=="duplicate_identifier","duplicate ID rejects"); }
    for (const auto id:{"", "wrong name", "123@chatroom", "user@openim"}) {
        Fixture f; f.Add(id,Target,""); Check(f.Find().error=="candidate_invalid","only private identifier candidates");
    }
    { Fixture f; f.Exec("DROP TABLE contact; CREATE VIEW contact AS SELECT 'x' AS username"); Check(f.Find().error=="contact_table_unsupported","reject views"); }
    { Fixture f; f.Exec("DROP TABLE contact; CREATE TABLE contact(username TEXT,nick TEXT,remark TEXT)"); Check(f.Find().error=="contact_schema_unsupported","unknown schema fails closed"); }
    { Fixture f; f.Add("wxid_x",Target,""); auto api=Api(); api.readonly=[](void*){return 0;}; Check(Find(api,f.db).error=="statement_policy_failed","statement read-only enforced"); }
    { Fixture f; f.Add("wxid_x",Target,""); auto api=Api(); api.bind=[](void*,int,const char*,int,void(*)(void*)){return SQLITE_RANGE;}; Check(Find(api,f.db).error=="bind_failed","bind error fails closed"); }
    { Fixture f; auto api=Api(); api.prepare=[](void* db,const char* sql,int size,void** stmt,const char** tail){
        const auto rc=sqlite3_prepare_v2(static_cast<sqlite3*>(db),sql,size,reinterpret_cast<sqlite3_stmt**>(stmt),tail);
        *tail="; SELECT 1";
        return rc;
      }; Check(Find(api,f.db).error=="statement_policy_failed","reject nonempty statement tail"); }
    { Fixture f; auto api=Api(); api.prepare=[](void*,const char*,int,void**,const char**){return SQLITE_ERROR;}; Check(Find(api,f.db).error=="prepare_failed","prepare error fails closed"); }
    { Fixture f; f.Add("wxid_x",Target,"", "\xff"); Check(f.Find().state=="failed","invalid UTF-8 exposes no candidate"); }
    { Fixture f; f.Add("wxid_x",Target,""); f.Exec("UPDATE contact SET alias='a'||char(0)||'b'"); Check(f.Find().error=="embedded_nul","embedded NUL rejects"); }
    { Fixture f; const std::string large(4097,'x'); f.Add("wxid_x",Target,"",large.c_str()); Check(f.Find().error=="column_budget_exceeded","column budget rejects"); }
    { Fixture f; f.Add("wxid_x",Target,""); f.Exec("CREATE TEMP TABLE contact(secret TEXT)"); Check(f.Find().candidates.size()==1,"main schema cannot be shadowed by temp contact"); }
    { Fixture f; auto api=Api(); api.step=[](void*){return SQLITE_BUSY;}; Check(Find(api,f.db).error=="step_failed_5","BUSY is not empty success"); }
    { Fixture f; auto api=Api(); api.bind=nullptr; Check(Find(api,f.db).error=="sqlite_api_incomplete","missing API fails"); }
    { Fixture f; f.Add("wxid_x",Target,""); auto api=Api(); api.finalize=[](void* s){sqlite3_finalize(static_cast<sqlite3_stmt*>(s));return SQLITE_IOERR;}; Check(Find(api,f.db).error=="finalize_failed","finalize error propagated"); }
    { Fixture f; auto api=Api(); api.autocommit=nullptr; Check(Find(api,f.db).error=="sqlite_api_incomplete","missing snapshot check fails closed"); }
    { Fixture f; f.Exec("ROLLBACK"); auto api=Api(); Check(Find(api,f.db).error=="caller_transaction_required","autocommit rejected"); Check(sqlite3_get_autocommit(f.db)!=0,"core never starts transaction"); }
    { Fixture f; f.Exec("PRAGMA read_uncommitted=1"); const auto result=f.Find(); Check(result.error=="read_uncommitted_not_allowed" && result.candidates.empty(),"nonisolated connection refused"); Check(sqlite3_get_autocommit(f.db)==0,"rejection keeps caller transaction"); }
    { Fixture f; f.Exec("CREATE TABLE caller_state(v); INSERT INTO caller_state VALUES(7); DROP TABLE contact"); Check(f.Find().state=="failed","query failure fixture"); Check(sqlite3_get_autocommit(f.db)==0,"error must not rollback caller transaction"); sqlite3_stmt* s=nullptr; Check(sqlite3_prepare_v2(f.db,"SELECT v FROM caller_state",-1,&s,nullptr)==SQLITE_OK,"caller state readable"); Check(sqlite3_step(s)==SQLITE_ROW && sqlite3_column_int(s,0)==7,"caller uncommitted changes preserved"); sqlite3_finalize(s); }
    { Fixture f; auto api=Api(); api.finalize=[](void* s){auto db=sqlite3_db_handle(static_cast<sqlite3_stmt*>(s));auto rc=sqlite3_finalize(static_cast<sqlite3_stmt*>(s));sqlite3_exec(db,"ROLLBACK",nullptr,nullptr,nullptr);return rc;}; Check(Find(api,f.db).error=="caller_transaction_required","lost transaction fails closed at boundary"); }
    SnapshotTests();
    ControllerTests();
    std::cout<<"contact_lookup_tests: "<<checks<<" checks passed (synthetic SQLite only)\n";
    return 0;
}

// Offline experiments only. No CLI path, WeChat handle, offset, key, or production adapter.
#include "contact_lookup.h"
#include <sqlite3.h>
#include <atomic>
#include <algorithm>
#include <vector>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <thread>

namespace {
int checks=0;
void Check(bool ok,const char* why)
{
    ++checks;
    if (!ok) throw std::runtime_error(why);
}
void Exec(sqlite3* db,const std::string& sql)
{
    const auto result=sqlite3_exec(db,sql.c_str(),nullptr,nullptr,nullptr);
    if (result!=SQLITE_OK) std::cerr<<"fixture SQL failed: "<<result<<" "<<sqlite3_errmsg(db)<<" sql="<<sql<<'\n';
    Check(result==SQLITE_OK,"fixture SQL");
}
int Count(sqlite3* db,const char* sql)
{
    sqlite3_stmt* statement=nullptr;
    Check(sqlite3_prepare_v2(db,sql,-1,&statement,nullptr)==SQLITE_OK,"count prepare");
    Check(sqlite3_step(statement)==SQLITE_ROW,"count row");
    const auto count=sqlite3_column_int(statement,0);
    Check(sqlite3_finalize(statement)==SQLITE_OK,"count finalize");
    return count;
}
contact_lookup::Sqlite Api()
{
    return {
        [](void* db,const char* sql,int n,void** statement,const char** tail) {
            return sqlite3_prepare_v2(static_cast<sqlite3*>(db),sql,n,reinterpret_cast<sqlite3_stmt**>(statement),tail);
        },
        [](void* s){return sqlite3_stmt_readonly(static_cast<sqlite3_stmt*>(s));},
        [](void* s){return sqlite3_bind_parameter_count(static_cast<sqlite3_stmt*>(s));},
        [](void* s,int n,const char* text,int size,void(*destroy)(void*)) {
            return sqlite3_bind_text(static_cast<sqlite3_stmt*>(s),n,text,size,destroy);
        },
        [](void* s){return sqlite3_step(static_cast<sqlite3_stmt*>(s));},
        [](void* s){return sqlite3_column_count(static_cast<sqlite3_stmt*>(s));},
        [](void* s,int c){return sqlite3_column_type(static_cast<sqlite3_stmt*>(s),c);},
        [](void* s,int c){return sqlite3_column_text(static_cast<sqlite3_stmt*>(s),c);},
        [](void* s,int c){return sqlite3_column_bytes(static_cast<sqlite3_stmt*>(s),c);},
        [](void* s){return sqlite3_finalize(static_cast<sqlite3_stmt*>(s));},
        [](void* db){return sqlite3_get_autocommit(static_cast<sqlite3*>(db));}
    };
}
constexpr int ReadFlags=SQLITE_OPEN_READONLY|SQLITE_OPEN_FULLMUTEX|SQLITE_OPEN_PRIVATECACHE;
struct Fixture {
    std::filesystem::path directory,path;
    sqlite3* writer=nullptr;
    std::vector<sqlite3*> readers;
    Fixture() {
        for (int i=0;i<64 && directory.empty();++i) {
            auto candidate=std::filesystem::temp_directory_path()
                /("contact-adapter-fixture-"+std::to_string(std::random_device{}()));
            if (std::filesystem::create_directory(candidate)) directory=std::move(candidate);
        }
        Check(!directory.empty(),"private fixture directory");
        path=directory/"contact.db";
        Check(sqlite3_open(path.u8string().c_str(),&writer)==SQLITE_OK,"writer open");
        Exec(writer,"PRAGMA journal_mode=WAL; CREATE TABLE contact(username TEXT,nick_name TEXT,remark TEXT,alias TEXT);"
            "INSERT INTO contact VALUES('wxid_original','金浩枫','','synthetic'); CREATE TABLE caller_state(v)");
    }
    ~Fixture() {
        // On a failed assertion, clean only the handles owned by this synthetic fixture.
        for (auto reader:readers) {
            while (auto statement=sqlite3_next_stmt(reader,nullptr)) sqlite3_finalize(statement);
            sqlite3_close(reader);
        }
        Check(sqlite3_next_stmt(writer,nullptr)==nullptr,"writer has no leftover statements");
        Check(sqlite3_close(writer)==SQLITE_OK,"writer close");
        Check(std::filesystem::remove_all(directory)>0,"fixture database and sidecars removed");
    }
    void Remember(sqlite3* reader) { if (reader) readers.push_back(reader); }
    sqlite3* OpenReader() {
        sqlite3* reader=nullptr;
        const auto opened=sqlite3_open_v2(path.u8string().c_str(),&reader,ReadFlags,nullptr);
        Remember(reader);
        Check(opened==SQLITE_OK,"owned reader open");
        Check(reader!=writer && sqlite3_db_readonly(reader,"main")==1,"distinct readonly main connection");
        Check(sqlite3_get_autocommit(reader)!=0,"fresh connection starts outside a transaction");
        Exec(reader,"PRAGMA query_only=ON; BEGIN"); // Only this test-owned connection.
        return reader;
    }
    void CloseReader(sqlite3* reader) {
        const auto found=std::find(readers.begin(),readers.end(),reader);
        Check(found!=readers.end(),"fixture owns reader being closed");
        Check(sqlite3_next_stmt(reader,nullptr)==nullptr,"owned reader statements finalized");
        Check(sqlite3_close(reader)==SQLITE_OK,"owned reader close succeeds");
        readers.erase(found);
    }
};
void OwnedContext()
{
    Fixture f;
    Exec(f.writer,"BEGIN; INSERT INTO caller_state VALUES(7); UPDATE contact SET username='wxid_pending'");
    auto reader=f.OpenReader();
    auto api=Api();
    auto result=contact_lookup::Find(api,reader);
    Check(result.candidates.size()==1 && result.candidates[0].id=="wxid_original","owned reader excludes host uncommitted changes");
    Check(sqlite3_exec(reader,"INSERT INTO caller_state VALUES(8)",nullptr,nullptr,nullptr)==SQLITE_READONLY,"owned query-only context refuses writes");
    Check(sqlite3_get_autocommit(f.writer)==0,"host write transaction remains active");
    Check(Count(f.writer,"SELECT count(*) FROM caller_state")==1,"host pending row remains visible to host");
    f.CloseReader(reader); // Ends only our read transaction.
    Check(sqlite3_get_autocommit(f.writer)==0 && Count(f.writer,"SELECT count(*) FROM caller_state")==1,"owned close does not rollback host transaction");
    Exec(f.writer,"COMMIT");
    reader=f.OpenReader();
    result=contact_lookup::Find(api,reader);
    Check(result.candidates.size()==1 && result.candidates[0].id=="wxid_pending","new owned context sees committed update");
    f.CloseReader(reader);
    std::cout<<"owned_context: pending host writes isolated; owner close preserved host transaction\n";
}
void FailureAndSnapshot()
{
    Fixture f;
    Exec(f.writer,"BEGIN; INSERT INTO caller_state VALUES(7)");
    auto reader=f.OpenReader();
    auto api=Api();
    api.step=[](void*){return SQLITE_BUSY;};
    const auto failed=contact_lookup::Find(api,reader);
    Check(failed.state=="failed" && failed.candidates.empty(),"reader BUSY fails without candidates");
    f.CloseReader(reader);
    Check(sqlite3_get_autocommit(f.writer)==0 && Count(f.writer,"SELECT count(*) FROM caller_state")==1,"reader failure leaves host pending writes intact");
    Exec(f.writer,"ROLLBACK");
    reader=f.OpenReader();
    api=Api();
    const auto first=contact_lookup::Find(api,reader);
    Exec(f.writer,"UPDATE contact SET username='wxid_committed_next'");
    const auto second=contact_lookup::Find(api,reader);
    Check(first.candidates.size()==1 && second.candidates.size()==1 && second.candidates[0].id==first.candidates[0].id,"owned explicit transaction retains original snapshot");
    f.CloseReader(reader);
    reader=f.OpenReader();
    const auto next=contact_lookup::Find(api,reader);
    Check(next.candidates.size()==1 && next.candidates[0].id=="wxid_committed_next","new read transaction sees next committed snapshot");
    f.CloseReader(reader);
    std::cout<<"failure_and_snapshot: BUSY isolated; committed changes remain outside existing snapshot\n";
}
void ReadonlyIsNotConnectionIsolation()
{
    Fixture f;
    sqlite3* reader=nullptr;
    const auto opened=sqlite3_open_v2(f.path.u8string().c_str(),&reader,ReadFlags,nullptr);
    f.Remember(reader);
    Check(opened==SQLITE_OK,"readonly counterexample open");
    // READONLY for main does not prevent pending writes in the temporary database.
    Exec(reader,"CREATE TEMP TABLE caller_state(v); BEGIN; INSERT INTO temp.caller_state VALUES(1)");
    Check(sqlite3_db_readonly(reader,"main")==1,"main still readonly despite other pending writes");
    Check(sqlite3_get_autocommit(reader)==0,"readonly main has active caller transaction");
    Check(Count(reader,"SELECT count(*) FROM temp.caller_state")==1,"temp pending write exists");
    f.CloseReader(reader);
    std::cout<<"readonly_counterexample: db_readonly(main)=1 did not exclude temp writes\n";
}
void IdentityIsNotSchema()
{
    Fixture first,second;
    Exec(second.writer,"UPDATE contact SET username='wxid_other_account'");
    auto api=Api();
    auto a=first.OpenReader(),b=second.OpenReader();
    const auto left=contact_lookup::Find(api,a),right=contact_lookup::Find(api,b);
    Check(left.candidates.size()==1 && right.candidates.size()==1 && left.candidates[0].id!=right.candidates[0].id,"same schema and exact target do not bind account identity");
    Check(!contact_lookup::Json(left)["IdentityConfirmed"].get<bool>() && !contact_lookup::Json(right)["IdentityConfirmed"].get<bool>(),"neither synthetic account candidate is confirmed");
    first.CloseReader(a); second.CloseReader(b);
    std::cout<<"identity_counterexample: two valid contact databases returned different candidates\n";
}
void OpenDoesNotProveReadable()
{
    Fixture f;
    const auto path=f.directory/"not-a-database.db";
    { std::ofstream output(path,std::ios::binary); output<<std::string(4096,'x'); Check(output.good(),"synthetic non-SQLite fixture written"); }
    sqlite3* reader=nullptr;
    const auto opened=sqlite3_open_v2(path.u8string().c_str(),&reader,ReadFlags,nullptr);
    f.Remember(reader);
    Check(opened==SQLITE_OK,"open can succeed before schema can be read");
    Exec(reader,"BEGIN");
    auto api=Api();
    const auto result=contact_lookup::Find(api,reader);
    Check(result.state=="failed" && result.candidates.empty(),"unreadable schema is failure rather than missing contact");
    f.CloseReader(reader);
    // This is not an encrypted SQLCipher fixture and proves no SQLCipher compatibility.
    std::cout<<"open_counterexample: open succeeded but malformed fixture lookup failed: "<<result.error<<'\n';
}
std::atomic<int> extension_calls{0};
int AutoExtension(sqlite3* db,char**,const sqlite3_api_routines*)
{
    ++extension_calls;
    return sqlite3_exec(db,"CREATE TEMP TABLE auto_extension_state(v); INSERT INTO auto_extension_state VALUES(1)",nullptr,nullptr,nullptr);
}
void GlobalInitializationIsNotProvenSafe()
{
    Fixture f;
    extension_calls=0;
    Check(sqlite3_auto_extension(reinterpret_cast<void(*)()>(AutoExtension))==SQLITE_OK,"register test-only auto extension");
    sqlite3* reader=nullptr;
    const auto opened=sqlite3_open_v2(f.path.u8string().c_str(),&reader,ReadFlags,nullptr);
    f.Remember(reader);
    // Remove only this test extension; never reset host extension registrations.
    Check(sqlite3_cancel_auto_extension(reinterpret_cast<void(*)()>(AutoExtension))==1,"remove test-only auto extension");
    Check(opened==SQLITE_OK && extension_calls==1,"readonly open ran global initialization callback");
    Check(Count(reader,"SELECT count(*) FROM temp.auto_extension_state")==1,"initialization callback ran before query-only setup");
    f.CloseReader(reader);
    std::cout<<"global_initialization: readonly open executed one auto-extension callback\n";
}
void ParallelOwnedReaders()
{
    Fixture f;
    std::atomic<int> passed{0};
    std::thread workers[4];
    for (auto& worker:workers) worker=std::thread([&] {
        sqlite3* reader=nullptr;
        int opened=sqlite3_open_v2(f.path.u8string().c_str(),&reader,ReadFlags,nullptr);
        if (opened!=SQLITE_OK) { if(reader) sqlite3_close(reader); return; }
        const auto begun=sqlite3_exec(reader,"PRAGMA query_only=ON; BEGIN",nullptr,nullptr,nullptr);
        auto api=Api();
        const auto result=contact_lookup::Find(api,reader);
        const bool ok=begun==SQLITE_OK && result.candidates.size()==1 && result.candidates[0].id=="wxid_original"
            && sqlite3_next_stmt(reader,nullptr)==nullptr;
        const auto closed=sqlite3_close(reader);
        if (ok && closed==SQLITE_OK) ++passed;
    });
    for (auto& worker:workers) worker.join();
    Check(passed==4,"four thread-owned readers complete and close independently");
    std::cout<<"parallel_owned_readers: 4 completed without sharing SQLite handles\n";
}
}
int main()
{
    try {
    std::cout<<"contact_adapter_feasibility SQLite "<<sqlite3_libversion()<<'\n';
    OwnedContext();
    FailureAndSnapshot();
    ReadonlyIsNotConnectionIsolation();
    IdentityIsNotSchema();
    OpenDoesNotProveReadable();
    GlobalInitializationIsNotProvenSafe();
    ParallelOwnedReaders();
    std::cout<<"contact_adapter_feasibility: "<<checks<<" checks passed (synthetic SQLite only; no native adapter)\n";
    } catch (const std::exception& error) { std::cerr<<"FAILED: "<<error.what()<<'\n'; return 1; }
}

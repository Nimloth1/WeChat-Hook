#include "send_native.h"
#include "send_link.h"
#include <iostream>
using namespace send_fix;
using json=nlohmann::json;
static int checks=0;
void Check(bool v) {++checks;if(!v)throw std::runtime_error("link_check_"+std::to_string(checks));}
json Body() {return {{"request_id","offline-link-card-0001"},{"wxidorgid","12345678901@chatroom"},
    {"title",u8"国泰君安：能化观察 <&> 😀"},{"description",u8"离线说明\n第二行"},{"url","https://example.com/report?a=1&b=2#section"}};}
bool Reject(const json& b) {try{ParseRequest("link",b.dump());return false;}catch(...){return true;}}
struct Fake : Backend {
    int prepared=0,run=0;
    struct Call : PreparedCall {Fake& f;explicit Call(Fake& x):f(x){}Result Run() override {++f.run;return {200,"sent","",true};}};
    std::unique_ptr<PreparedCall> Prepare(const Request&,const Approval&) override {++prepared;return std::make_unique<Call>(*this);}
};
int main() {
    try {
        const auto b=Body();auto r=ParseRequest("link",b.dump());
        Check(r.kind=="link" && r.title==b["title"] && r.description==b["description"] && r.value==b["url"]);
        Check(Fingerprint(r)==Sha256(json{{"kind","link"},{"recipient",r.recipient},{"title",r.title},
            {"description",r.description},{"url",r.value}}.dump().data(),
            json{{"kind","link"},{"recipient",r.recipient},{"title",r.title},{"description",r.description},{"url",r.value}}.dump().size()));
        for(const auto& field : {"request_id","wxidorgid","title","description","url"}) {
            auto x=b;x.erase(field);Check(Reject(x));x=b;x[field]=3;Check(Reject(x));
        }
        auto x=b;x["xml"]="<appmsg/>";Check(Reject(x));
        for(const auto& url : {"", "file:///C:/x", "javascript:alert(1)", "data:text/html,x", "https://", "https://user:pass@example.com/",
            "https://example.com\\file", "https://example.com/\r\nInjected: x", "https://example.com:0/", "https://example.com:65536/",
            "https://example.com:x/", "https://example.com:80:90/", "https://.example.com/", "https://a..b/"}) {
            x=b;x["url"]=url;Check(Reject(x));
        }
        for(const auto& field : {"title","description","url"}) {
            x=b;x[field]=std::string("a\0b",3);Check(Reject(x));
        }
        x=b;x["title"]=std::string(257,'a');Check(Reject(x));
        x=b;x["title"]=" \n\t";Check(Reject(x));
        x=b;x["description"]=std::string(2001,'x');Check(Reject(x));
        x=b;x["url"]="https://example.com/"+std::string(2048,'x');Check(Reject(x));
        for(const auto& url : {"https://example.com/", "http://example.com:8080/a?b=1&c=2", "https://xn--fiqs8s.example/a%20b"}) {
            x=b;x["url"]=url;x["description"]="";Check(!Reject(x));
        }
        const std::string token(40,'a');Approval a{true,token,r.id,r.recipient,"link",Fingerprint(r),std::string(64,'f'),0,2};
        for(const auto& field : {"title","description","url","wxidorgid","request_id"}) {
            Fake f;int consumed=0;Controller c(a,f,[&](const Approval&){++consumed;return true;});
            x=b;x[field]=field==std::string("url") ? "https://other.example/" : field==std::string("wxidorgid") ? "12345678902@chatroom" : "different-value-0001";
            Check(c.Dispatch("Bearer "+token,"link",x.dump()).http==403);Check(f.run==0 && consumed==0);
        }
        Fake f;int consumed=0;Controller c(a,f,[&](const Approval&){++consumed;return true;});
        Check(c.Dispatch("Bearer wrong","link",b.dump()).http==403 && consumed==0);
        Check(c.Dispatch("Bearer "+token,"text",json{{"request_id",r.id},{"wxidorgid",r.recipient},{"msg",r.value}}.dump()).http==403);
        auto result=c.Dispatch("Bearer "+token,"link",b.dump());
        Check(result.http==202 && result.state=="unconfirmed" && result.native_entered && consumed==1 && f.run==1);
        Check(c.Dispatch("Bearer "+token,"link",b.dump()).replayed && f.run==1 && consumed==1);
        x=b;x["title"]="different";Check(c.Dispatch("Bearer "+token,"link",x.dump()).http==409 && f.run==1);
        Check(GetModuleHandleW(L"Weixin.dll")==nullptr);
        std::cout<<"PASS send_link checks="<<checks<<"; strict fields, exact approval, no native calls\n";
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}

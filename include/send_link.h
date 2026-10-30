#pragma once
#include "send_layout.h"
#include <algorithm>

namespace send_fix {
inline void ValidateLink(const std::string& title, const std::string& description, const std::string& url)
{
    const auto t=Utf16(title), d=Utf16(description), u=Utf16(url);
    if(t.empty() || t.size()>256 || d.size()>2000 || u.size()>2048
        || std::all_of(title.begin(),title.end(),[](unsigned char c){return c==' ' || c=='\t' || c=='\r' || c=='\n';}))
        throw std::invalid_argument("link_fields_invalid");
    // 不取网页、不接受外部 XML 或本地/可执行协议；微信处理实际点击。
    const auto start=url.compare(0,8,"https://")==0 ? 8u : url.compare(0,7,"http://")==0 ? 7u : 0u;
    if(!start || std::any_of(url.begin(),url.end(),[](unsigned char c){return c<=32 || c==127 || c=='\\';}))
        throw std::invalid_argument("link_url_invalid");
    const auto end=url.find_first_of("/?#",start);
    const auto authority=url.substr(start,end==std::string::npos ? end : end-start);
    if(authority.empty() || authority.find('@')!=std::string::npos
        || std::any_of(authority.begin(),authority.end(),[](unsigned char c){
            return !((c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') || c=='.' || c=='-' || c==':');}))
        throw std::invalid_argument("link_url_invalid");
    const auto colon=authority.find(':');
    const auto host=authority.substr(0,colon);
    if(host.empty() || host.front()=='.' || host.back()=='.' || host.find("..")!=std::string::npos)
        throw std::invalid_argument("link_url_invalid");
    if(colon!=std::string::npos) {
        const auto port=authority.substr(colon+1);
        if(port.empty() || port.size()>5 || !std::all_of(port.begin(),port.end(),[](char c){return c>='0'&&c<='9';})
            || std::stoul(port)==0 || std::stoul(port)>65535) throw std::invalid_argument("link_url_invalid");
    }
    for(const auto& text : {title,description})
        if(std::any_of(text.begin(),text.end(),[](unsigned char c){return (c<32 && c!='\t' && c!='\r' && c!='\n') || c==127;}))
            throw std::invalid_argument("link_fields_invalid");
}

// 4.1.10.27 ForwardWebPage 的同一原生对象，不经旧作者协议 Hook 或任意 XML。
// 字段证据：0x3f89729/774/7fb 的 url/title/digest -> 0x798/0x708/0x728。
struct LinkStrings { NarrowString title{}, description{}, url{}; };
inline LinkStrings MakeLinkStrings(Arena& arena,const std::string& title,
    const std::string& description,const std::string& url)
{
    return {MakeNarrow(arena,title,true),MakeNarrow(arena,description,true),MakeNarrow(arena,url,true)};
}
inline void FinishLinkFrame(Frame& frame,const LinkStrings& strings)
{
    auto object=static_cast<char*>(frame.object)+16;
    for(auto offset : {0xb0,0x708,0x728,0x798}) {
        NarrowString current{};std::memcpy(&current,object+offset,32);
        if(current.length || current.capacity>15) throw std::runtime_error("unexpected_link_constructor_layout");
    }
    std::uint64_t self=0,control=0;
    std::memcpy(&self,object+8,8);std::memcpy(&control,object+16,8);
    if(self || control) throw std::runtime_error("unexpected_link_constructor_layout");
    Put64(frame.object,8,0x200000001);
    Put64(object,8,reinterpret_cast<std::uint64_t>(object));
    Put64(object,16,reinterpret_cast<std::uint64_t>(frame.object));
    std::memcpy(object+0xb0,&frame.receiver,32);
    std::memcpy(object+0x708,&strings.title,32);
    std::memcpy(object+0x728,&strings.description,32);
    std::memcpy(object+0x798,&strings.url,32);
    Put64(object,0xd8,0x500000031);
}
} // namespace send_fix

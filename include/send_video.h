#pragma once
#include "send_layout.h"
namespace send_fix {
// 4.1.10.27: 工厂0x22a9190，构造0x18efd70，路径/缩略图/秒数对应
// 0x437499e/0x437498e/0x43749cf。只构造本地MP4消息，不复用CDN密钥或原XML。
inline void FinishVideoFrame(Frame& frame,const WideString& thumbnail,std::uint64_t bytes,std::uint32_t seconds)
{
    auto object=static_cast<char*>(frame.object)+16;
    for(auto offset : {0xb0,0x168}) {
        NarrowString current{};std::memcpy(&current,object+offset,32);
        if(current.length || current.capacity>15) throw std::runtime_error("unexpected_video_constructor_layout");
    }
    for(auto offset : {0xe0,0x720}) {
        WideString current{};std::memcpy(&current,object+offset,32);
        if(current.length || current.capacity>7) throw std::runtime_error("unexpected_video_constructor_layout");
    }
    std::uint64_t self=0,control=0;
    std::memcpy(&self,object+8,8);std::memcpy(&control,object+16,8);
    if(self || control) throw std::runtime_error("unexpected_video_constructor_layout");
    Put64(frame.object,8,0x200000001);
    Put64(object,8,reinterpret_cast<std::uint64_t>(object));
    Put64(object,16,reinterpret_cast<std::uint64_t>(frame.object));
    std::memcpy(object+0xb0,&frame.receiver,32);
    std::memcpy(object+0xe0,&frame.file_path,32);
    std::memcpy(object+0x168,&frame.filename,32);
    std::memcpy(object+0x720,&thumbnail,32);
    Put64(object,0xd8,43);
    Put64(object,0x188,bytes);
    std::memcpy(object+0x71c,&seconds,4);
}
} // namespace send_fix

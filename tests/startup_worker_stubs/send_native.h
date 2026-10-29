#pragma once
#include <string>
#include <functional>
namespace send_fix {
struct Approval {};
struct WindowsBackend {};
inline std::string ApprovalPath(){return "synthetic";}
inline Approval LoadApproval(const std::string&){return {};}
inline bool ConsumeApproval(const std::string&,const Approval&){return true;}
struct Controller {
    Controller(std::function<Approval()>,WindowsBackend&,std::function<bool(const Approval&)>){}
};
}

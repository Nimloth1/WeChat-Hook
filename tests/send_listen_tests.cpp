// Native WinSock failure in a test-owned server. No WeChat DLL or network message.
#include "httplib.h"
#include <cerrno>
#include <iostream>

namespace {
int cleanups=0;
struct ClearingQueue : httplib::TaskQueue {
    ~ClearingQueue() override { ++cleanups; WSASetLastError(0); SetLastError(0); }
    void enqueue(std::function<void()>) override { throw std::runtime_error("unexpected_connection"); }
    void shutdown() override { ++cleanups; WSASetLastError(0); SetLastError(0); }
};
struct TestServer : httplib::Server {
    void BrokenSocket() { svr_sock_=static_cast<socket_t>(-2); }
    void ClearForTest() { svr_sock_=INVALID_SOCKET; }
};
}
int main()
{
    if(GetModuleHandleW(L"Weixin.dll"))return 1;
    for(bool fail:{false,true}) {
        TestServer server;
        server.new_task_queue=[] { return new ClearingQueue; };
        if(fail)server.BrokenSocket(); // Invalid sentinel; never another process's handle.
        cleanups=0;errno=0;WSASetLastError(0);SetLastError(0);
        const auto result=server.listen_after_bind();
        const auto error=WSAGetLastError();
        server.ClearForTest();
        std::cout<<"listen_failure="<<fail<<" returned="<<result<<" winsock="<<error<<" cleanup_calls="<<cleanups<<'\n';
        if(cleanups!=2 || (fail ? result || error!=WSAENOTSOCK : !result || error!=0))return 2;
    }
    std::cout<<"PASS native listen failure survives socket/queue cleanup; normal return remains true; no messages\n";
}

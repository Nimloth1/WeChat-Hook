// Only a synthetic Weixin.exe child runs this program. No real Weixin.dll or POST.
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include "send_startup.h"
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

int wmain(int argc,wchar_t** argv)
{
    if(argc<4 || GetModuleHandleW(L"Weixin.dll"))return 2;
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    if(!SetEnvironmentVariableW(L"LOCALAPPDATA",argv[2]))return 3;
#ifdef SEND_STARTUP_STATIC_IMPORT
    DWORD ignored=0;
    if(!GetFileVersionInfoSizeW(L"C:\\Windows\\System32\\kernel32.dll",&ignored))return 4;
    const auto module=GetModuleHandleW(L"version.dll");
#else
    const auto module=LoadLibraryExW(argv[1],nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
#endif
    if(!module)return 5;
    wchar_t loaded[32768]{};
    if(!GetModuleFileNameW(module,loaded,32768) || !std::filesystem::equivalent(loaded,argv[1]))return 6;
    const auto state=reinterpret_cast<const send_fix::StartupState*>(GetProcAddress(module,"SendFixStartupState"));
    if(!state || state->magic!=send_fix::StartupMagic || state->version!=1 || state->bytes!=sizeof(*state))return 7;
    Sleep(1500);
    std::cout<<"loader="<<state->loader_stage<<" worker="<<state->worker_stage
        <<" win32="<<state->win32_error<<" winsock="<<state->winsock_error
        <<" thread="<<state->worker_thread_id<<" stdcode="<<state->standard_error_code
        <<" stdcategory="<<state->standard_error_category<<'\n';
    const std::wstring mode=argv[3];
    using Loader=send_fix::LoaderStage;
    using Worker=send_fix::WorkerStage;
    if(mode==L"child") {
        if(state->loader_stage!=static_cast<LONG>(Loader::child_process)
            || state->worker_stage!=static_cast<LONG>(Worker::not_entered) || state->worker_thread_id)return 8;
        return GetModuleHandleW(L"Weixin.dll") ? 9 : 0;
    }
    if(state->loader_stage!=static_cast<LONG>(Loader::thread_created) || !state->worker_thread_id)return 10;
    if(mode==L"collision") {
        // Read the data export despite no HTTP service, which is the purpose of this change.
        if(state->worker_stage!=static_cast<LONG>(Worker::bind_failed)
            || (state->winsock_error!=WSAEACCES && state->winsock_error!=WSAEADDRINUSE))return 11;
        return GetModuleHandleW(L"Weixin.dll") ? 12 : 0;
    }
    if(mode!=L"ready" || state->worker_stage!=static_cast<LONG>(Worker::listen_entered))return 13;
    DWORD size=0;
    GetExtendedTcpTable(nullptr,&size,FALSE,AF_INET,TCP_TABLE_OWNER_PID_LISTENER,0);
    std::vector<unsigned char> buffer(size);
    if(GetExtendedTcpTable(buffer.data(),&size,FALSE,AF_INET,TCP_TABLE_OWNER_PID_LISTENER,0)!=NO_ERROR)return 14;
    const auto table=reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    bool owned=false;
    for(DWORD i=0;i<table->dwNumEntries;++i) {
        const auto& row=table->table[i];
        if(ntohs(static_cast<u_short>(row.dwLocalPort))==30001 && row.dwLocalAddr==htonl(INADDR_LOOPBACK)
            && row.dwOwningPid==GetCurrentProcessId())owned=true;
    }
    if(!owned)return 15;
    WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data))return 16;
    const auto socket=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    DWORD timeout=3000;
    setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
    setsockopt(socket,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(30001);address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(socket,reinterpret_cast<const sockaddr*>(&address),sizeof(address)))return 17;
    const std::string request="GET /QueryDB/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    send(socket,request.data(),static_cast<int>(request.size()),0);
    std::string reply;char bytes[2048];int received=0;
    while((received=recv(socket,bytes,sizeof(bytes),0))>0 && reply.size()<8192)reply.append(bytes,received);
    closesocket(socket);WSACleanup();
    std::cout<<reply<<'\n';
    if(reply.find("vw12-send-fix-v1")==std::string::npos || reply.find("\"SendApprovalConfigured\":false")==std::string::npos)return 18;
    return GetModuleHandleW(L"Weixin.dll") ? 19 : 0;
}

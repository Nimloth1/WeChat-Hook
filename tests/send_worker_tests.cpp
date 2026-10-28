// Compile the actual worker with stand-in dependencies; no product or real Weixin.dll is loaded.
#include "../src/dllmain_send.cpp"
#include <iostream>

int main()
{
    bool passed=true;
    for(int mode=0;mode<3;++mode) {
        mock_mode=mode;mock_win32=0;mock_winsock=0;
        SendFixStartupState.worker_stage=0;
        SendFixStartupState.win32_error=0;
        SendFixStartupState.winsock_error=0;
        const auto exit=RunSendServer(nullptr);
        const auto stage=SendFixStartupState.worker_stage;
        const auto error=SendFixStartupState.winsock_error;
        std::cout<<"mode="<<mode<<" thread_exit="<<exit<<" worker_stage="<<stage
            <<" win32="<<SendFixStartupState.win32_error<<" winsock="<<error<<'\n';
        if(mode==0)passed=passed && exit==0 && stage==70 && error==0;
        if(mode==1)passed=passed && exit==1 && stage==100 && error==10048 && SendFixStartupState.win32_error==10048;
        if(mode==2)passed=passed && exit==2 && stage==150 && error==10022 && SendFixStartupState.win32_error==10022;
    }
    if(!passed)return 1;
    std::cout<<"PASS actual worker: normal return, bind failure, listen failure separated (stand-in APIs only)\n";
}

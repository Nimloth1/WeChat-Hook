#pragma once
#include "windows.h"
#include <memory>
#include <functional>
namespace httplib {
struct TaskQueue { virtual ~TaskQueue()=default; };
struct ThreadPool : TaskQueue { explicit ThreadPool(int){} };
struct Server {
    std::function<TaskQueue*()> new_task_queue;
    bool bind_to_port(const char*,int) {
        if(mock_mode==1) {mock_winsock=10048;mock_win32=10048;return false;}
        return true;
    }
    bool listen_after_bind() {
        if(mock_mode==2) {mock_winsock=10022;mock_win32=10022;return false;}
        return true;
    }
};
}

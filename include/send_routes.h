#pragma once
#include "send_api.h"
namespace httplib { class Server; }
namespace send_fix { void RegisterSendRoutes(httplib::Server& server, Controller& controller); }

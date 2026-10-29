#include "httplib.h"
#include "send_routes.h"

namespace send_fix {
void RegisterSendRoutes(httplib::Server& server, Controller& controller)
{
    server.set_socket_options([](socket_t socket) {
        const int exclusive = 1;
        if (setsockopt(socket,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&exclusive),sizeof(exclusive)) != 0) closesocket(socket);
    });
    server.set_payload_max_length(32768);
    server.set_read_timeout(3,0);
    server.set_write_timeout(3,0);
    server.Get("/QueryDB/status",[&](const httplib::Request&,httplib::Response& response) {
        const auto state = controller.Status();
        const auto retention = controller.Retention();
        const nlohmann::json value{{"Build","vw12-send-fix-v1"},{"IsLogin",nullptr},
            {"LoginStateKnown",false},{"SendApprovalConfigured",state.configured},
            {"SendAttemptConsumed",state.consumed},{"SendInProgress",state.busy},
            {"ApprovalReload","per_request"},{"ApprovalVersion2GroupOnly",true},
            {"RetainedParameterBytes",retention.bytes},{"RetainedImageHandles",retention.handles},
            {"RetainedParameterByteLimit",retention.byte_limit},{"RetainedImageHandleLimit",retention.handle_limit},
            {"NativeResourceReclamationVerified",false},
            {"DeliveryConfirmed",false},
            {"FileSendSupported",false},{"RuntimeCompatibilityVerified",false}};
        response.set_content(value.dump(),"application/json");
    });
    const auto route = [&](const char* path,const std::string& kind) {
        server.Post(path,[&,kind](const httplib::Request& request,httplib::Response& response) {
            try {
                const auto result = controller.Dispatch(request.get_header_value("Authorization"),kind,request.body);
                response.status = result.http;
                response.set_content(Response(result).dump(),"application/json");
            } catch (...) {
                response.status = 500;
                response.set_content(R"({"state":"unknown","IsSent":null,"DeliveryConfirmed":false,"error":"handler_exception_no_retry"})","application/json");
            }
        });
    };
    route("/SendTextMsg","text");
    route("/SendImgMsg","image");
    server.Post("/send_file_msg",[](const httplib::Request&,httplib::Response& response) {
        response.status = 501;
        response.set_content(R"({"state":"not_attempted","IsSent":null,"error":"file_send_source_not_available"})","application/json");
    });
}
} // namespace send_fix

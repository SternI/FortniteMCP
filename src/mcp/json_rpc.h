#pragma once

#include "mcp/http_server.h"
#include "mcp/tools.h"

#include <mutex>
#include <nlohmann/json.hpp>
#include <string>

namespace fmcp {

struct RpcReply {
    bool hasResponse = false;
    nlohmann::json response;
};

class McpServer {
public:
    McpServer();
    RpcReply Handle(const nlohmann::json& message);
    HttpResponse HandleHttp(const HttpRequest& request);

private:
    nlohmann::json HandleRequest(const std::string& method, const nlohmann::json& params,
                                 const nlohmann::json& id);
    nlohmann::json Error(const nlohmann::json& id, int code, const std::string& message);
    bool Authorized(const HttpRequest& request) const;

    ToolRegistry tools_;
    std::mutex callMutex_;
    uint64_t startedAt_ = 0;
};

}

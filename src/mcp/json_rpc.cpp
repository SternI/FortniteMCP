#include "mcp/json_rpc.h"

#include "core/config.h"
#include "core/lifecycle.h"
#include "core/log.h"
#include "core/memory.h"
#include "core/strings.h"
#include "ue/context.h"

#include <algorithm>
#include <chrono>

namespace fmcp {

namespace {

constexpr const char* kServerName = "FortniteMCP";

const char* kInstructions =
    "FortniteMCP controls the injected game process. Tools are grouped as memory_*, object/UE tools, "
    "input_*, dll tools, and shutdown. Addresses accept hex, decimal, or module+offset. "
    "UE tools require offsets in config.json or ue_configure; call status/ue_status first. "
    "ProcessEvent and call_address run on the game thread when the hook is available; otherwise "
    "they fail unless direct_fallback is enabled. Raw calls can crash the game: validate arguments "
    "and targets first. Use memory_read/memory_scan to inspect before writing. Use offline/private "
    "builds only.";

const char* ChooseProtocolVersion(const std::string& requested) {
    if (requested == "2024-11-05" || requested == "2025-03-26" || requested == "2025-06-18") {
        return requested == "2024-11-05" ? "2024-11-05"
              : requested == "2025-03-26" ? "2025-03-26" : "2025-06-18";
    }
    return "2025-06-18";
}

bool ConstantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

std::string ExtractToken(const HttpRequest& request) {
    for (const char* name : {"authorization", "x-mcp-token"}) {
        std::string value = request.Header(name);
        if (value.empty()) {
            continue;
        }
        if (str::StartsWith(str::ToLower(value), "bearer ")) {
            value = str::Trim(value.substr(7));
        }
        return value;
    }
    return {};
}

}

McpServer::McpServer() {
    RegisterAllTools(tools_);
    startedAt_ = GetTickCount64();
}

bool McpServer::Authorized(const HttpRequest& request) const {
    const Config& config = Config::Get();
    if (config.server.token.empty()) {
        return true;
    }
    return ConstantTimeEquals(ExtractToken(request), config.server.token);
}

nlohmann::json McpServer::Error(const nlohmann::json& id, int code, const std::string& message) {
    nlohmann::json error = {{"jsonrpc", "2.0"},
                            {"id", id},
                            {"error", {{"code", code}, {"message", message}}}};
    return error;
}

RpcReply McpServer::Handle(const nlohmann::json& message) {
    RpcReply reply;

    if (message.is_array()) {
        if (message.empty()) {
            reply.hasResponse = true;
            reply.response = Error(nullptr, -32600, "empty batch");
            return reply;
        }
        nlohmann::json responses = nlohmann::json::array();
        for (const auto& item : message) {
            RpcReply itemReply = Handle(item);
            if (itemReply.hasResponse) {
                responses.push_back(std::move(itemReply.response));
            }
        }
        if (!responses.empty()) {
            reply.hasResponse = true;
            reply.response = std::move(responses);
        }
        return reply;
    }

    if (!message.is_object()) {
        reply.hasResponse = true;
        reply.response = Error(nullptr, -32600, "invalid request");
        return reply;
    }

    const bool hasId = message.contains("id");
    const nlohmann::json id = hasId ? message["id"] : nlohmann::json(nullptr);
    const bool isNotification = !hasId;

    if (!message.contains("method") || !message["method"].is_string()) {
        if (isNotification) {
            return reply;
        }
        reply.hasResponse = true;
        reply.response = Error(id, -32600, "missing method");
        return reply;
    }

    const std::string method = message["method"].get<std::string>();
    if (str::StartsWith(method, "notifications/")) {
        if (method == "notifications/initialized" || method == "notifications/cancelled") {
            FMCP_LOGD("MCP notification: %s", method.c_str());
        }
        return reply;
    }

    if (isNotification) {
        return reply;
    }

    const nlohmann::json params = message.contains("params") && !message["params"].is_null()
                                      ? message["params"]
                                      : nlohmann::json::object();

    const uint64_t start = GetTickCount64();
    nlohmann::json result;
    try {
        result = HandleRequest(method, params, id);
    } catch (const ToolError& e) {
        result = Error(id, -32602, e.what());
    } catch (const std::exception& e) {
        result = Error(id, -32603, e.what());
    } catch (...) {
        result = Error(id, -32603, "internal error");
    }

    FMCP_LOGD("MCP %s (%llu ms)", method.c_str(),
              static_cast<unsigned long long>(GetTickCount64() - start));
    reply.hasResponse = true;
    reply.response = std::move(result);
    return reply;
}

nlohmann::json McpServer::HandleRequest(const std::string& method, const nlohmann::json& params,
                                        const nlohmann::json& id) {
    if (method == "initialize") {
        const std::string requested = params.is_object() && params.contains("protocolVersion")
                                          ? params["protocolVersion"].get<std::string>()
                                          : std::string{};
        return {{"jsonrpc", "2.0"},
                {"id", id},
                {"result", {{"protocolVersion", ChooseProtocolVersion(requested)},
                            {"capabilities", {{"tools", {{"listChanged", false}}}}},
                            {"serverInfo", {{"name", kServerName}, {"version", FMCP_VERSION}}},
                            {"instructions", kInstructions}}}};
    }

    if (method == "ping") {
        return {{"jsonrpc", "2.0"}, {"id", id}, {"result", nlohmann::json::object()}};
    }

    if (method == "tools/list") {
        return {{"jsonrpc", "2.0"}, {"id", id}, {"result", {{"tools", tools_.List()}}}};
    }

    if (method == "tools/call") {
        if (!params.is_object() || !params.contains("name") || !params["name"].is_string()) {
            throw ToolError("tools/call requires a tool name");
        }
        const std::string name = params["name"].get<std::string>();
        if (!tools_.Find(name)) {
            throw ToolError("unknown tool: " + name);
        }
        const nlohmann::json arguments = params.contains("arguments") ? params["arguments"]
                                                                     : nlohmann::json::object();

        std::lock_guard lock(callMutex_);
        return {{"jsonrpc", "2.0"}, {"id", id}, {"result", tools_.Call(name, arguments)}};
    }

    if (method == "resources/list") {
        return {{"jsonrpc", "2.0"}, {"id", id}, {"result", {{"resources", nlohmann::json::array()}}}};
    }

    if (method == "resources/templates/list") {
        return {{"jsonrpc", "2.0"}, {"id", id},
                {"result", {{"resourceTemplates", nlohmann::json::array()}}}};
    }

    if (method == "prompts/list") {
        return {{"jsonrpc", "2.0"}, {"id", id}, {"result", {{"prompts", nlohmann::json::array()}}}};
    }

    if (method == "logging/setLevel") {
        return {{"jsonrpc", "2.0"}, {"id", id}, {"result", nlohmann::json::object()}};
    }

    return Error(id, -32601, "method not found: " + method);
}

HttpResponse McpServer::HandleHttp(const HttpRequest& request) {
    HttpResponse response;

    if (str::IEquals(request.method, "OPTIONS")) {
        response.status = 204;
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
        response.headers["Access-Control-Allow-Headers"] =
            "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, X-MCP-Token";
        response.headers["Access-Control-Max-Age"] = "600";
        return response;
    }

    if (request.path == "/health" || request.path == "/") {
        if (!str::IEquals(request.method, "GET") && !str::IEquals(request.method, "HEAD")) {
            response.status = 405;
            response.headers["Allow"] = "GET, HEAD, OPTIONS";
            response.body = "{\"error\":\"method not allowed\"}";
            return response;
        }

        std::lock_guard lock(callMutex_);
        auto& ctx = ue::UeContext::Get();
        const ue::ResolveReport& report = ctx.Report();
        nlohmann::json health = {
            {"ok", true},
            {"name", kServerName},
            {"version", FMCP_VERSION},
            {"pid", GetCurrentProcessId()},
            {"uptime_ms", GetTickCount64() - startedAt_},
            {"ue_resolved", report.resolved},
            {"names", report.names},
            {"game_thread", report.game_thread},
            {"token_required", !Config::Get().server.token.empty()}};
        response.body = health.dump();
        return response;
    }

    if (request.path != "/mcp") {
        response.status = 404;
        response.body = "{\"error\":\"not found\"}";
        return response;
    }

    if (!str::IEquals(request.method, "POST")) {
        response.status = 405;
        response.headers["Allow"] = "POST, OPTIONS";
        response.body = "{\"error\":\"MCP requires POST\"}";
        return response;
    }

    if (!Authorized(request)) {
        response.status = 401;
        response.headers["WWW-Authenticate"] = "Bearer";
        response.body = "{\"error\":\"unauthorized\"}";
        return response;
    }

    nlohmann::json message;
    try {
        message = nlohmann::json::parse(request.body, nullptr, true, true);
    } catch (const std::exception& e) {
        response.status = 400;
        nlohmann::json error = {{"jsonrpc", "2.0"},
                                {"id", nullptr},
                                {"error", {{"code", -32700}, {"message", std::string("parse error: ") + e.what()}}}};
        response.body = error.dump();
        return response;
    }

    if (lifecycle::Pending()) {
        FMCP_LOGW("MCP request accepted while shutdown is pending");
    }

    const RpcReply reply = Handle(message);
    if (!reply.hasResponse) {
        response.status = 202;
        response.body.clear();
        response.contentType = "application/json; charset=utf-8";
        return response;
    }

    response.status = 200;
    response.body = reply.response.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    return response;
}

}

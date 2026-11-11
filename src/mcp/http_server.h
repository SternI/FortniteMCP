#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fmcp {

struct HttpRequest {
    std::string method;
    std::string target;
    std::string path;
    std::string version;
    std::string body;
    std::string remote;
    std::unordered_map<std::string, std::string> headers;

    [[nodiscard]] std::string Header(const std::string& name) const {
        auto it = headers.find(name);
        return it == headers.end() ? std::string{} : it->second;
    }
};

struct HttpResponse {
    int status = 200;
    std::string contentType = "application/json; charset=utf-8";
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    bool close = false;
};

using HttpHandler = std::function<HttpResponse(const HttpRequest&)>;
using AfterResponse = std::function<bool()>;

class HttpServer {
public:
    HttpServer() = default;
    ~HttpServer();

    bool Start(const std::string& host, uint16_t port, HttpHandler handler, size_t maxBodyBytes,
               int maxConnections, int idleTimeoutMs, std::string* error);
    void Stop();
    void SetAfterResponse(AfterResponse callback);
    [[nodiscard]] bool Running() const;
    [[nodiscard]] uint16_t Port() const;

private:
    struct ConnectionWorker {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    void AcceptLoop();
    void ConnectionLoop(uintptr_t socket, std::shared_ptr<std::atomic<bool>> done);
    std::string RemoteAddress(uintptr_t socket) const;

    std::thread acceptThread_;
    mutable std::mutex mutex_;
    std::vector<ConnectionWorker> connectionWorkers_;
    std::unordered_set<uintptr_t> sockets_;
    HttpHandler handler_;
    AfterResponse afterResponse_;
    uintptr_t listenSocket_ = static_cast<uintptr_t>(~0ull);
    uint16_t port_ = 0;
    size_t maxBodyBytes_ = 4 * 1024 * 1024;
    int maxConnections_ = 32;
    int idleTimeoutMs_ = 30000;
    bool running_ = false;
    bool stopping_ = false;
    int activeConnections_ = 0;
    bool wsaStarted_ = false;
};

}

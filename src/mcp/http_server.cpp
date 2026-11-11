#include "mcp/http_server.h"

#include "core/log.h"
#include "core/strings.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace fmcp {

namespace {

constexpr size_t kMaxHeaderBytes = 64 * 1024;

std::string ReasonPhrase(int status) {
    switch (status) {
    case 200: return "OK";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
    case 415: return "Unsupported Media Type";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default: return "OK";
    }
}

bool SendAll(SOCKET socket, const char* data, size_t size) {
    size_t sent = 0;
    while (sent < size) {
        const int chunk = static_cast<int>(std::min<size_t>(size - sent, 1 << 20));
        const int result = send(socket, data + sent, chunk, 0);
        if (result <= 0) {
            return false;
        }
        sent += static_cast<size_t>(result);
    }
    return true;
}

void CloseSocket(uintptr_t handle) {
    if (handle == static_cast<uintptr_t>(INVALID_SOCKET)) {
        return;
    }
    SOCKET socket = static_cast<SOCKET>(handle);
    shutdown(socket, SD_BOTH);
    closesocket(socket);
}

bool ContainsToken(const std::string& value, const char* token) {
    const std::string lower = str::ToLower(value);
    return lower.find(str::ToLower(token)) != std::string::npos;
}

std::string BuildResponse(const HttpResponse& response, bool close, bool headOnly) {
    std::string out;
    out.reserve(response.body.size() + 512);
    out += "HTTP/1.1 " + std::to_string(response.status) + " " + ReasonPhrase(response.status) + "\r\n";
    out += "Server: FortniteMCP\r\n";
    out += "Content-Type: " + response.contentType + "\r\n";
    out += "Content-Length: " + std::to_string(response.body.size()) + "\r\n";
    out += std::string("Connection: ") + (close ? "close" : "keep-alive") + "\r\n";
    out += "Access-Control-Allow-Origin: *\r\n";
    out += "Access-Control-Expose-Headers: Mcp-Session-Id, MCP-Protocol-Version\r\n";
    out += "X-Content-Type-Options: nosniff\r\n";

    for (const auto& [key, value] : response.headers) {
        if (str::IEquals(key, "content-length") || str::IEquals(key, "connection") ||
            str::IEquals(key, "content-type") || str::IEquals(key, "server")) {
            continue;
        }
        out += key + ": " + value + "\r\n";
    }

    out += "\r\n";
    if (!headOnly) {
        out += response.body;
    }
    return out;
}

bool SendErrorResponse(SOCKET socket, int status, const std::string& message) {
    HttpResponse response;
    response.status = status;
    response.body = "{\"error\":\"" + message + "\"}";
    response.close = true;
    const std::string wire = BuildResponse(response, true, false);
    return SendAll(socket, wire.data(), wire.size());
}

}

HttpServer::~HttpServer() {
    Stop();
}

bool HttpServer::Start(const std::string& host, uint16_t port, HttpHandler handler,
                       size_t maxBodyBytes, int maxConnections, int idleTimeoutMs,
                       std::string* error) {
    std::lock_guard lock(mutex_);
    if (running_) {
        return true;
    }
    if (!handler) {
        if (error) *error = "HTTP handler is empty";
        return false;
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        if (error) *error = "WSAStartup failed";
        return false;
    }
    wsaStarted_ = true;

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (host.empty() || host == "localhost" || host == "127.0.0.1") {
        hints.ai_flags = AI_PASSIVE;
    }

    addrinfo* result = nullptr;
    const std::string portText = std::to_string(port);
    if (getaddrinfo(host.empty() ? nullptr : host.c_str(), portText.c_str(), &hints, &result) != 0 ||
        !result) {
        if (error) *error = str::Format("getaddrinfo failed for %s:%u", host.c_str(), port);
        WSACleanup();
        wsaStarted_ = false;
        return false;
    }

    SOCKET listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listenSocket == INVALID_SOCKET) {
        freeaddrinfo(result);
        if (error) *error = "socket creation failed";
        WSACleanup();
        wsaStarted_ = false;
        return false;
    }

    BOOL exclusive = TRUE;
    setsockopt(listenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

    if (bind(listenSocket, result->ai_addr, static_cast<int>(result->ai_addrlen)) != 0) {
        const int code = WSAGetLastError();
        closesocket(listenSocket);
        freeaddrinfo(result);
        WSACleanup();
        wsaStarted_ = false;
        if (error) *error = str::Format("bind failed on %s:%u (WSA %d)", host.c_str(), port, code);
        return false;
    }
    freeaddrinfo(result);

    if (listen(listenSocket, SOMAXCONN) != 0) {
        closesocket(listenSocket);
        WSACleanup();
        wsaStarted_ = false;
        if (error) *error = "listen failed";
        return false;
    }

    sockaddr_in bound{};
    int length = sizeof(bound);
    if (getsockname(listenSocket, reinterpret_cast<sockaddr*>(&bound), &length) == 0) {
        port_ = ntohs(bound.sin_port);
    } else {
        port_ = port;
    }

    listenSocket_ = static_cast<uintptr_t>(listenSocket);
    handler_ = std::move(handler);
    maxBodyBytes_ = maxBodyBytes;
    maxConnections_ = std::max(maxConnections, 1);
    idleTimeoutMs_ = std::max(idleTimeoutMs, 1000);
    stopping_ = false;
    running_ = true;

    try {
        acceptThread_ = std::thread(&HttpServer::AcceptLoop, this);
    } catch (const std::exception& e) {
        running_ = false;
        CloseSocket(listenSocket_);
        listenSocket_ = static_cast<uintptr_t>(INVALID_SOCKET);
        WSACleanup();
        wsaStarted_ = false;
        if (error) *error = str::Format("failed to start accept thread: %s", e.what());
        return false;
    }

    FMCP_LOGI("MCP HTTP server listening on %s:%u", host.c_str(), port_);
    return true;
}

void HttpServer::Stop() {
    std::vector<std::thread> connectionThreads;
    std::thread acceptThread;
    uintptr_t listenSocket = static_cast<uintptr_t>(INVALID_SOCKET);
    bool cleanupWsa = false;

    {
        std::lock_guard lock(mutex_);
        if (!running_ && !wsaStarted_) {
            return;
        }
        if (stopping_) {
            return;
        }
        stopping_ = true;
        listenSocket = listenSocket_;
        listenSocket_ = static_cast<uintptr_t>(INVALID_SOCKET);

        for (uintptr_t socket : sockets_) {
            CloseSocket(socket);
        }
        sockets_.clear();

        if (acceptThread_.joinable()) {
            acceptThread = std::move(acceptThread_);
        }
        for (auto& worker : connectionWorkers_) {
            if (worker.thread.joinable()) {
                connectionThreads.push_back(std::move(worker.thread));
            }
        }
        connectionWorkers_.clear();
        cleanupWsa = wsaStarted_;
        wsaStarted_ = false;
    }

    CloseSocket(listenSocket);
    if (acceptThread.joinable()) {
        acceptThread.join();
    }
    for (auto& thread : connectionThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    if (cleanupWsa) {
        WSACleanup();
    }

    std::lock_guard lock(mutex_);
    running_ = false;
    activeConnections_ = 0;
    handler_ = nullptr;
    afterResponse_ = nullptr;
}

void HttpServer::SetAfterResponse(AfterResponse callback) {
    std::lock_guard lock(mutex_);
    afterResponse_ = std::move(callback);
}

bool HttpServer::Running() const {
    std::lock_guard lock(mutex_);
    return running_;
}

uint16_t HttpServer::Port() const {
    std::lock_guard lock(mutex_);
    return port_;
}

void HttpServer::AcceptLoop() {
    while (true) {
        std::vector<std::thread> finished;
        {
            std::lock_guard lock(mutex_);
            if (stopping_) {
                break;
            }
            for (auto it = connectionWorkers_.begin(); it != connectionWorkers_.end();) {
                if (it->done && it->done->load(std::memory_order_acquire)) {
                    if (it->thread.joinable()) {
                        finished.push_back(std::move(it->thread));
                    }
                    it = connectionWorkers_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto& thread : finished) {
            if (thread.joinable()) {
                thread.join();
            }
        }

        const SOCKET client = accept(static_cast<SOCKET>(listenSocket_), nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            std::lock_guard lock(mutex_);
            if (stopping_) {
                break;
            }
            continue;
        }

        DWORD timeout = static_cast<DWORD>(idleTimeoutMs_);
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        BOOL noDelay = TRUE;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));

        std::lock_guard lock(mutex_);
        if (stopping_) {
            CloseSocket(static_cast<uintptr_t>(client));
            break;
        }
        if (activeConnections_ >= maxConnections_) {
            SendErrorResponse(client, 503, "too many connections");
            closesocket(client);
            continue;
        }

        activeConnections_++;
        sockets_.insert(static_cast<uintptr_t>(client));
        auto done = std::make_shared<std::atomic<bool>>(false);
        try {
            ConnectionWorker worker;
            worker.thread = std::thread(&HttpServer::ConnectionLoop, this,
                                        static_cast<uintptr_t>(client), done);
            worker.done = std::move(done);
            connectionWorkers_.push_back(std::move(worker));
        } catch (...) {
            if (done) done->store(true, std::memory_order_release);
            sockets_.erase(static_cast<uintptr_t>(client));
            activeConnections_--;
            CloseSocket(static_cast<uintptr_t>(client));
        }
    }
}

void HttpServer::ConnectionLoop(uintptr_t socketHandle, std::shared_ptr<std::atomic<bool>> done) {
    struct DoneGuard {
        std::shared_ptr<std::atomic<bool>> flag;
        ~DoneGuard() {
            if (flag) flag->store(true, std::memory_order_release);
        }
    } doneGuard{std::move(done)};

    const SOCKET client = static_cast<SOCKET>(socketHandle);
    std::string buffer;
    buffer.reserve(8192);

    auto finish = [&] {
        std::lock_guard lock(mutex_);
        sockets_.erase(socketHandle);
        activeConnections_--;
    };

    auto readMore = [&]() -> bool {
        char chunk[8192];
        const int received = recv(client, chunk, sizeof(chunk), 0);
        if (received <= 0) {
            return false;
        }
        buffer.append(chunk, static_cast<size_t>(received));
        return true;
    };

    auto findHeaderEnd = [&]() -> size_t {
        return buffer.find("\r\n\r\n");
    };

    auto readLine = [&](std::string& line) -> bool {
        while (true) {
            const size_t end = buffer.find("\r\n");
            if (end != std::string::npos) {
                line.assign(buffer.data(), end);
                buffer.erase(0, end + 2);
                return true;
            }
            if (buffer.size() > kMaxHeaderBytes) {
                return false;
            }
            if (!readMore()) {
                return false;
            }
        }
    };

    while (true) {
        {
            std::lock_guard lock(mutex_);
            if (stopping_) {
                break;
            }
        }

        size_t headerEnd = findHeaderEnd();
        while (headerEnd == std::string::npos) {
            if (buffer.size() > kMaxHeaderBytes) {
                SendErrorResponse(client, 400, "header too large");
                finish();
                CloseSocket(socketHandle);
                return;
            }
            if (!readMore()) {
                finish();
                CloseSocket(socketHandle);
                return;
            }
            headerEnd = findHeaderEnd();
        }

        const std::string headerBlock = buffer.substr(0, headerEnd + 4);
        buffer.erase(0, headerEnd + 4);

        HttpRequest request;
        std::unordered_map<std::string, std::string> headers;
        std::string line;
        bool first = true;
        bool parseError = false;
        size_t cursor = 0;

        while (cursor < headerBlock.size()) {
            const size_t lineEnd = headerBlock.find("\r\n", cursor);
            if (lineEnd == std::string::npos) {
                break;
            }
            line.assign(headerBlock.data() + cursor, lineEnd - cursor);
            cursor = lineEnd + 2;

            if (first) {
                first = false;
                std::vector<std::string> parts = str::Split(line, ' ');
                if (parts.size() < 3) {
                    parseError = true;
                    break;
                }
                request.method = parts[0];
                request.target = parts[1];
                request.version = parts[2];
                const size_t query = request.target.find('?');
                request.path = query == std::string::npos ? request.target : request.target.substr(0, query);
                if (request.path.empty() || request.path[0] != '/') {
                    parseError = true;
                    break;
                }
                continue;
            }

            const size_t colon = line.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            std::string name = str::ToLower(str::Trim(line.substr(0, colon)));
            std::string value = str::Trim(line.substr(colon + 1));
            if (name.empty()) {
                continue;
            }
            auto it = headers.find(name);
            if (it != headers.end()) {
                it->second += ", " + value;
            } else {
                headers.emplace(std::move(name), std::move(value));
            }
        }

        if (parseError) {
            SendErrorResponse(client, 400, "malformed request");
            finish();
            CloseSocket(socketHandle);
            return;
        }

        request.headers = headers;
        request.remote = RemoteAddress(socketHandle);

        if (ContainsToken(request.Header("expect"), "100-continue")) {
            static constexpr char kContinue[] = "HTTP/1.1 100 Continue\r\n\r\n";
            SendAll(client, kContinue, sizeof(kContinue) - 1);
        }

        const std::string transferEncoding = request.Header("transfer-encoding");
        const std::string contentLength = request.Header("content-length");
        bool badBody = false;

        if (ContainsToken(transferEncoding, "chunked")) {
            std::string body;
            while (true) {
                if (!readLine(line)) {
                    badBody = true;
                    break;
                }
                const size_t semicolon = line.find(';');
                const std::string sizeText = str::Trim(
                    semicolon == std::string::npos ? line : line.substr(0, semicolon));
                const auto chunkSize = str::ParseUint(sizeText, 64ull * 1024 * 1024);
                if (!chunkSize) {
                    badBody = true;
                    break;
                }
                if (*chunkSize == 0) {
                    while (true) {
                        if (!readLine(line)) {
                            badBody = true;
                            break;
                        }
                        if (line.empty()) {
                            break;
                        }
                    }
                    break;
                }
                if (body.size() + *chunkSize > maxBodyBytes_) {
                    badBody = true;
                    break;
                }

                while (buffer.size() < *chunkSize + 2) {
                    if (!readMore()) {
                        badBody = true;
                        break;
                    }
                }
                if (badBody) {
                    break;
                }
                body.append(buffer.data(), static_cast<size_t>(*chunkSize));
                buffer.erase(0, static_cast<size_t>(*chunkSize) + 2);
            }
            request.body = std::move(body);
        } else if (!contentLength.empty()) {
            const auto length = str::ParseUint(contentLength, static_cast<uint64_t>(maxBodyBytes_));
            if (!length) {
                SendErrorResponse(client, 413, "body too large or invalid content-length");
                finish();
                CloseSocket(socketHandle);
                return;
            }
            while (buffer.size() < *length) {
                if (!readMore()) {
                    badBody = true;
                    break;
                }
            }
            if (!badBody) {
                request.body.assign(buffer.data(), static_cast<size_t>(*length));
                buffer.erase(0, static_cast<size_t>(*length));
            }
        }

        if (badBody) {
            SendErrorResponse(client, 400, "invalid request body");
            finish();
            CloseSocket(socketHandle);
            return;
        }

        HttpResponse response;
        try {
            HttpHandler handler;
            {
                std::lock_guard lock(mutex_);
                handler = handler_;
            }
            if (handler) {
                response = handler(request);
            } else {
                response.status = 503;
                response.body = "{\"error\":\"server stopping\"}";
                response.close = true;
            }
        } catch (const std::exception& e) {
            FMCP_LOGE("HTTP handler exception: %s", e.what());
            response.status = 500;
            response.body = "{\"error\":\"internal error\"}";
            response.close = true;
        } catch (...) {
            response.status = 500;
            response.body = "{\"error\":\"internal error\"}";
            response.close = true;
        }

        bool closeConnection = response.close || ContainsToken(request.Header("connection"), "close") ||
                               (str::IEquals(request.version, "HTTP/1.0") &&
                                !ContainsToken(request.Header("connection"), "keep-alive"));

        const bool headOnly = str::IEquals(request.method, "HEAD");
        const std::string wire = BuildResponse(response, closeConnection, headOnly);
        if (!SendAll(client, wire.data(), wire.size())) {
            finish();
            CloseSocket(socketHandle);
            return;
        }

        AfterResponse after;
        {
            std::lock_guard lock(mutex_);
            after = afterResponse_;
        }
        if (after && after()) {
            closeConnection = true;
        }

        {
            std::lock_guard lock(mutex_);
            if (stopping_) {
                closeConnection = true;
            }
        }

        if (closeConnection) {
            break;
        }
    }

    finish();
    CloseSocket(socketHandle);
}

std::string HttpServer::RemoteAddress(uintptr_t socketHandle) const {
    sockaddr_in address{};
    int length = sizeof(address);
    if (getpeername(static_cast<SOCKET>(socketHandle), reinterpret_cast<sockaddr*>(&address), &length) == 0) {
        char text[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &address.sin_addr, text, sizeof(text));
        return str::Format("%s:%u", text, ntohs(address.sin_port));
    }
    return "unknown";
}

}

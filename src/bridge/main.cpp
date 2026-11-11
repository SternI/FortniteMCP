#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cstdlib>
#include <fcntl.h>
#include <io.h>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace {

struct Options {
    std::string url = "http://127.0.0.1:26064/mcp";
    std::string token;
    int timeoutSeconds = 30;
    int waitSeconds = 10;
    bool verbose = false;
};

std::string Narrow(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        out.data(), size, nullptr, nullptr);
    return out;
}

std::wstring Widen(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                         nullptr, 0);
    if (size <= 0) return {};
    std::wstring out(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), size);
    return out;
}

std::string Trim(std::string value) {
    while (!value.empty() && static_cast<unsigned char>(value.back()) <= ' ') value.pop_back();
    size_t start = 0;
    while (start < value.size() && static_cast<unsigned char>(value[start]) <= ' ') ++start;
    return value.substr(start);
}

std::string ReadFirstLine(const std::string& path) {
    std::ifstream file(path);
    std::string line;
    if (file && std::getline(file, line)) {
        return Trim(line);
    }
    return {};
}

std::string ParentPath(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? std::string{} : path.substr(0, pos);
}

std::string DefaultTokenPath() {
    if (const char* configPath = std::getenv("FORTNITEMCP_CONFIG")) {
        const std::string parent = ParentPath(configPath);
        if (!parent.empty()) {
            return parent + "\\token.txt";
        }
    }

    wchar_t* local = nullptr;
    size_t length = 0;
    std::string base;
    if (_wdupenv_s(&local, &length, L"LOCALAPPDATA") == 0 && local) {
        base = Narrow(local);
    }
    free(local);
    if (base.empty()) base = "C:\\FortniteMCP";
    return base + "\\FortniteMCP\\token.txt";
}

void PrintUsage() {
    std::cerr
        << "FortniteMCPBridge - stdio to HTTP MCP bridge\n"
        << "Usage: FortniteMCPBridge [--url URL] [--token TOKEN] [--timeout SECONDS] "
           "[--wait SECONDS] [--verbose]\n"
        << "Defaults: --url http://127.0.0.1:26064/mcp, token from FORTNITEMCP_TOKEN or token.txt\n";
}

std::optional<Options> ParseOptions(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto need = [&](const char* name) -> std::optional<std::string> {
            if (i + 1 >= argc) {
                std::cerr << "missing value for " << name << "\n";
                return std::nullopt;
            }
            return std::string(argv[++i]);
        };

        if (arg == "--url") {
            auto value = need("--url");
            if (!value) return std::nullopt;
            options.url = *value;
        } else if (arg == "--token") {
            auto value = need("--token");
            if (!value) return std::nullopt;
            options.token = *value;
        } else if (arg == "--timeout") {
            auto value = need("--timeout");
            if (!value) return std::nullopt;
            options.timeoutSeconds = std::max(1, std::atoi(value->c_str()));
        } else if (arg == "--wait") {
            auto value = need("--wait");
            if (!value) return std::nullopt;
            options.waitSeconds = std::max(0, std::atoi(value->c_str()));
        } else if (arg == "--verbose") {
            options.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            std::exit(0);
        } else {
            std::cerr << "unknown argument: " << arg << "\n";
            return std::nullopt;
        }
    }

    if (options.token.empty()) {
        if (const char* env = std::getenv("FORTNITEMCP_TOKEN")) {
            options.token = env;
        }
    }
    if (options.token.empty()) {
        options.token = ReadFirstLine(DefaultTokenPath());
    }
    if (options.token.empty()) {
        options.token = Trim(ReadFirstLine("token.txt"));
    }

    return options;
}

struct UrlParts {
    std::wstring host;
    std::wstring path;
    uint16_t port = 80;
    bool secure = false;
};

std::optional<UrlParts> ParseUrl(const std::string& url) {
    const std::wstring wide = Widen(url);
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    components.dwSchemeLength = static_cast<DWORD>(-1);

    if (!WinHttpCrackUrl(wide.c_str(), 0, 0, &components)) {
        return std::nullopt;
    }

    UrlParts parts;
    parts.host.assign(components.lpszHostName, components.dwHostNameLength);
    parts.path.assign(components.lpszUrlPath, components.dwUrlPathLength);
    if (components.dwExtraInfoLength > 0) {
        parts.path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }
    parts.port = components.nPort;
    parts.secure = components.nScheme == INTERNET_SCHEME_HTTPS;
    if (components.nScheme != INTERNET_SCHEME_HTTP && components.nScheme != INTERNET_SCHEME_HTTPS) {
        return std::nullopt;
    }
    if (parts.path.empty()) {
        parts.path = L"/mcp";
    }
    return parts;
}

class BridgeClient {
public:
    explicit BridgeClient(const Options& options) : options_(options) {}

    bool Open() {
        parts_ = ParseUrl(options_.url);
        if (!parts_) {
            std::cerr << "invalid URL: " << options_.url << "\n";
            return false;
        }

        session_ = WinHttpOpen(L"FortniteMCPBridge/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session_) {
            return false;
        }

        const int timeout = options_.timeoutSeconds * 1000;
        WinHttpSetTimeouts(session_, timeout, timeout, timeout, timeout);

        connection_ = WinHttpConnect(session_, parts_->host.c_str(), parts_->port, 0);
        return connection_ != nullptr;
    }

    void Close() {
        if (session_) {
            WinHttpCloseHandle(session_);
            session_ = nullptr;
            connection_ = nullptr;
        }
    }

    ~BridgeClient() {
        Close();
    }

    std::optional<std::string> Send(const std::string& body, int* statusOut) {
        if (!connection_ && !Open()) {
            return std::nullopt;
        }

        HINTERNET request = WinHttpOpenRequest(connection_, L"POST", parts_->path.c_str(), nullptr,
                                               WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               parts_->secure ? WINHTTP_FLAG_SECURE : 0);
        if (!request) {
            return std::nullopt;
        }

        std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
        if (!options_.token.empty()) {
            headers += L"Authorization: Bearer " + Widen(options_.token) + L"\r\n";
        }

        BOOL ok = WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(-1L),
                                     const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
                                     static_cast<DWORD>(body.size()), 0);
        if (ok) {
            ok = WinHttpReceiveResponse(request, nullptr);
        }

        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                            WINHTTP_NO_HEADER_INDEX);

        std::string response;
        if (ok) {
            DWORD available = 0;
            do {
                available = 0;
                if (!WinHttpQueryDataAvailable(request, &available)) {
                    ok = FALSE;
                    break;
                }
                if (available == 0) {
                    break;
                }
                std::vector<char> buffer(std::min<DWORD>(available, 1 << 20));
                DWORD read = 0;
                if (!WinHttpReadData(request, buffer.data(), static_cast<DWORD>(buffer.size()), &read)) {
                    ok = FALSE;
                    break;
                }
                response.append(buffer.data(), read);
                if (response.size() > 64 * 1024 * 1024) {
                    ok = FALSE;
                    break;
                }
            } while (available > 0);
        }

        WinHttpCloseHandle(request);

        if (statusOut) *statusOut = status;
        if (!ok) {
            if (options_.verbose) {
                std::cerr << "request failed, error " << GetLastError() << "\n";
            }
            Close();
            return std::nullopt;
        }

        return response;
    }

private:
    Options options_;
    std::optional<UrlParts> parts_;
    HINTERNET session_ = nullptr;
    HINTERNET connection_ = nullptr;
};

}

int main(int argc, char** argv) {
    auto options = ParseOptions(argc, argv);
    if (!options) {
        PrintUsage();
        return 2;
    }

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stdin), _O_BINARY);

    BridgeClient client(*options);
    if (!client.Open()) {
        std::cerr << "failed to initialize WinHTTP\n";
        return 2;
    }

    bool connected = false;
    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(options->waitSeconds) * 1000;
    do {
        int status = 0;
        auto response = client.Send(R"({"jsonrpc":"2.0","id":0,"method":"ping"})", &status);
        if (response && status == 200) {
            connected = true;
            break;
        }
        if (deadline <= GetTickCount64()) {
            break;
        }
        Sleep(250);
    } while (true);

    if (!connected && options->verbose) {
        std::cerr << "server not reachable yet; will retry per request\n";
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        line = Trim(line);
        if (line.empty()) {
            continue;
        }

        int status = 0;
        auto response = client.Send(line, &status);
        if (!response) {
            std::cout << R"({"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"FortniteMCP server unreachable"}})"
                      << '\n'
                      << std::flush;
            continue;
        }

        if (status == 401) {
            std::cerr << "unauthorized: set --token or FORTNITEMCP_TOKEN, or read the token file\n";
            std::cout << R"({"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"unauthorized"}})"
                      << '\n'
                      << std::flush;
            continue;
        }

        if (!response->empty()) {
            std::cout << Trim(*response) << '\n' << std::flush;
        }
    }

    client.Close();
    return 0;
}

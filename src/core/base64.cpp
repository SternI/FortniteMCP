#include "core/base64.h"

namespace fmcp::b64 {

namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int DecodeChar(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

}

std::string Encode(const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    std::string out;
    out.reserve(((size + 2) / 3) * 4);

    size_t i = 0;
    for (; i + 2 < size; i += 3) {
        uint32_t value = (static_cast<uint32_t>(bytes[i]) << 16) |
                         (static_cast<uint32_t>(bytes[i + 1]) << 8) |
                         static_cast<uint32_t>(bytes[i + 2]);
        out.push_back(kAlphabet[(value >> 18) & 0x3F]);
        out.push_back(kAlphabet[(value >> 12) & 0x3F]);
        out.push_back(kAlphabet[(value >> 6) & 0x3F]);
        out.push_back(kAlphabet[value & 0x3F]);
    }

    if (i < size) {
        uint32_t value = static_cast<uint32_t>(bytes[i]) << 16;
        if (i + 1 < size) {
            value |= static_cast<uint32_t>(bytes[i + 1]) << 8;
        }
        out.push_back(kAlphabet[(value >> 18) & 0x3F]);
        out.push_back(kAlphabet[(value >> 12) & 0x3F]);
        out.push_back(i + 1 < size ? kAlphabet[(value >> 6) & 0x3F] : '=');
        out.push_back('=');
    }

    return out;
}

std::optional<std::vector<uint8_t>> Decode(std::string_view text) {
    std::vector<uint8_t> out;
    out.reserve((text.size() / 4) * 3);

    uint32_t buffer = 0;
    int bits = 0;
    for (char c : text) {
        if (c == '=') {
            break;
        }
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            continue;
        }

        const int value = DecodeChar(c);
        if (value < 0) {
            return std::nullopt;
        }

        buffer = (buffer << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }

    return out;
}

}

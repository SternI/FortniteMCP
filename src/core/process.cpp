#include "core/process.h"

#include "core/strings.h"

#include <cstring>
#include <limits>

namespace fmcp {

bool CallPlan::AddStack(uint64_t raw) {
    if (stack_.size() >= 32) {
        error_ = "too many stack arguments (max 32)";
        return false;
    }
    stack_.push_back(raw);
    return true;
}

bool CallPlan::AddInt(uint64_t value) {
    if (argIndex_ < 4) {
        ints_[argIndex_] = value;
        intMask_ |= (1u << argIndex_);
    } else if (!AddStack(value)) {
        return false;
    }
    ++argIndex_;
    return true;
}

bool CallPlan::AddPointer(uintptr_t value) {
    return AddInt(static_cast<uint64_t>(value));
}

bool CallPlan::AddFloat(float value) {
    uint32_t bits = 0;
    static_assert(sizeof(bits) == sizeof(value));
    memcpy(&bits, &value, sizeof(bits));

    if (argIndex_ < 4) {
        xmm_[argIndex_] = static_cast<uint64_t>(bits);
        xmmMask_ |= (1u << argIndex_);
    } else if (!AddStack(static_cast<uint64_t>(bits))) {
        return false;
    }
    ++argIndex_;
    return true;
}

bool CallPlan::AddDouble(double value) {
    uint64_t bits = 0;
    static_assert(sizeof(bits) == sizeof(value));
    memcpy(&bits, &value, sizeof(bits));

    if (argIndex_ < 4) {
        xmm_[argIndex_] = bits;
        xmmMask_ |= (1u << argIndex_);
    } else if (!AddStack(bits)) {
        return false;
    }
    ++argIndex_;
    return true;
}

CallResult CallPlan::Invoke(uintptr_t function) const {
    CallResult result;
    if (!function || !error_.empty()) {
        return result;
    }
    result.rax = FmcpInvokeX64(reinterpret_cast<void*>(function), ints_, intMask_, xmm_, xmmMask_,
                               stack_.data(), static_cast<uint32_t>(stack_.size()), &result.xmm0);
    return result;
}

extern "C" uint64_t FmcpSelfTestMix(uint64_t a, double b, uint64_t c, double d,
                                    uint64_t e, uint64_t f, double g) {
    const double sum = static_cast<double>(a + c + e + f) + b + d + g;
    return static_cast<uint64_t>(sum) ^ 0xA5A5A5A5ull;
}

extern "C" uint64_t FmcpSelfTestInts(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                                     uint64_t e, uint64_t f, uint64_t g, uint64_t h) {
    return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6 + g * 7 + h * 8;
}

extern "C" float FmcpSelfTestFloat(float a, float b) {
    return a * 3.0f + b;
}

bool SelfTestCallingConvention(std::string* error) {
    CallPlan ints;
    for (uint64_t i = 1; i <= 8; ++i) {
        if (!ints.AddInt(i)) {
            if (error) *error = ints.Error();
            return false;
        }
    }
    const CallResult r = ints.Invoke(reinterpret_cast<uintptr_t>(&FmcpSelfTestInts));
    if (r.rax != 204ull) {
        if (error) *error = str::Format("integer calling convention mismatch: 0x%llX",
                                        static_cast<unsigned long long>(r.rax));
        return false;
    }

    CallPlan mixed;
    mixed.AddInt(1);
    mixed.AddDouble(2.0);
    mixed.AddInt(3);
    mixed.AddDouble(4.0);
    mixed.AddInt(5);
    mixed.AddInt(6);
    mixed.AddDouble(7.0);
    const CallResult m = mixed.Invoke(reinterpret_cast<uintptr_t>(&FmcpSelfTestMix));
    const uint64_t expected = static_cast<uint64_t>(28.0) ^ 0xA5A5A5A5ull;
    if (m.rax != expected) {
        if (error) *error = str::Format("mixed calling convention mismatch: 0x%llX != 0x%llX",
                                        static_cast<unsigned long long>(m.rax),
                                        static_cast<unsigned long long>(expected));
        return false;
    }

    CallPlan flt;
    flt.AddFloat(4.0f);
    flt.AddFloat(2.0f);
    const CallResult f = flt.Invoke(reinterpret_cast<uintptr_t>(&FmcpSelfTestFloat));
    uint32_t bits = static_cast<uint32_t>(f.xmm0);
    float value = 0.0f;
    memcpy(&value, &bits, sizeof(value));
    if (value != 14.0f) {
        if (error) *error = str::Format("float calling convention mismatch: %f", value);
        return false;
    }

    return true;
}

}

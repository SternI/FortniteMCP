#pragma once

#include <cstdint>
#include <string>
#include <vector>

extern "C" uint64_t FmcpInvokeX64(void* fn, const uint64_t* ints, uint32_t intMask,
                                  const uint64_t* xmm, uint32_t xmmMask,
                                  const uint64_t* stackArgs, uint32_t stackCount,
                                  uint64_t* xmmOut);

namespace fmcp {

struct CallResult {
    uint64_t rax = 0;
    uint64_t xmm0 = 0;
};

// Win64 assigns registers by argument position: RCX/XMM0 for arg 0, RDX/XMM1 for arg 1, etc.
class CallPlan {
public:
    bool AddInt(uint64_t value);
    bool AddPointer(uintptr_t value);
    bool AddFloat(float value);
    bool AddDouble(double value);
    CallResult Invoke(uintptr_t function) const;
    [[nodiscard]] const std::string& Error() const { return error_; }
    [[nodiscard]] size_t ArgumentCount() const { return argIndex_; }

private:
    bool AddStack(uint64_t raw);

    uint64_t ints_[4]{};
    uint32_t intMask_ = 0;
    uint64_t xmm_[4]{};
    uint32_t xmmMask_ = 0;
    std::vector<uint64_t> stack_;
    size_t argIndex_ = 0;
    std::string error_;
};

extern "C" uint64_t FmcpSelfTestMix(uint64_t a, double b, uint64_t c, double d,
                                    uint64_t e, uint64_t f, double g);
extern "C" uint64_t FmcpSelfTestInts(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                                     uint64_t e, uint64_t f, uint64_t g, uint64_t h);
extern "C" float FmcpSelfTestFloat(float a, float b);
bool SelfTestCallingConvention(std::string* error);

}

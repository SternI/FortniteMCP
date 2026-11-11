#include "bootstrap.h"

#include <windows.h>

namespace {

DWORD WINAPI BootstrapThread(LPVOID parameter) {
    fmcp::BootstrapMain(static_cast<HMODULE>(parameter));
    return 0;
}

}

extern "C" __declspec(dllexport) uint32_t FmcpAbiVersion() {
    return 1;
}

extern "C" __declspec(dllexport) bool FmcpSelfTestMarker() {
    return true;
}

extern "C" __declspec(dllexport) unsigned long long FmcpAbiTest(
    unsigned long long a, double b, unsigned long long c, double d,
    unsigned long long e, unsigned long long f, double g) {
    return (a + c + e + f) * 1000ull + static_cast<unsigned long long>(b + d + g);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);

        HANDLE thread = CreateThread(nullptr, 0, BootstrapThread, module, 0, nullptr);
        if (thread) {
            CloseHandle(thread);
        }
    }
    return TRUE;
}

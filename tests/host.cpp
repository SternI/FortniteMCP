#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <cstdlib>
#include <string>

namespace {

alignas(16) unsigned char g_fakeEngine[0xC00]{};
alignas(16) unsigned char g_fakeViewport[0x100]{};

}  // namespace

extern "C" __declspec(dllexport) unsigned char g_fmcpFakeWorld[0x28]{};
extern "C" __declspec(dllexport) void* g_fmcpFakeEngineSlot = nullptr;

extern "C" __declspec(dllexport) void FmcpFakeNameToString(const void* fname, void* out) {
    struct FStringLayout {
        wchar_t* data;
        int32_t num;
        int32_t max;
    };

    const uint32_t index = fname ? *static_cast<const uint32_t*>(fname) : 0;
    wchar_t text[64]{};
    swprintf_s(text, std::size(text), L"FakeName_%u", index);

    auto* string = static_cast<FStringLayout*>(out);
    if (!string || !string->data || string->max <= 0) {
        return;
    }

    size_t length = wcslen(text);
    if (length + 1 > static_cast<size_t>(string->max)) {
        length = static_cast<size_t>(string->max) - 1;
    }
    wmemcpy(string->data, text, length);
    string->data[length] = L'\0';
    string->num = static_cast<int32_t>(length + 1);
}

static void SetupFakeGlobals() {
    *reinterpret_cast<void**>(g_fakeEngine + 0xB70) = g_fakeViewport;
    *reinterpret_cast<void**>(g_fakeViewport + 0x78) = g_fmcpFakeWorld;
    g_fmcpFakeEngineSlot = g_fakeEngine;

    const uintptr_t world = reinterpret_cast<uintptr_t>(g_fmcpFakeWorld);
    *reinterpret_cast<uintptr_t*>(g_fmcpFakeWorld + 0x00) = world;
    *reinterpret_cast<uintptr_t*>(g_fmcpFakeWorld + 0x10) = world;
    *reinterpret_cast<uint32_t*>(g_fmcpFakeWorld + 0x18) = 7;
    *reinterpret_cast<uintptr_t*>(g_fmcpFakeWorld + 0x20) = 0;
}

int main(int argc, char** argv) {
    int seconds = 120;
    bool loadDll = true;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--seconds" && i + 1 < argc) {
            seconds = std::max(1, std::atoi(argv[++i]));
        } else if (std::string(argv[i]) == "--no-load") {
            loadDll = false;
        }
    }

    SetupFakeGlobals();

    HMODULE dll = nullptr;
    if (loadDll) {
        dll = LoadLibraryW(L"FortniteMCP.dll");
        if (!dll) {
            std::printf("LOAD_FAILED=%lu\n", GetLastError());
            return 1;
        }
    }

    std::printf("HOST_PID=%lu\n", GetCurrentProcessId());
    std::printf("DLL_BASE=0x%llX\n", reinterpret_cast<unsigned long long>(dll));
    std::fflush(stdout);

    const ULONGLONG end = GetTickCount64() + static_cast<ULONGLONG>(seconds) * 1000;
    while (GetTickCount64() < end) {
        Sleep(200);
    }

    HMODULE still = GetModuleHandleW(L"FortniteMCP.dll");
    std::printf("MODULE_LOADED=%d\n", still ? 1 : 0);
    std::fflush(stdout);
    return 0;
}

#pragma once

#include <cstdint>
#include <windows.h>

namespace fmcp {

void BootstrapMain(HMODULE module);
void RequestStop(bool unloadSelf, bool restorePatches);
uint64_t UptimeMs();
bool IsManuallyMapped();

}

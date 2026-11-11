#pragma once

namespace fmcp::lifecycle {

void RequestShutdown(bool unloadSelf, bool restorePatches);
bool Pending();
bool Consume(bool& unloadSelf, bool& restorePatches);

}

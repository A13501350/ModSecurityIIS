#pragma once

#include <string>
#include <memory>
#include <windows.h>   // WORD (used by WriteEventViewerLog)

// libModSecurity v3 public headers (submodule: libmodsecurity/headers/).
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"

namespace iis {

// Returns the global, initialized libModSecurity engine.
modsecurity::ModSecurity& engine();

// Loads (and caches) a RulesSet by config file path. Returns nullptr on
// unrecoverable parse error. Cache is invalidated when the file's mtime
// changes; on reload failure the previous good config is kept.
std::shared_ptr<modsecurity::RulesSet> getRules(const std::string& configFile,
                                                std::string* err);

// Write a message to the Windows Event Viewer (source "ModSecurity").
void WriteEventViewerLog(const char* message, WORD category);

}  // namespace iis

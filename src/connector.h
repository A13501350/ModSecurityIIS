#pragma once

#include <string>
#include <memory>
#include <windows.h>   // WORD (used by WriteEventViewerLog)

// libModSecurity v3 public headers (submodule: libmodsecurity/headers/).
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"     // RulesSet (loadFromUri / getParserError)
#include "modsecurity/transaction.h"   // Transaction
#include "modsecurity/intervention.h"  // ModSecurityIntervention + helpers

namespace iis {

// Returns the global, initialized libModSecurity engine. The engine is created
// once (thread-safe) with the connector string set and the server-log callback
// installed; every Transaction references it.
modsecurity::ModSecurity& engine();

// Loads (and caches, keyed by config file path) a RulesSet. Returns nullptr on
// a parse error that cannot be recovered from (file missing/unreadable) and
// fills *err with the parser message. The cache is invalidated when the rules
// file's last-write time changes, so editing rules takes effect without
// recycling the application pool; on a reload parse failure the previous
// good config is kept so requests stay protected. The returned object is
// read-only after load and is safe to share across transactions/threads, so
// caching is both correct and desirable. The caller should hold the returned
// shared_ptr for as long as the Transaction using the rules is alive.
std::shared_ptr<modsecurity::RulesSet> getRules(const std::string& configFile,
                                                std::string* err);

// Write a message to the Windows Event Viewer (source "ModSecurity").
void WriteEventViewerLog(const char* message, WORD category);

}  // namespace iis

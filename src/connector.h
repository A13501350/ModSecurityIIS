#pragma once

#include <string>
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
// parse error and fills *err with the parser message. The returned object is
// read-only after load and is safe to share across transactions/threads, so
// caching is both correct and desirable.
modsecurity::RulesSet* getRules(const std::string& configFile, std::string* err);

// Write a message to the Windows Event Viewer (source "ModSecurity").
void WriteEventViewerLog(const char* message, WORD category);

}  // namespace iis

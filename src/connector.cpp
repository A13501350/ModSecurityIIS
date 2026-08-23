// libModSecurity v3 connector glue for the IIS module.
//
// This file holds the only ModSecurity-version-specific state in the project:
//   * iis::engine()     -- global modsecurity::ModSecurity singleton
//   * iis::getRules()    -- per-configFile modsecurity::RulesSet cache
//   * ServerLogCallback  -- routes engine logs to the Windows Event Viewer
//   * iis::WriteEventViewerLog -- Event Viewer sink (used by the callback)
//
// All ModSecurity symbols used here are written against the verified v3 API in
// libmodsecurity/headers (modsecurity.h / rules_set.h / transaction.h /
// intervention.h). No "VERIFY" placeholders remain -- the signatures below were
// confirmed against those headers.

#define NOMINMAX
#include <windows.h>

#include "connector.h"

#include <mutex>
#include <unordered_map>

// The Event Viewer handle is owned by the (singleton) CMyHttpModule instance
// and declared here so the server-log callback can reach it.
extern HANDLE g_hEventLog;

namespace iis {

static modsecurity::ModSecurity*        g_engine      = nullptr;
static std::mutex                        g_engineMutex;

static std::unordered_map<std::string, modsecurity::RulesSet*> g_rulesCache;
static std::mutex                        g_rulesMutex;


// Server-log callback. Matches ModSecLogCb = void(*)(void*, const void*).
//   data    -> the per-transaction callback data we pass to the Transaction
//              constructor (the CMyHttpModule*). Unused here; we log via the
//              shared Event Viewer handle.
//   message -> for the default TextLogProperty this is a const char* holding
//              the formatted ModSecurity log line.
static void ServerLogCallback(void* data, const void* message)
{
    UNREFERENCED_PARAMETER(data);

    if (message == nullptr)
    {
        return;
    }
    iis::WriteEventViewerLog(static_cast<const char*>(message),
                             EVENTLOG_INFORMATION_TYPE);
}


modsecurity::ModSecurity& engine()
{
    std::lock_guard<std::mutex> lock(g_engineMutex);
    if (g_engine == nullptr)
    {
        g_engine = new modsecurity::ModSecurity();
        // v3 API: setConnectorInformation(const std::string&), NOT setConnector.
        g_engine->setConnectorInformation("ModSecurity IIS (libModSecurity v3)");
        // v3 API: logging is configured via a callback, there is no virtual
        // log() to override. Default property => message is a const char*.
        g_engine->setServerLogCb(ServerLogCallback);
    }
    return *g_engine;
}


modsecurity::RulesSet* getRules(const std::string& configFile, std::string* err)
{
    {
        std::lock_guard<std::mutex> lock(g_rulesMutex);
        auto it = g_rulesCache.find(configFile);
        if (it != g_rulesCache.end())
        {
            return it->second;
        }
    }

    // v3 API: the rules container is modsecurity::RulesSet (loadFromUri /
    // getParserError live here). The public `Rules` subclass simply inherits
    // from RulesSet, so using RulesSet directly is equivalent and unambiguous.
    auto* rules = new modsecurity::RulesSet();

    // loadFromUri returns an int: < 0 means a parse error.
    int rc = rules->loadFromUri(configFile.c_str());
    if (rc < 0)
    {
        if (err != nullptr)
        {
            *err = rules->getParserError();
        }
        delete rules;
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(g_rulesMutex);
    auto it = g_rulesCache.find(configFile);
    if (it != g_rulesCache.end())
    {
        // Another thread won the race and cached it first.
        delete rules;
        return it->second;
    }
    g_rulesCache[configFile] = rules;
    return rules;
}


void WriteEventViewerLog(const char* message, WORD category)
{
    if (g_hEventLog != NULL && message != NULL)
    {
        ReportEventA(g_hEventLog, category, 0, 0x1, NULL, 1, 0, &message, NULL);
    }
}

}  // namespace iis

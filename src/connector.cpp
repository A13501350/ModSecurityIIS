// libModSecurity v3 connector glue for the IIS module.
//
// Holds: iis::engine(), iis::getRules(), ServerLogCallback, WriteEventViewerLog.

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

struct CachedRules
{
    std::shared_ptr<modsecurity::RulesSet> rules;
    FILETIME                                mtime;
};
static std::unordered_map<std::string, CachedRules> g_rulesCache;
static std::mutex                        g_rulesMutex;

// Throttle engine per-request server-log lines to avoid flooding the Event
// Viewer under attack traffic.
static std::mutex  g_logThrottleMutex;
static ULONGLONG   g_logWindowStart = 0;
static ULONG       g_logCount       = 0;
static const ULONG kMaxLogsPerSecond = 100;


// Returns the last-write time of configFile, or false if it cannot be stat'd.
static bool GetRulesFileTime(const std::string& configFile, FILETIME* out)
{
    int wlen = MultiByteToWideChar(CP_UTF8, 0, configFile.c_str(), -1, NULL, 0);
    if (wlen == 0)
    {
        return false;
    }
    std::wstring wpath(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, configFile.c_str(), -1,
                        &wpath[0], wlen);
    WIN32_FILE_ATTRIBUTE_DATA fad = { 0 };
    if (!GetFileAttributesExW(wpath.c_str(), GetFileExInfoStandard, &fad))
    {
        return false;
    }
    *out = fad.ftLastWriteTime;
    return true;
}


// Server-log callback. Matches ModSecLogCb = void(*)(void*, const void*).
static void ServerLogCallback(void* data, const void* message)
{
    UNREFERENCED_PARAMETER(data);

    if (message == nullptr)
    {
        return;
    }

    // Rate-limit to avoid flooding the Event Viewer under attack traffic.
    {
        std::lock_guard<std::mutex> lk(g_logThrottleMutex);
        ULONGLONG now = GetTickCount64();
        if (now - g_logWindowStart >= 1000)
        {
            g_logWindowStart = now;
            g_logCount = 0;
        }
        if (g_logCount >= kMaxLogsPerSecond)
        {
            return;
        }
        g_logCount++;
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
        // v3 API: setConnectorInformation (not setConnector).
        g_engine->setConnectorInformation("ModSecurity IIS (libModSecurity v3)");
        g_engine->setServerLogCb(ServerLogCallback);
    }
    return *g_engine;
}


std::shared_ptr<modsecurity::RulesSet> getRules(const std::string& configFile, std::string* err)
{
    FILETIME curMtime = { 0 };
    bool haveMtime = GetRulesFileTime(configFile, &curMtime);

    // Fast path: already cached and the file has not changed since.
    {
        std::lock_guard<std::mutex> lock(g_rulesMutex);
        auto it = g_rulesCache.find(configFile);
        if (it != g_rulesCache.end() &&
            (!haveMtime ||
             (it->second.mtime.dwLowDateTime == curMtime.dwLowDateTime &&
              it->second.mtime.dwHighDateTime == curMtime.dwHighDateTime)))
        {
            return it->second.rules;
        }
    }

    // v3 API: RulesSet (loadFromUri / getParserError live here).
    auto rules = std::make_shared<modsecurity::RulesSet>();

    // loadFromUri returns an int: < 0 means a parse error.
    int rc = rules->loadFromUri(configFile.c_str());
    if (rc < 0)
    {
        if (err != nullptr)
        {
            *err = rules->getParserError();
        }
        // Keep last-known-good config so requests stay protected.
        std::lock_guard<std::mutex> lock(g_rulesMutex);
        auto it = g_rulesCache.find(configFile);
        if (it != g_rulesCache.end())
        {
            WriteEventViewerLog(
                ("ModSecurityIIS: rules reload failed, keeping previous "
                 "config: " + (err != nullptr ? *err : std::string())).c_str(),
                EVENTLOG_ERROR_TYPE);
            return it->second.rules;
        }
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(g_rulesMutex);
    auto it = g_rulesCache.find(configFile);
    if (it != g_rulesCache.end())
    {
        // Another thread won the race; discard our copy.
        return it->second.rules;
    }
    CachedRules entry;
    entry.rules = rules;
    entry.mtime = curMtime;
    g_rulesCache[configFile] = entry;
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

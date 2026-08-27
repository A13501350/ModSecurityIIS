// ModSecurityIIS -- native IIS 7+ module built on libModSecurity v3.
//
// This file is the IIS-side connector. It is essentially version-agnostic
// except for the engine calls, which go through the v3 API
// (modsecurity::Transaction). The flow mirrors the v2 iis/ connector:
//
//   RegisterModule  -> registers the module factory + request notifications
//   OnBeginRequest  -> create a Transaction, feed request line/headers/body
//   OnSendResponse  -> feed response headers/body
//   OnPostEndRequest-> processLogging + release the Transaction
//
// All ModSecurity call sites use the verified v3 API (confirmed against
// libmodsecurity/headers: modsecurity.h, rules_set.h, transaction.h,
// intervention.h).

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <Windows.h>
#include <sal.h>
#include <strsafe.h>
#include <string>
#include <vector>
#include <memory>    // std::shared_ptr
#include <new>       // std::nothrow
#include <exception> // std::exception

#include "httpserv.h"

#include "ModSecurityIIS.h"
#include "mymodulefactory.h"
#include "moduleconfig.h"
#include "connector.h"

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
IHttpServer *   g_pHttpServer = NULL;
PVOID           g_pModuleContext = NULL;

// Event Viewer handle, owned by the (singleton) CMyHttpModule instance and
// shared with connector.cpp's server-log callback via this global.
HANDLE          g_hEventLog = NULL;


// ---------------------------------------------------------------------------
// Small helpers (WCHAR <-> UTF8, sockaddr -> ip/port)
// ---------------------------------------------------------------------------

static std::string WToUtf8(const WCHAR* w, int byteLen)
{
    if (w == nullptr || byteLen <= 0)
    {
        return "";
    }
    int wlen = byteLen / (int)sizeof(WCHAR);
    int cb = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
    if (cb == 0)
    {
        return "";
    }
    std::string out(cb, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, wlen, &out[0], cb, NULL, NULL);
    return out;
}

// IIS raw header values (HTTP_KNOWN_HEADER.pRawValue / HTTP_UNKNOWN_HEADER.*)
// are ANSI (PCSTR) byte strings on the wire, already UTF-8/ASCII. ModSecurity
// expects UTF-8, so copy the bytes (RawValueLength may include a trailing NUL).
static std::string AToUtf8(const char* a, int byteLen)
{
    if (a == nullptr || byteLen <= 0)
    {
        return "";
    }
    int len = byteLen;
    if (a[len - 1] == '\0')
    {
        len--;
    }
    if (len <= 0)
    {
        return "";
    }
    return std::string(a, len);
}

static std::string SockAddrToIp(PSOCKADDR pAddr)
{
    if (pAddr == nullptr)
    {
        return "";
    }
    char buf[NI_MAXHOST] = { 0 };
    int salen = (pAddr->sa_family == AF_INET)
                    ? (int)sizeof(SOCKADDR_IN)
                    : (int)sizeof(SOCKADDR_IN6);
    if (GetNameInfoA(pAddr, salen, buf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0)
    {
        return std::string(buf);
    }
    return "";
}

static int SockAddrToPort(PSOCKADDR pAddr)
{
    if (pAddr == nullptr)
    {
        return 0;
    }
    if (pAddr->sa_family == AF_INET)
    {
        return ntohs(((SOCKADDR_IN*)pAddr)->sin_port);
    }
    if (pAddr->sa_family == AF_INET6)
    {
        return ntohs(((SOCKADDR_IN6*)pAddr)->sin6_port);
    }
    return 0;
}

// Upper bound (bytes) of request/response body we allow the engine to buffer
// for inspection. Without this the full body is copied into the transaction's
// memory (bounded only by IIS maxAllowedContentLength), so a large upload can
// exhaust worker-process memory. SecRequestBodyLimit is only checked AFTER the
// whole body has been appended, hence the explicit cap here. Override with the
// MODSEC_IIS_MAX_INSPECT_BODY_BYTES environment variable (decimal bytes).
static size_t GetMaxInspectBodyBytes()
{
    static size_t cached = 0;
    static LONG   init   = 0;
    if (InterlockedCompareExchange(&init, 1, 0) == 0)
    {
        cached = 128 * 1024 * 1024;
        char buf[32] = { 0 };
        DWORD n = GetEnvironmentVariableA("MODSEC_IIS_MAX_INSPECT_BODY_BYTES",
                                          buf, (DWORD)sizeof(buf));
        if (n > 0 && n < (DWORD)sizeof(buf))
        {
            unsigned long long v = _strtoui64(buf, NULL, 10);
            if (v > 0) cached = (size_t)v;
        }
        InterlockedExchange(&init, 2);
    }
    while (init != 2) Sleep(0);
    return cached;
}

// When the module is registered but a request's configuration cannot be read,
// a WAF must not silently serve the request unprotected (that is a rule bypass).
// By default we therefore fail-closed (reject). Set the environment variable
// MODSEC_IIS_FAIL_CLOSED=0 to revert to the old fail-open behavior for
// deployments where the module is globally registered but intentionally
// unconfigured on some sites.
static bool ConfigFailClosed()
{
    static LONG   init = 0;
    static LONG   value = 1;   // default: fail closed
    if (InterlockedCompareExchange(&init, 1, 0) == 0)
    {
        char buf[8] = { 0 };
        DWORD n = GetEnvironmentVariableA("MODSEC_IIS_FAIL_CLOSED", buf, (DWORD)sizeof(buf));
        if (n > 0 && n < (DWORD)sizeof(buf) && (buf[0] == '0'))
        {
            value = 0;
        }
        InterlockedExchange(&init, 2);
    }
    while (init != 2) Sleep(0);
    return value != 0;
}

static std::string VerbToString(HTTP_REQUEST* req)
{
    switch (req->Verb)
    {
    case HttpVerbOPTIONS: return "OPTIONS";
    case HttpVerbGET:     return "GET";
    case HttpVerbHEAD:    return "HEAD";
    case HttpVerbPOST:    return "POST";
    case HttpVerbPUT:     return "PUT";
    case HttpVerbDELETE:  return "DELETE";
    case HttpVerbTRACE:   return "TRACE";
    case HttpVerbTRACK:   return "TRACK";
    case HttpVerbCONNECT: return "CONNECT";
    case HttpVerbMOVE:    return "MOVE";
    case HttpVerbCOPY:    return "COPY";
    case HttpVerbPROPFIND:   return "PROPFIND";
    case HttpVerbPROPPATCH: return "PROPPATCH";
    case HttpVerbMKCOL:   return "MKCOL";
    case HttpVerbLOCK:    return "LOCK";
    case HttpVerbUNLOCK:  return "UNLOCK";
    case HttpVerbSEARCH:  return "SEARCH";
    default:
        // http.sys maps every non-enumerated method (PATCH, custom verbs,
        // WebDAV extensions, ...) to HttpVerbUnknown and keeps the original
        // bytes in pUnknownVerb. Report the real method so rules matching
        // REQUEST_METHOD (e.g. @streq PATCH) keep working; fall back to
        // "INVALID" only when the raw bytes are unavailable.
        //
        // NOTE: UnknownVerbLength is the verb length in BYTES, NOT including
        // any NUL terminator (see http.h). pUnknownVerb is therefore not
        // guaranteed to be NUL-terminated, so we pass exactly that length and
        // never read one byte past it. The previous "+1" caused an out-of-bounds
        // read and, when that trailing byte was the space after the verb on the
        // request line, silently turned e.g. "PATCH" into "PATCH ", breaking
        // rules such as @streq PATCH.
        if (req->Verb == HttpVerbUnknown && req->pUnknownVerb != NULL)
        {
            std::string verb = AToUtf8(req->pUnknownVerb,
                                       (int)req->UnknownVerbLength);
            if (!verb.empty())
            {
                return verb;
            }
        }
        return "INVALID";
    }
}

// NOTE: the engine composes REQUEST_LINE / REQUEST_PROTOCOL itself by
// prepending "HTTP/" to whatever we pass (transaction.cc: " HTTP/" +
// http_version), so this returns the BARE version ("1.1", "2"). The
// response side is the opposite: Transaction::processResponseHeaders
// stores the protocol string verbatim into RESPONSE_PROTOCOL, so callers
// there must pass the full "HTTP/x.y".
static std::string VersionToString(HTTP_VERSION version)
{
    if (HTTP_EQUAL_VERSION(version, 0, 9))  return "0.9";
    if (HTTP_EQUAL_VERSION(version, 1, 0))  return "1.0";
    if (HTTP_EQUAL_VERSION(version, 1, 1))  return "1.1";
    if (HTTP_EQUAL_VERSION(version, 2, 0))  return "2.0";
    if (HTTP_EQUAL_VERSION(version, 3, 0))  return "3.0";
    // Unknown future version: report the major number instead of silently
    // claiming 1.1.
    return std::to_string(version.MajorVersion);
}


// ---------------------------------------------------------------------------
// Exception containment. libModSecurity and STL allocations can throw
// (std::bad_alloc, regex errors from rules, ...). An exception escaping a
// CHttpModule callback crosses the IIS module ABI boundary and tears down the
// w3wp process, so every notification handler runs inside try/catch.
// ---------------------------------------------------------------------------

static void ReportException(const char* where, const char* what) noexcept
{
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "ModSecurityIIS: unexpected exception in %s: %s",
                where != NULL ? where : "?",
                what != NULL ? what : "unknown error");
    iis::WriteEventViewerLog(buf, EVENTLOG_ERROR_TYPE);
}


// Inspect a FromFileHandle response chunk. IIS hands out file handles that
// may be shared with other consumers and are not guaranteed to be opened for
// overlapped access, so pass a duplicated handle with its own file position:
// DuplicateHandle + SetFilePointerEx on the copy, then stream the requested
// byte range through the engine in bounded buffers (a whole-file allocation
// would spike memory on large downloads).
static void AppendResponseFileChunk(modsecurity::Transaction* tx,
                                    HANDLE hFile,
                                    ULONGLONG start,
                                    ULONGLONG length)
{
    HANDLE hDup = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), hFile,
                         GetCurrentProcess(), &hDup,
                         0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        return;
    }

    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(start);
    if (SetFilePointerEx(hDup, li, NULL, FILE_BEGIN))
    {
        if (length == (ULONGLONG)HTTP_BYTE_RANGE_TO_EOF)
        {
            LARGE_INTEGER fs;
            length = GetFileSizeEx(hDup, &fs)
                         ? (ULONGLONG)(fs.QuadPart - li.QuadPart)
                         : 0;
        }
        char buf[65536];
        while (length > 0)
        {
            DWORD want = (length > (ULONGLONG)sizeof(buf))
                             ? (DWORD)sizeof(buf)
                             : (DWORD)length;
            DWORD got  = 0;
            // Synchronous ReadFile on our private handle; partial reads are
            // continued until the range is covered or EOF/error occurs.
            if (!ReadFile(hDup, buf, want, &got, NULL) || got == 0)
            {
                break;
            }
            tx->appendResponseBody((const unsigned char*)buf, (size_t)got);
            length -= got;
        }
    }
    CloseHandle(hDup);
}


// ---------------------------------------------------------------------------
// Intervention helper: if the transaction wants to disrupt, apply it to the
// IIS response and finalize the request. Returns true if the request should
// be finished.
// ---------------------------------------------------------------------------

// Reason phrases for the statuses a WAF typically emits (RFC 9110/6585).
// Anything else falls back to a generic phrase instead of the previous
// one-size-fits-all "ModSecurity Action".
static PCSTR StandardReason(int status)
{
    switch (status)
    {
    case 200: return "OK";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 408: return "Request Timeout";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "Rejected by ModSecurity";
    }
}

static bool ApplyIntervention(REQUEST_STORED_CONTEXT* rsc, IHttpContext* pHttpContext)
{
    modsecurity::Transaction* tx = rsc->m_pTx;
    if (tx == nullptr)
    {
        return false;
    }

    // v3 API: intervention is reported via the intervention(ModSecurityIntervention*)
    // method, which returns true while a pending intervention exists and fills
    // the struct. It is a consuming read -- once consumed, further calls during
    // the same transaction return false -- which is exactly what we want since
    // we check once after each phase.
    modsecurity::ModSecurityIntervention it;
    // clean() nulls url/log then resets status/pause/disruptive, so that
    // intervention::free() afterwards never frees uninitialized pointers.
    modsecurity::intervention::clean(&it);

    if (!tx->intervention(&it))
    {
        return false;
    }

    bool disruptive = (it.disruptive != 0);
    int  status     = it.status;

    // Copy the redirect URL out of the intervention BEFORE freeing it:
    // intervention::free() (intervention.h:59-62) calls free() on it.url, so
    // keeping a raw pointer into the struct would be a use-after-free.
    std::string redirectUrl = (it.url != nullptr) ? std::string(it.url) : std::string();
    modsecurity::intervention::free(&it);   // release url/log owned by libmodsecurity

    if (!disruptive)
    {
        return false;
    }

    // A disruptive action was requested. Prefer a redirect when the rule
    // supplied one; otherwise honor the explicit status (defaulting to 403).
    IHttpResponse* pResponse = pHttpContext->GetResponse();
    pResponse->Clear();
    if (!redirectUrl.empty())
    {
        // IHttpResponse::Redirect always answers 302; keep the engine's
        // redirect flavor (301/303/307/308) by overriding the status line
        // afterwards -- the Location header set by Redirect() is kept.
        pResponse->Redirect(redirectUrl.c_str(), TRUE);
        if (status >= 301 && status <= 308 && status != 302)
        {
            pResponse->SetStatus((USHORT)status, StandardReason(status));
        }
    }
    else
    {
        if (status <= 0)
        {
            status = 403;
        }
        pResponse->SetStatus((USHORT)status, StandardReason(status));
    }
    pHttpContext->SetRequestHandled();
    rsc->FinishRequest();
    return true;
}


// ---------------------------------------------------------------------------
// CMyHttpModule
// ---------------------------------------------------------------------------

CMyHttpModule::CMyHttpModule()
{
    m_hEventLog = RegisterEventSourceA(NULL, "ModSecurity");
    g_hEventLog  = m_hEventLog;

    // Create the global engine singleton once.
    iis::engine();
}

CMyHttpModule::~CMyHttpModule()
{
    if (m_hEventLog != NULL)
    {
        DeregisterEventSource(m_hEventLog);
        m_hEventLog = NULL;
        g_hEventLog = NULL;
    }
}

// Intentionally empty: the base-class default Dispose() does "delete this",
// but this module is a singleton owned by CMyHttpModuleFactory (freed in
// Terminate). Letting IIS delete it here would free it while requests may
// still hold references.
void CMyHttpModule::Dispose()
{
}

BOOL CMyHttpModule::WriteEventViewerLog(LPCSTR szNotification, WORD category)
{
    if (m_hEventLog != NULL && szNotification != NULL)
    {
        return ReportEventA(m_hEventLog, category, 0, 0x1, NULL, 1, 0, &szNotification, NULL);
    }
    return FALSE;
}


// ---------------------------------------------------------------------------
// OnBeginRequest
// ---------------------------------------------------------------------------

REQUEST_NOTIFICATION_STATUS
CMyHttpModule::OnBeginRequest(
    IN IHttpContext * pHttpContext,
    IN IHttpEventProvider * pProvider
)
{
    HRESULT                       hr        = S_OK;
    IHttpRequest*                 pRequest  = NULL;
    MODSECURITY_STORED_CONTEXT*   pConfig   = NULL;

    UNREFERENCED_PARAMETER(pProvider);

    try
    {

    do
    {
    if (pHttpContext == NULL)
    {
        hr = E_UNEXPECTED;
        break;
    }

    pRequest = pHttpContext->GetRequest();
    if (pRequest == NULL)
    {
        hr = E_UNEXPECTED;
        break;
    }

    hr = MODSECURITY_STORED_CONTEXT::GetConfig(pHttpContext, &pConfig);
    if (FAILED(hr))
    {
        // The configuration could not be read. A WAF must fail-closed: serving
        // the request unprotected (the previous behavior) silently bypasses all
        // rules. Reject the request and surface the failure in the Event Viewer.
        // Set MODSEC_IIS_FAIL_CLOSED=0 to opt back into fail-open.
        WriteEventViewerLog(
            "ModSecurityIIS: failed to read module configuration; "
            "failing closed (request rejected).",
            EVENTLOG_ERROR_TYPE);
        if (!ConfigFailClosed())
        {
            hr = S_OK;          // operator opted out -> pass through
            break;
        }
        IHttpResponse* pResponse = pHttpContext->GetResponse();
        if (pResponse != NULL)
        {
            pResponse->SetStatus(500, "Internal Server Error");
        }
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }

    if (pConfig->GetIsEnabled() == false)
    {
        break;
    }

    WCHAR* wpath = pConfig->GetPath();
    if (wpath == NULL || wpath[0] == L'\0')
    {
        break;
    }

    std::string configFile = WToUtf8(wpath, (int)wcslen(wpath) * (int)sizeof(WCHAR));
    std::string rulesErr;
    std::shared_ptr<modsecurity::RulesSet> rules = iis::getRules(configFile, &rulesErr);
    if (rules == nullptr)
    {
        WriteEventViewerLog(rulesErr.c_str(), EVENTLOG_ERROR_TYPE);
        break;
    }

    // v3 API: Transaction(ModSecurity*, RulesSet*, void*) where the 3rd arg is
    // the per-transaction log-callback data (passed back to ServerLogCallback).
    // nothrow keeps the null check meaningful; internal engine allocations are
    // covered by the try/catch around this handler. We keep a shared_ptr to the
    // RulesSet on the request context so the cached rules object outlives this
    // transaction even if connector.cpp reloads the cache mid-flight.
    modsecurity::Transaction* tx =
        new (std::nothrow) modsecurity::Transaction(&iis::engine(), rules.get(), this);
    if (tx == nullptr)
    {
        hr = E_OUTOFMEMORY;
        break;
    }

    REQUEST_STORED_CONTEXT* rsc = new (std::nothrow) REQUEST_STORED_CONTEXT();
    if (rsc == nullptr)
    {
        delete tx;
        hr = E_OUTOFMEMORY;
        break;
    }
    rsc->m_pTx          = tx;
    rsc->m_pRules       = rules;
    rsc->m_pHttpContext = pHttpContext;
    IHttpModuleContextContainer* pCtxContainer =
        pHttpContext->GetModuleContextContainer();
    HRESULT shr = pCtxContainer->SetModuleContext(rsc, g_pModuleContext);
    if (FAILED(shr))
    {
        // Release our orphaned context (and its transaction).
        rsc->CleanupStoredContext();
        rsc = NULL;
        if (shr == HRESULT_FROM_WIN32(ERROR_ALREADY_ASSIGNED))
        {
            // A context already exists for this request. Notifications for
            // one request are normally serialized, so treat this as "the
            // request is already being handled" and pass through.
            break;
        }
        hr = E_UNEXPECTED;
        break;
    }

    HTTP_REQUEST* req = pRequest->GetRawHttpRequest();

    // --- connection ---
    PSOCKADDR pRemote = pRequest->GetRemoteAddress();
    std::string clientIp   = SockAddrToIp(pRemote);
    int         clientPort = SockAddrToPort(pRemote);
    std::string serverIp; int serverPort = 0;
    // IHttpRequest::GetLocalAddress() is part of the IIS 7+ httpserv.h contract.
    PSOCKADDR pLocal = pRequest->GetLocalAddress();
    if (pLocal != nullptr)
    {
        serverIp   = SockAddrToIp(pLocal);
        serverPort = SockAddrToPort(pLocal);
    }
    tx->processConnection(clientIp.c_str(), clientPort, serverIp.c_str(), serverPort);

    // --- URI / method / version ---
    // Prefer the raw (unprocessed) URL: IIS has not decoded/normalized it, so
    // ModSecurity applies its own decoding/normalization -- essential for
    // encoded-evasion and path-traversal detection, and consistent with the
    // Apache connector's REQUEST_URI semantics. pRawUrl is ANSI and already
    // includes the query string ("/path?query"). Fall back to the cooked URL
    // only if the raw pointer is absent (malformed request line).
    std::string uri;
    if (req->pRawUrl != nullptr)
    {
        uri = AToUtf8(req->pRawUrl, req->RawUrlLength);
    }
    else
    {
        std::string path = WToUtf8(req->CookedUrl.pAbsPath, req->CookedUrl.AbsPathLength);
        uri = path;
        if (req->CookedUrl.QueryStringLength > 0)
        {
            uri += "?";
            uri += WToUtf8(req->CookedUrl.pQueryString + 1,
                           req->CookedUrl.QueryStringLength - (int)sizeof(WCHAR));
        }
    }
    std::string method  = VerbToString(req);
    std::string version = VersionToString(req->Version);
    rsc->m_Protocol = version;
    tx->processURI(uri.c_str(), method.c_str(), version.c_str());

    // --- request headers ---
#define _TRANSHEADER(id,str)                                               \
    if (req->Headers.KnownHeaders[id].pRawValue != NULL)                   \
    {                                                                      \
        std::string v = AToUtf8(req->Headers.KnownHeaders[id].pRawValue,   \
                                req->Headers.KnownHeaders[id].RawValueLength); \
        tx->addRequestHeader((const unsigned char*)(str),                 \
                             (const unsigned char*)v.c_str());            \
    }

    _TRANSHEADER(HttpHeaderCacheControl, "Cache-Control");
    _TRANSHEADER(HttpHeaderConnection, "Connection");
    _TRANSHEADER(HttpHeaderDate, "Date");
    _TRANSHEADER(HttpHeaderKeepAlive, "Keep-Alive");
    _TRANSHEADER(HttpHeaderPragma, "Pragma");
    _TRANSHEADER(HttpHeaderTrailer, "Trailer");
    _TRANSHEADER(HttpHeaderTransferEncoding, "Transfer-Encoding");
    _TRANSHEADER(HttpHeaderUpgrade, "Upgrade");
    _TRANSHEADER(HttpHeaderVia, "Via");
    _TRANSHEADER(HttpHeaderWarning, "Warning");
    _TRANSHEADER(HttpHeaderAllow, "Allow");
    _TRANSHEADER(HttpHeaderContentLength, "Content-Length");
    _TRANSHEADER(HttpHeaderContentType, "Content-Type");
    _TRANSHEADER(HttpHeaderContentEncoding, "Content-Encoding");
    _TRANSHEADER(HttpHeaderContentLanguage, "Content-Language");
    _TRANSHEADER(HttpHeaderContentLocation, "Content-Location");
    _TRANSHEADER(HttpHeaderContentMd5, "Content-Md5");
    _TRANSHEADER(HttpHeaderContentRange, "Content-Range");
    _TRANSHEADER(HttpHeaderExpires, "Expires");
    _TRANSHEADER(HttpHeaderLastModified, "Last-Modified");
    _TRANSHEADER(HttpHeaderAccept, "Accept");
    _TRANSHEADER(HttpHeaderAcceptCharset, "Accept-Charset");
    _TRANSHEADER(HttpHeaderAcceptEncoding, "Accept-Encoding");
    _TRANSHEADER(HttpHeaderAcceptLanguage, "Accept-Language");
    _TRANSHEADER(HttpHeaderAuthorization, "Authorization");
    _TRANSHEADER(HttpHeaderCookie, "Cookie");
    _TRANSHEADER(HttpHeaderExpect, "Expect");
    _TRANSHEADER(HttpHeaderFrom, "From");
    _TRANSHEADER(HttpHeaderHost, "Host");
    _TRANSHEADER(HttpHeaderIfMatch, "If-Match");
    _TRANSHEADER(HttpHeaderIfModifiedSince, "If-Modified-Since");
    _TRANSHEADER(HttpHeaderIfNoneMatch, "If-None-Match");
    _TRANSHEADER(HttpHeaderIfRange, "If-Range");
    _TRANSHEADER(HttpHeaderIfUnmodifiedSince, "If-Unmodified-Since");
    _TRANSHEADER(HttpHeaderMaxForwards, "Max-Forwards");
    _TRANSHEADER(HttpHeaderProxyAuthorization, "Proxy-Authorization");
    _TRANSHEADER(HttpHeaderReferer, "Referer");
    _TRANSHEADER(HttpHeaderRange, "Range");
    _TRANSHEADER(HttpHeaderTe, "TE");
    _TRANSHEADER(HttpHeaderTranslate, "Translate");
    _TRANSHEADER(HttpHeaderUserAgent, "User-Agent");

#undef _TRANSHEADER

    for (int i = 0; i < req->Headers.UnknownHeaderCount; i++)
    {
        std::string name = AToUtf8(req->Headers.pUnknownHeaders[i].pName,
                                   req->Headers.pUnknownHeaders[i].NameLength);
        std::string val  = AToUtf8(req->Headers.pUnknownHeaders[i].pRawValue,
                                   req->Headers.pUnknownHeaders[i].RawValueLength);
        tx->addRequestHeader((const unsigned char*)name.c_str(),
                             (const unsigned char*)val.c_str());
    }

    tx->processRequestHeaders();
    if (ApplyIntervention(rsc, pHttpContext))
    {
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }

    // --- request body ---
    // Do NOT gate the loop on GetRemainingEntityBytes(): at RQ_BEGIN_REQUEST
    // it can legitimately report 0 while chunks are still in flight, which
    // silently skips inspection. Drive the loop off ReadEntityBody results;
    // ERROR_HANDLE_EOF marks the clean end of the entity.
    {
        char  buf[65536];
        DWORD read = 0;
        size_t inspected = 0;
        const size_t maxInspect = GetMaxInspectBodyBytes();
        for (;;)
        {
            HRESULT hrr = pRequest->ReadEntityBody(buf, sizeof(buf), FALSE, &read, NULL);
            if (read > 0)
            {
                // ReadEntityBody consumes the entity-body pipe, so the downstream
                // handler (ASP.NET/PHP/ISAPI) would otherwise receive an empty
                // body. Re-insert the bytes so the application still sees the
                // original request body.
                pRequest->InsertEntityBody(buf, read);
                // Bound the memory the engine buffers for inspection; the full
                // body is still forwarded to the backend regardless (IIS enforces
                // its own maxAllowedContentLength on the real request).
                if (inspected < maxInspect)
                {
                    size_t take = (size_t)read;
                    if (inspected + take > maxInspect)
                    {
                        take = maxInspect - inspected;
                    }
                    tx->appendRequestBody((const unsigned char*)buf, take);
                    inspected += take;
                }
            }
            if (read == 0 || read < sizeof(buf))
            {
                break;              // drained (or clean EOF signaled via hrr)
            }
            if (FAILED(hrr) && hrr != HRESULT_FROM_WIN32(ERROR_HANDLE_EOF))
            {
                break;
            }
        }
        tx->processRequestBody();
    }
    if (ApplyIntervention(rsc, pHttpContext))
    {
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }

    } while (0);

    }
    catch (const std::exception& e)
    {
        // Fail-closed: finish the request (IIS emits 500) rather than letting
        // an exception cross the module boundary and kill w3wp.
        ReportException("OnBeginRequest", e.what());
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }
    catch (...)
    {
        ReportException("OnBeginRequest", NULL);
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }

    if (FAILED(hr))
    {
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }
    return RQ_NOTIFICATION_CONTINUE;
}


// ---------------------------------------------------------------------------
// OnSendResponse
// ---------------------------------------------------------------------------

REQUEST_NOTIFICATION_STATUS
CMyHttpModule::OnSendResponse(
    IN IHttpContext * pHttpContext,
    IN ISendResponseProvider * pProvider
)
{
    UNREFERENCED_PARAMETER(pProvider);

    REQUEST_STORED_CONTEXT* rsc = (REQUEST_STORED_CONTEXT*)
        pHttpContext->GetModuleContextContainer()->GetModuleContext(g_pModuleContext);

    try
    {

    do
    {
    if (rsc == NULL || rsc->m_pTx == NULL)
    {
        break;
    }

    modsecurity::Transaction* tx = rsc->m_pTx;
    IHttpResponse*             pResponse = pHttpContext->GetResponse();
    HTTP_RESPONSE*             pRaw      = pResponse->GetRawHttpResponse();

    // --- response headers ---
    // Fed exactly once per request: RQ_SEND_RESPONSE fires again for every
    // explicit handler flush, and re-adding the (unchanged) header set would
    // pollute the transaction with duplicates.
    if (!rsc->m_ResponseHeadersFed)
    {
#define _TRANSHEADER(id,str)                                               \
    if (pRaw->Headers.KnownHeaders[id].pRawValue != NULL)                   \
    {                                                                      \
        std::string v = AToUtf8(pRaw->Headers.KnownHeaders[id].pRawValue,   \
                                pRaw->Headers.KnownHeaders[id].RawValueLength); \
        tx->addResponseHeader((const unsigned char*)(str),                \
                              (const unsigned char*)v.c_str());            \
    }

    _TRANSHEADER(HttpHeaderCacheControl, "Cache-Control");
    _TRANSHEADER(HttpHeaderConnection, "Connection");
    _TRANSHEADER(HttpHeaderDate, "Date");
    _TRANSHEADER(HttpHeaderKeepAlive, "Keep-Alive");
    _TRANSHEADER(HttpHeaderPragma, "Pragma");
    _TRANSHEADER(HttpHeaderTrailer, "Trailer");
    _TRANSHEADER(HttpHeaderTransferEncoding, "Transfer-Encoding");
    _TRANSHEADER(HttpHeaderUpgrade, "Upgrade");
    _TRANSHEADER(HttpHeaderVia, "Via");
    _TRANSHEADER(HttpHeaderWarning, "Warning");
    _TRANSHEADER(HttpHeaderAllow, "Allow");
    _TRANSHEADER(HttpHeaderContentLength, "Content-Length");
    _TRANSHEADER(HttpHeaderContentType, "Content-Type");
    _TRANSHEADER(HttpHeaderContentEncoding, "Content-Encoding");
    _TRANSHEADER(HttpHeaderContentLanguage, "Content-Language");
    _TRANSHEADER(HttpHeaderContentLocation, "Content-Location");
    _TRANSHEADER(HttpHeaderContentMd5, "Content-Md5");
    _TRANSHEADER(HttpHeaderContentRange, "Content-Range");
    _TRANSHEADER(HttpHeaderExpires, "Expires");
    _TRANSHEADER(HttpHeaderLastModified, "Last-Modified");
    _TRANSHEADER(HttpHeaderAcceptRanges, "Accept-Ranges");
    _TRANSHEADER(HttpHeaderAge, "Age");
    _TRANSHEADER(HttpHeaderEtag, "Etag");
    _TRANSHEADER(HttpHeaderLocation, "Location");
    _TRANSHEADER(HttpHeaderProxyAuthenticate, "Proxy-Authenticate");
    _TRANSHEADER(HttpHeaderRetryAfter, "Retry-After");
    _TRANSHEADER(HttpHeaderServer, "Server");
    _TRANSHEADER(HttpHeaderSetCookie, "Set-Cookie");
    _TRANSHEADER(HttpHeaderVary, "Vary");
    _TRANSHEADER(HttpHeaderWwwAuthenticate, "Www-Authenticate");

#undef _TRANSHEADER

    for (int i = 0; i < pRaw->Headers.UnknownHeaderCount; i++)
    {
        std::string name = AToUtf8(pRaw->Headers.pUnknownHeaders[i].pName,
                                   pRaw->Headers.pUnknownHeaders[i].NameLength);
        std::string val  = AToUtf8(pRaw->Headers.pUnknownHeaders[i].pRawValue,
                                   pRaw->Headers.pUnknownHeaders[i].RawValueLength);
        tx->addResponseHeader((const unsigned char*)name.c_str(),
                              (const unsigned char*)val.c_str());
    }

    // v3 API: processResponseHeaders(int code, const std::string& protocol).
    // IHttpResponse::GetStatus returns void; status comes via OUT params.
    // The response protocol mirrors the request protocol (HTTP/2 responses
    // travel over HTTP/2; only report HTTP/1.1 when it really was 1.1).
    USHORT statusCode = 0;
    USHORT subStatus = 0;
    PCSTR  statusReason = NULL;
    int    respStatus = 0;
    pResponse->GetStatus(&statusCode, &subStatus, &statusReason,
                         NULL, NULL, NULL, NULL, NULL, NULL);
    respStatus = (int)statusCode;
    // RESPONSE_PROTOCOL stores the string verbatim -> full "HTTP/x.y" here
    // (see VersionToString note about the request-side asymmetry).
    tx->processResponseHeaders(respStatus,
        rsc->m_Protocol.empty() ? std::string("HTTP/1.1")
                                : "HTTP/" + rsc->m_Protocol);
    if (ApplyIntervention(rsc, pHttpContext))
    {
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }
    rsc->m_ResponseHeadersFed = true;
    }

    // --- response body (accumulate only) ---
    // Chunks are incremental: each RQ_SEND_RESPONSE carries only the entity
    // bytes queued since the previous send, so append them all to the
    // transaction here. Do NOT process them yet -- v3's processResponseBody()
    // has no re-run guard and appendResponseBody accumulates, so evaluating on
    // every flush would re-run phase-4 rules over the whole growing body
    // (duplicate alerts + O(n^2)). The single processResponseBody() call is
    // made in OnPostEndRequest once the response is complete.
    {
    size_t respInspected = 0;
    const size_t maxInspect = GetMaxInspectBodyBytes();
    for (ULONG c = 0; c < pRaw->EntityChunkCount; c++)
    {
        HTTP_DATA_CHUNK* chunk = &pRaw->pEntityChunks[c];
        if (chunk->DataChunkType == HttpDataChunkFromMemory)
        {
            size_t len = (size_t)chunk->FromMemory.BufferLength;
            if (respInspected < maxInspect && len > 0)
            {
                size_t take = (respInspected + len > maxInspect)
                                  ? (maxInspect - respInspected) : len;
                tx->appendResponseBody((const unsigned char*)chunk->FromMemory.pBuffer, take);
                respInspected += take;
            }
        }
        else if (chunk->DataChunkType == HttpDataChunkFromFileHandle)
        {
            ULONGLONG start = (ULONGLONG)chunk->FromFileHandle.ByteRange.StartingOffset.QuadPart;
            ULONGLONG length = (ULONGLONG)chunk->FromFileHandle.ByteRange.Length.QuadPart;
            if (length == (ULONGLONG)HTTP_BYTE_RANGE_TO_EOF)
            {
                // Unknown total size; only inspect up to the remaining cap.
                length = maxInspect - respInspected;
            }
            else if (respInspected + length > maxInspect)
            {
                length = maxInspect - respInspected;
            }
            if (length > 0)
            {
                AppendResponseFileChunk(tx,
                                        chunk->FromFileHandle.FileHandle,
                                        start,
                                        length);
                respInspected += (size_t)length;
            }
        }
        // HttpDataChunkFromFragmentCache: IIS exposes no API for a module to
        // read another module's cached fragment bytes, so such content cannot
        // be inspected here; it is skipped deliberately.
    }
    }

    } while (0);

    }
    catch (const std::exception& e)
    {
        // Mid-response there is no clean way to abort the send; fail-open and
        // let IIS finish delivering the already-inspected response.
        ReportException("OnSendResponse", e.what());
        return RQ_NOTIFICATION_CONTINUE;
    }
    catch (...)
    {
        ReportException("OnSendResponse", NULL);
        return RQ_NOTIFICATION_CONTINUE;
    }

    return RQ_NOTIFICATION_CONTINUE;
}


// ---------------------------------------------------------------------------
// OnPostEndRequest
// ---------------------------------------------------------------------------

REQUEST_NOTIFICATION_STATUS
CMyHttpModule::OnPostEndRequest(
    IN IHttpContext * pHttpContext,
    IN IHttpEventProvider * pProvider
)
{
    UNREFERENCED_PARAMETER(pProvider);

    REQUEST_STORED_CONTEXT* rsc = (REQUEST_STORED_CONTEXT*)
        pHttpContext->GetModuleContextContainer()->GetModuleContext(g_pModuleContext);

    if (rsc != NULL && rsc->m_pTx != NULL)
    {
        try
        {
            // Single, deferred response-body evaluation: phase-4 rules run once
            // over the fully accumulated body (appended in OnSendResponse),
            // avoiding duplicate alerts from per-flush re-processing.
            rsc->m_pTx->processResponseBody();
            if (ApplyIntervention(rsc, pHttpContext))
            {
                // Disruptive: ApplyIntervention already finalized the tx.
                return RQ_NOTIFICATION_CONTINUE;
            }
            rsc->FinishRequest();   // processLogging + delete tx
        }
        catch (const std::exception& e)
        {
            ReportException("OnPostEndRequest", e.what());
        }
        catch (...)
        {
            ReportException("OnPostEndRequest", NULL);
        }
    }

    return RQ_NOTIFICATION_CONTINUE;
}


// ---------------------------------------------------------------------------
// RegisterModule -- the only exported symbol (see ModSecurityIIS.def)
// ---------------------------------------------------------------------------

HRESULT
__stdcall
RegisterModule(
    DWORD                           dwServerVersion,
    IHttpModuleRegistrationInfo *   pModuleInfo,
    IHttpServer *                   pHttpServer
)
{
    HRESULT                  hr = S_OK;
    CMyHttpModuleFactory *   pFactory = NULL;

    UNREFERENCED_PARAMETER(dwServerVersion);

    if (pModuleInfo == NULL || pHttpServer == NULL)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
        goto Finished;
    }

    g_pModuleContext = pModuleInfo->GetId();
    g_pHttpServer    = pHttpServer;

    try
    {
    pFactory = new (std::nothrow) CMyHttpModuleFactory();
    if (pFactory == NULL)
    {
        hr = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
        goto Finished;
    }

    hr = pModuleInfo->SetRequestNotifications(
            pFactory,
            RQ_BEGIN_REQUEST | RQ_SEND_RESPONSE,
            RQ_END_REQUEST);
    if (FAILED(hr))
    {
        goto Finished;
    }

    hr = pModuleInfo->SetPriorityForRequestNotification(RQ_BEGIN_REQUEST, PRIORITY_ALIAS_FIRST);
    if (FAILED(hr))
    {
        goto Finished;
    }
    hr = pModuleInfo->SetPriorityForRequestNotification(RQ_SEND_RESPONSE, PRIORITY_ALIAS_LAST);
    if (FAILED(hr))
    {
        goto Finished;
    }

    pFactory = NULL;
    }
    catch (const std::exception& e)
    {
        ReportException("RegisterModule", e.what());
        hr = E_UNEXPECTED;
    }
    catch (...)
    {
        ReportException("RegisterModule", NULL);
        hr = E_UNEXPECTED;
    }

 Finished:
    if (pFactory != NULL)
    {
        delete pFactory;
        pFactory = NULL;
    }
    return hr;
}

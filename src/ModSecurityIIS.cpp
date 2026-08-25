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

static std::string VerbToString(HTTP_REQUEST* req)
{
    switch (req->Verb)
    {
    case HttpVerbOPTIONS: return "OPTIONS";
    case HttpVerbGET:
    case HttpVerbHEAD:    return "GET";
    case HttpVerbPOST:    return "POST";
    case HttpVerbPUT:     return "PUT";
    case HttpVerbDELETE:  return "DELETE";
    case HttpVerbTRACE:   return "TRACE";
    case HttpVerbCONNECT: return "CONNECT";
    case HttpVerbMOVE:    return "MOVE";
    case HttpVerbCOPY:    return "COPY";
    case HttpVerbPROPFIND:   return "PROPFIND";
    case HttpVerbPROPPATCH: return "PROPPATCH";
    case HttpVerbMKCOL:   return "MKCOL";
    case HttpVerbLOCK:    return "LOCK";
    case HttpVerbUNLOCK:  return "UNLOCK";
    default:              return "INVALID";
    }
}

static std::string VersionToString(HTTP_VERSION version)
{
    if (HTTP_EQUAL_VERSION(version, 0, 9)) return "HTTP/0.9";
    if (HTTP_EQUAL_VERSION(version, 1, 0)) return "HTTP/1.0";
    return "HTTP/1.1";
}


// ---------------------------------------------------------------------------
// Intervention helper: if the transaction wants to disrupt, apply it to the
// IIS response and finalize the request. Returns true if the request should
// be finished.
// ---------------------------------------------------------------------------

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
    const char* url = it.url;

    modsecurity::intervention::free(&it);   // release url/log owned by libmodsecurity

    if (!disruptive)
    {
        return false;
    }

    // A disruptive action was requested. Prefer a redirect when the rule
    // supplied one; otherwise honor the explicit status (defaulting to 403).
    pHttpContext->GetResponse()->Clear();
    if (url != nullptr && url[0] != '\0')
    {
        pHttpContext->GetResponse()->Redirect(url, TRUE);
    }
    else
    {
        if (status <= 0)
        {
            status = 403;
        }
        pHttpContext->GetResponse()->SetStatus(status, "ModSecurity Action");
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

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    m_dwPageSize = sysInfo.dwPageSize;

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
        hr = S_OK;          // config not present -> simply don't secure
        break;
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
    modsecurity::RulesSet* rules = iis::getRules(configFile, &rulesErr);
    if (rules == nullptr)
    {
        WriteEventViewerLog(rulesErr.c_str(), EVENTLOG_ERROR_TYPE);
        break;
    }

    // v3 API: Transaction(ModSecurity*, RulesSet*, void*) where the 3rd arg is
    // the per-transaction log-callback data (passed back to ServerLogCallback).
    modsecurity::Transaction* tx = new modsecurity::Transaction(&iis::engine(), rules, this);
    if (tx == nullptr)
    {
        hr = E_UNEXPECTED;
        break;
    }

    REQUEST_STORED_CONTEXT* rsc = new REQUEST_STORED_CONTEXT();
    rsc->m_pTx          = tx;
    rsc->m_pHttpContext = pHttpContext;
    rsc->m_pProvider    = pProvider;

    pHttpContext->GetModuleContextContainer()->SetModuleContext(rsc, g_pModuleContext);

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
    {
        char  buf[65536];
        DWORD read = 0;
        while (pRequest->GetRemainingEntityBytes() > 0)
        {
            HRESULT hrr = pRequest->ReadEntityBody(buf, sizeof(buf), FALSE, &read, NULL);
            if (read > 0)
            {
                tx->appendRequestBody((const unsigned char*)buf, (size_t)read);
                // ReadEntityBody consumes the entity-body pipe, so the downstream
                // handler (ASP.NET/PHP/ISAPI) would otherwise receive an empty
                // body. Re-insert the bytes (IIS appends to existing entity body)
                // so the application still sees the original request body.
                pRequest->InsertEntityBody(buf, read);
            }
            if (read == 0)
            {
                break;
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
    // (processed for every response, including header-only/empty-body ones)
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
    USHORT statusCode = 0;
    USHORT subStatus = 0;
    PCSTR  statusReason = NULL;
    int    respStatus = 0;
    pResponse->GetStatus(&statusCode, &subStatus, &statusReason,
                         NULL, NULL, NULL, NULL, NULL, NULL);
    respStatus = (int)statusCode;
    tx->processResponseHeaders(respStatus, "HTTP/1.1");
    if (ApplyIntervention(rsc, pHttpContext))
    {
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }

    // --- response body ---
    for (ULONG c = 0; c < pRaw->EntityChunkCount; c++)
    {
        HTTP_DATA_CHUNK* chunk = &pRaw->pEntityChunks[c];
        if (chunk->DataChunkType == HttpDataChunkFromMemory)
        {
            tx->appendResponseBody((const unsigned char*)chunk->FromMemory.pBuffer,
                                   (size_t)chunk->FromMemory.BufferLength);
        }
        else if (chunk->DataChunkType == HttpDataChunkFromFileHandle)
        {
            // Read the file range into memory, then append.
            HANDLE  hFile = chunk->FromFileHandle.FileHandle;
            ULONGLONG start = chunk->FromFileHandle.ByteRange.StartingOffset.QuadPart;
            ULONGLONG length = chunk->FromFileHandle.ByteRange.Length.QuadPart;
            if (length == HTTP_BYTE_RANGE_TO_EOF)
            {
                LARGE_INTEGER fs;
                if (GetFileSizeEx(hFile, &fs))
                {
                    length = fs.QuadPart - start;
                }
                else
                {
                    length = 0;
                }
            }
            if (length > 0)
            {
                std::vector<char> fbuf((size_t)length);
                DWORD got = 0;
                OVERLAPPED ovl = { 0 };
                ovl.Offset     = (DWORD)start;
                ovl.OffsetHigh = (DWORD)(start >> 32);
                if (ReadFile(hFile, fbuf.data(), (DWORD)length, &got, &ovl) || GetLastError() == ERROR_IO_PENDING)
                {
                    tx->appendResponseBody((const unsigned char*)fbuf.data(), (size_t)got);
                }
            }
        }
    }

    tx->processResponseBody();
    if (ApplyIntervention(rsc, pHttpContext))
    {
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }

    } while (0);

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
        rsc->FinishRequest();   // processLogging + delete tx
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

    pFactory = new CMyHttpModuleFactory();
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
    hr = pModuleInfo->SetPriorityForRequestNotification(RQ_SEND_RESPONSE, PRIORITY_ALIAS_LAST);

    pFactory = NULL;

Finished:
    return hr;
}

#pragma once

#include "httpserv.h"
#include "connector.h"        // brings in modsecurity::Transaction + iis:: namespace
#include "moduleconfig.h"

#include <memory>
#include <vector>

class REQUEST_STORED_CONTEXT : public IHttpStoredContext
{
 public:
    REQUEST_STORED_CONTEXT()
        : m_pTx(nullptr), m_pHttpContext(nullptr),
          m_ResponseHeadersFed(false), m_BodyReadActive(false),
          m_ResponseBodyBlock(false), m_ResponseBodyEvaluated(false)
    { }

    ~REQUEST_STORED_CONTEXT()
    {
        FinishRequest();
    }

    // IHttpStoredContext: IIS calls this to release the object.
    VOID
    CleanupStoredContext(VOID)
    {
        FinishRequest();
        delete this;
    }


    // Must never let an exception escape: besides the explicit call from
    // OnPostEndRequest this also runs from the destructor -- and a throwing
    // step during another exception's stack unwinding would std::terminate
    // the worker process.
    void FinishRequest() noexcept
    {
        if (m_pTx != nullptr)
        {
            try
            {
                // v3 finalizes logging at the end of the request lifecycle.
                m_pTx->processLogging();
                delete m_pTx;
            }
            catch (...)
            {
                // Static-literal only: anything fancier risks allocating
                // while the likely failure mode IS an allocation failure.
                iis::WriteEventViewerLog(
                    "ModSecurityIIS: exception while finalizing transaction",
                    EVENTLOG_ERROR_TYPE);
            }
            m_pTx = nullptr;
        }
        // Release the rules reference only after the transaction that used it
        // is gone, so the cached RulesSet can never be freed while in use.
        m_pRules.reset();
    }

    modsecurity::Transaction*           m_pTx;
    IHttpContext*                       m_pHttpContext;
    // Keeps the RulesSet alive for the lifetime of this transaction.
    std::shared_ptr<modsecurity::RulesSet> m_pRules;
    // RQ_SEND_RESPONSE can fire several times per request. Response headers
    // must be fed exactly once.
    bool                      m_ResponseHeadersFed;
    // Mirrors the IIS <responseBodyBlock> switch. When true and response-body
    // access + rule engine are enabled, the connector may block responses.
    bool                      m_ResponseBodyBlock;
    // Set once phase-4 has been evaluated in OnSendResponse (Mode A).
    bool                      m_ResponseBodyEvaluated;
    // HTTP version of the request line ("HTTP/1.1", "HTTP/2", ...).
    std::string               m_Protocol;

    // --- entity-body read state ---
    // The entity body is drained chunk by chunk into m_Body and handed back to
    // IIS with a SINGLE InsertEntityBody() once the body is complete.
    std::vector<char>         m_Body;
    char                      m_ReadBuf[65536];
    // True while an async ReadEntityBody() is in flight. Only ever set on the
    // LEGACY async path (MODSEC_IIS_BODY_ASYNC=1); the default synchronous
    // path never leaves a read pending.
    bool                      m_BodyReadActive;
};


class CMyHttpModule : public CHttpModule
{
public:
    HANDLE              m_hEventLog;

    REQUEST_NOTIFICATION_STATUS
    OnBeginRequest(
        IN IHttpContext * pHttpContext,
        IN IHttpEventProvider * pProvider
    ) override;

    REQUEST_NOTIFICATION_STATUS
    OnSendResponse(
        IN IHttpContext * pHttpContext,
        IN ISendResponseProvider * pProvider
    ) override;

    REQUEST_NOTIFICATION_STATUS
    OnPostEndRequest(
        IN IHttpContext * pHttpContext,
        IN IHttpEventProvider * pProvider
    ) override;

    // Entity-body reads are SYNCHRONOUS by default (see DriveBodyRead): both
    // async completion mechanisms lost completions under concurrent load, so
    // there is no per-operation callback involvement. The legacy multicast
    // handler below is retained DISABLED for reference/debugging only.
    REQUEST_NOTIFICATION_STATUS
    OnAsyncCompletion(
        IN IHttpContext * pHttpContext,
        IN DWORD          dwNotification,
        IN BOOL           fPostNotification,
        IN IHttpEventProvider * pProvider,
        IN IHttpCompletionInfo * pCompletionInfo
    ) override;

    CMyHttpModule();
    ~CMyHttpModule();

    void Dispose() override;

    BOOL WriteEventViewerLog(LPCSTR szNotification, WORD category = EVENTLOG_INFORMATION_TYPE);

private:
    // Drains the request entity body, stopping on EOF / error / once the
    // declared Content-Length is consumed. Two modes:
    //  - DEFAULT: SYNCHRONOUS ReadEntityBody() calls (fAsync=FALSE), the whole
    //    body consumed and re-inserted before returning -- no async operation
    //    exists that could be lost (diag/arr-body-stall).
    //  - MODSEC_IIS_BODY_ASYNC=1: legacy ASYNCHRONOUS reads whose completions
    //    resume via OnAsyncCompletion (retained for reference; known to lose
    //    completions under concurrent load).
    // Short reads NEVER mean end-of-body in either mode.
    static REQUEST_NOTIFICATION_STATUS
    DriveBodyRead(REQUEST_STORED_CONTEXT* rsc, IHttpContext* pHttpContext);

    // Restores the drained entity body for the downstream handler, feeds it to
    // the engine and applies any intervention. `reason` names the stop
    // condition (body-trace diagnostics only).
    static REQUEST_NOTIFICATION_STATUS
    FinishBodyRead(REQUEST_STORED_CONTEXT* rsc, IHttpContext* pHttpContext,
                   const char* reason);
};

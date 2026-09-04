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
    // True while an async ReadEntityBody() is in flight.
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
    );

    REQUEST_NOTIFICATION_STATUS
    OnSendResponse(
        IN IHttpContext * pHttpContext,
        IN ISendResponseProvider * pProvider
    );

    REQUEST_NOTIFICATION_STATUS
    OnPostEndRequest(
        IN IHttpContext * pHttpContext,
        IN IHttpEventProvider * pProvider
    );

    // Called by IIS when an async operation from OnBeginRequest completes.
    // Only handles RQ_BEGIN_REQUEST completions with a read of ours in flight.
    REQUEST_NOTIFICATION_STATUS
    OnAsyncCompletion(
        IN IHttpContext * pHttpContext,
        IN DWORD          dwNotification,
        IN BOOL           fPostNotification,
        IN IHttpEventProvider * pProvider,
        IN IHttpCompletionInfo * pCompletionInfo
    );

    CMyHttpModule();
    ~CMyHttpModule();

    void Dispose();

    BOOL WriteEventViewerLog(LPCSTR szNotification, WORD category = EVENTLOG_INFORMATION_TYPE);

private:
    // Drains the request entity body with asynchronous ReadEntityBody() calls,
    // continuing through short reads (they do NOT mean end-of-body) and stopping
    // on EOF / error / once the declared Content-Length is consumed. Returns
    // RQ_NOTIFICATION_PENDING while a read is in flight; resumes in
    // OnAsyncCompletion.
    REQUEST_NOTIFICATION_STATUS
    DriveBodyRead(REQUEST_STORED_CONTEXT* rsc, IHttpContext* pHttpContext);

    // Restores the drained entity body for the downstream handler, feeds it to
    // the engine and applies any intervention.
    REQUEST_NOTIFICATION_STATUS
    FinishBodyRead(REQUEST_STORED_CONTEXT* rsc, IHttpContext* pHttpContext);
};

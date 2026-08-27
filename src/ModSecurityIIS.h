#pragma once

#include "httpserv.h"
#include "connector.h"        // brings in modsecurity::Transaction + iis:: namespace
#include "moduleconfig.h"

#include <memory>

class REQUEST_STORED_CONTEXT : public IHttpStoredContext
{
 public:
    REQUEST_STORED_CONTEXT()
        : m_pTx(nullptr), m_pHttpContext(nullptr),
          m_ResponseHeadersFed(false)
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
    // Keeps the RulesSet alive for the lifetime of this transaction. The engine
    // caches RulesSet objects by config-file path; holding a shared_ptr here
    // lets the cache safely reload (and free the old copy) without dangling the
    // raw pointer the Transaction was constructed with.
    std::shared_ptr<modsecurity::RulesSet> m_pRules;
    // RQ_SEND_RESPONSE can fire several times per request (every explicit
    // handler Flush/SendResponse). Response headers must be fed to the
    // transaction exactly once; entity chunks are delivered incrementally,
    // one batch per notification.
    bool                      m_ResponseHeadersFed;
    // HTTP version of the request line ("HTTP/1.1", "HTTP/2", ...). The
    // response protocol mirrors the request protocol, so it is reused when
    // feeding Transaction::processResponseHeaders.
    std::string               m_Protocol;
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

    // Inspects the request body. Deferred from OnBeginRequest to
    // OnMapRequestHandler: at RQ_BEGIN_REQUEST the entity body is not yet fully
    // buffered, so a synchronous ReadEntityBody loop can hang (CI observed a
    // ~44-min stall) and short reads force a premature EOF break that truncates
    // inspection. By RQ_MAP_REQUEST_HANDLER the handler is about to be selected
    // and the full entity body is available, so a clean break-on-zero loop is
    // both safe and complete. The downstream handler still consumes the body
    // during RQ_EXECUTE_REQUEST_HANDLER (after map-handler), so the bytes are
    // re-injected via InsertEntityBody and never lost.
    REQUEST_NOTIFICATION_STATUS
    OnMapRequestHandler(
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

    CMyHttpModule();
    ~CMyHttpModule();

    void Dispose();

    BOOL WriteEventViewerLog(LPCSTR szNotification, WORD category = EVENTLOG_INFORMATION_TYPE);
};

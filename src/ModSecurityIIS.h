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
          m_ResponseHeadersFed(false), m_BodyReadActive(false)
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

    // --- entity-body read state ----------------------------------------------
    // The entity body is drained chunk by chunk into m_Body and handed back to
    // IIS with a SINGLE InsertEntityBody() once the body is complete. Rationale:
    //   * InsertEntityBody() inserts BEFORE any remaining unread entity body, so
    //     calling it while we are still reading would make the next
    //     ReadEntityBody return our own copy (duplication / endless loop).
    //   * IIS does not copy the buffer -- it must live until the end of the
    //     request, so the final insert uses request-scoped memory
    //     (IHttpContext::AllocateRequestMemory), never the read buffer.
    std::vector<char>         m_Body;
    char                      m_ReadBuf[65536];
    // True while an asynchronous ReadEntityBody() is in flight. OnAsyncCompletion
    // uses it to tell our own completions apart from any other async operation.
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

    // Called by IIS when an asynchronous operation started from OnBeginRequest
    // completes -- that is how the entity body is drained without ever blocking a
    // worker thread. Only operations WE started are handled (RQ_BEGIN_REQUEST,
    // non-post, with a read of ours in flight); everything else is passed back
    // untouched. The status is returned directly from here: PostCompletion() is
    // deliberately NOT used, because that is for module-owned async work and
    // would double-signal this IIS-tracked I/O.
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

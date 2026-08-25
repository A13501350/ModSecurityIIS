#pragma once

#include "httpserv.h"
#include "connector.h"        // brings in modsecurity::Transaction + iis:: namespace
#include "moduleconfig.h"

class REQUEST_STORED_CONTEXT : public IHttpStoredContext
{
 public:
    REQUEST_STORED_CONTEXT()
        : m_pTx(nullptr), m_pHttpContext(nullptr), m_pProvider(nullptr),
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
    }

    modsecurity::Transaction* m_pTx;
    IHttpContext*             m_pHttpContext;
    IHttpEventProvider*       m_pProvider;
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

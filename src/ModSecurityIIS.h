#pragma once

#include "httpserv.h"
#include "connector.h"        // brings in modsecurity::Transaction + iis:: namespace
#include "moduleconfig.h"

class REQUEST_STORED_CONTEXT : public IHttpStoredContext
{
 public:
    REQUEST_STORED_CONTEXT()
        : m_pTx(nullptr), m_pHttpContext(nullptr), m_pProvider(nullptr),
          m_pResponseBuffer(nullptr), m_pResponseLength(0), m_pResponsePosition(0)
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

    void FinishRequest()
    {
        if (m_pTx != nullptr)
        {
            // VERIFY: method name. v3 logs via processLogging() at the end of
            // the request lifecycle.
            m_pTx->processLogging();   // <-- VERIFY
            delete m_pTx;
            m_pTx = nullptr;
        }
    }

    modsecurity::Transaction* m_pTx;
    IHttpContext*             m_pHttpContext;
    IHttpEventProvider*       m_pProvider;
    char*                     m_pResponseBuffer;
    ULONGLONG                 m_pResponseLength;
    ULONGLONG                 m_pResponsePosition;
};


class CMyHttpModule : public CHttpModule
{
public:
    HANDLE              m_hEventLog;
    DWORD               m_dwPageSize;
    CRITICAL_SECTION    m_csLock;

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

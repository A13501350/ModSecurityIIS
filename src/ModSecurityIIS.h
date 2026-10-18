#pragma once

#include "httpserv.h"
#include "connector.h"        // brings in modsecurity::Transaction + iis:: namespace
#include "moduleconfig.h"

#include <memory>
#include <vector>

// ARR-model asynchronous entity-body state machine. At most ONE async
// ReadEntityBody is outstanding per request; the completion is claimed by
// swapping this state, never by filtering the multicast notification bits
// (research/body-async-arr-model, modeled on FORWARDING_HANDLER::
// OnAsyncCompletion in requestRouter.dll, which ignores dwNotification and
// dispatches on its private handler state).
enum BodyReadState
{
    BRS_IDLE = 0,        // no outstanding read
    BRS_READ_PENDING = 1,// exactly one async ReadEntityBody in flight
    BRS_DONE = 2         // body finished; late/foreign completions are ignored
};

// Size of each ReadEntityBody chunk. The staging buffer (m_ReadBuf below)
// is allocated with this exact size on demand in BeginBodyRead.
constexpr DWORD kBodyReadChunkSize = 65536;

// ---------------------------------------------------------------------------
// Perf phase stats (MODSEC_IIS_PERF_STATS=<path>). Implemented in
// ModSecurityIIS.cpp; cheap no-ops while the switch is off.
// ---------------------------------------------------------------------------
enum PerfPhase
{
    PERF_BEGIN = 0,      // OnBeginRequest: config + tx create + phase 1
    PERF_BODY_DRAIN,     // body drain wall time (incl. IIS I/O wait)
    PERF_BODY_IO,        // accumulated ReadEntityBody call time
    PERF_BODY_RESTORE,   // AllocateRequestMemory + InsertEntityBody re-forward
    PERF_PHASE2,         // appendRequestBody + processRequestBody
    PERF_RESP_HDRS,      // response headers feed + processResponseHeaders
    PERF_RESP_BODY_ACC,  // response body chunk accumulation
    PERF_PHASE4,         // processResponseBody
    PERF_LOGGING,        // processLogging at end of request
    PERF_PHASE_COUNT
};

ULONGLONG PerfQpcNow() noexcept;
void PerfRecord(int phase, ULONGLONG qpcStart) noexcept;

class REQUEST_STORED_CONTEXT : public IHttpStoredContext
{
 public:
    REQUEST_STORED_CONTEXT()
        : m_pTx(nullptr), m_pHttpContext(nullptr),
          m_ResponseHeadersFed(false),
          m_ResponseBodyBlock(false), m_ResponseBodyEvaluated(false),
          m_HasBody(false), m_DeclaredBodyLength(0),
          m_BodyReadState(BRS_IDLE), m_BodyDrainStartTicks(0)
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
                const ULONGLONG tLog = PerfQpcNow();
                m_pTx->processLogging();
                PerfRecord(PERF_LOGGING, tLog);
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
    // Per-read staging buffer, allocated on demand in BeginBodyRead: bodyless
    // requests (the common GET) must not carry 64 KiB of dead weight in their
    // stored context.
    std::vector<char>         m_ReadBuf;
    // What the request declared about its body (cached at BeginRequest so the
    // stop condition holds across async completions).
    bool                      m_HasBody;
    ULONGLONG                 m_DeclaredBodyLength;   // 0 == unknown/chunked
    // ARR-model single-outstanding-read state; interlocked because the
    // completion may arrive on an IIS I/O thread while BeginRequest returned
    // PENDING. See the BodyReadState enum above.
    volatile LONG             m_BodyReadState;
    // QPC stamp taken at BeginBodyRead entry; consumed by PERF_BODY_DRAIN in
    // FinishBodyRead (reset to 0 after recording). 0 == not draining.
    ULONGLONG                 m_BodyDrainStartTicks;
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

    // Entity-body reads follow the ARR state-machine model (see the
    // BodyReadState enum): asynchronous by default on this research branch,
    // fAsync=FALSE available via MODSEC_IIS_BODY_ASYNC=0 for A/B comparison.
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
    // First entry from OnBeginRequest: resolve what the request declares,
    // pre-size the accumulator, then pump reads.
    static REQUEST_NOTIFICATION_STATUS
    BeginBodyRead(REQUEST_STORED_CONTEXT* rsc, IHttpContext* pHttpContext);

    // Issues ReadEntityBody calls until one goes pending (returns
    // RQ_NOTIFICATION_PENDING) or the body finishes. Inline-completed chunks
    // are consumed in a loop; a pended read resumes in OnAsyncCompletion,
    // which re-enters here to chain the next read -- the same continuation
    // shape ARR's FORWARDING_HANDLER uses.
    static REQUEST_NOTIFICATION_STATUS
    PumpBodyRead(REQUEST_STORED_CONTEXT* rsc, IHttpContext* pHttpContext);

    // Appends one completed chunk and applies the stop conditions (EOF /
    // error / declared Content-Length / inspection cap). Returns true when
    // another read must be issued; false with *pStatus holding the final
    // notification status (FinishBodyRead already ran).
    static bool
    ConsumeBodyChunk(REQUEST_STORED_CONTEXT* rsc, IHttpContext* pHttpContext,
                     DWORD cb, HRESULT hr,
                     REQUEST_NOTIFICATION_STATUS* pStatus);

    // Restores the drained entity body for the downstream handler, feeds it to
    // the engine and applies any intervention.
    static REQUEST_NOTIFICATION_STATUS
    FinishBodyRead(REQUEST_STORED_CONTEXT* rsc, IHttpContext* pHttpContext);
};

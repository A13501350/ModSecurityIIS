// Factory class for CMyHttpModule.
// Creates a single CMyHttpModule instance (singleton) and returns it for
// every request. Mirrors the v2 IIS connector's factory. The CRITICAL_SECTION
// guards only the one-time creation of that singleton so concurrent requests
// don't race to construct it; the CMyHttpModule instance itself holds no
// per-request mutable state that needs locking.

#include <new>   // std::nothrow

class CMyHttpModule;

class CMyHttpModuleFactory : public IHttpModuleFactory
{
        CMyHttpModule *				m_pModule;
		CRITICAL_SECTION			m_csLock;

public:
	CMyHttpModuleFactory()
	{
		m_pModule = NULL;
		InitializeCriticalSection(&m_csLock);
	}

	virtual
    HRESULT
    GetHttpModule(
        OUT CHttpModule            **ppModule,
        IN IModuleAllocator        *
    )
    {
        HRESULT                    hr = S_OK;

	    if ( ppModule == NULL )
        {
            hr = HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER );
            goto Finished;
        }

		EnterCriticalSection(&m_csLock);

		if(m_pModule == NULL)
		{
            // nothrow: a throwing operator new would unwind straight across the
            // module COM boundary and crash w3wp. The nothrow form also absorbs
            // any exception thrown by the CMyHttpModule constructor (which may
            // allocate the engine via iis::engine()), returning NULL so we can
            // report the failure safely. The lock must be released before the
            // error path or every later request would deadlock on this CS.
			m_pModule = new (std::nothrow) CMyHttpModule();

			if ( m_pModule == NULL )
			{
				hr = HRESULT_FROM_WIN32( ERROR_NOT_ENOUGH_MEMORY );
                LeaveCriticalSection(&m_csLock);
				goto Finished;
			}
		}

		LeaveCriticalSection(&m_csLock);

        *ppModule = m_pModule;

	Finished:
        return hr;
    }

    virtual
    void
    Terminate()
    {
        if ( m_pModule != NULL )
        {
			delete m_pModule;
            m_pModule = NULL;
        }

        DeleteCriticalSection(&m_csLock);
        delete this;
    }
};

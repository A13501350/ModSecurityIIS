// Factory class for CMyHttpModule. Creates a singleton and returns it for
// every request. The CRITICAL_SECTION guards one-time creation only.

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
            // nothrow: a throwing new would unwind across the module COM
            // boundary and crash w3wp.
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

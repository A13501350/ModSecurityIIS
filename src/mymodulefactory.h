// Factory class for CMyHttpModule.
// Creates a single CMyHttpModule instance (singleton) and returns it for
// every request. Mirrors the v2 IIS connector's factory; the module object
// is shared across all requests, so CMyHttpModule guards shared state with a
// CRITICAL_SECTION.

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
			m_pModule = new CMyHttpModule();

			if ( m_pModule == NULL )
			{
				hr = HRESULT_FROM_WIN32( ERROR_NOT_ENOUGH_MEMORY );
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

        delete this;
    }
};

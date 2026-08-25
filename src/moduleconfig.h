#pragma once

// IIS-native configuration for the ModSecurity connector.
// Reads the <system.webServer/ModSecurity> section via the IIS administration
// COM API (IAppHostAdminManager). The actual ModSecurity rules are NOT stored
// here -- only the `enabled` flag and the path to a normal ModSecurity v3
// config file (`configFile`). The connector loads/caches the Rules from that
// path on demand (see connector.cpp).

#define MODSECURITY_SECTION                  L"system.webServer/ModSecurity"
#define MODSECURITY_SECTION_ENABLED          L"enabled"
#define MODSECURITY_SECTION_CONFIGFILE       L"configFile"

extern IHttpServer *                       g_pHttpServer;
extern PVOID                                g_pModuleContext;

class MODSECURITY_STORED_CONTEXT : public IHttpStoredContext
{
 public:
    MODSECURITY_STORED_CONTEXT();
    ~MODSECURITY_STORED_CONTEXT();

    static
    HRESULT
    GetConfig(
        IHttpContext *   pContext,
        MODSECURITY_STORED_CONTEXT ** ppModuleConfig
    );

    // IHttpStoredContext: IIS calls this to release the object.
    VOID
    CleanupStoredContext(VOID)
    {
        delete this;
    }

    BOOL   GetIsEnabled() { return m_bIsEnabled; }
    WCHAR* GetPath()      { return m_pszPath; }

    HRESULT
    Initialize(
        IHttpContext *              pW3Context,
        IAppHostConfigException **  ppException
    );

 private:
    HRESULT
    GetBooleanPropertyValue(
            IAppHostElement*            pElement,
            WCHAR*                      pszPropertyName,
            IAppHostPropertyException** pException,
            BOOL*                       pBoolValue );

    HRESULT
    GetStringPropertyValue(
            IAppHostElement*            pElement,
            WCHAR*                      pszPropertyName,
            IAppHostPropertyException** pException,
            WCHAR**                     ppszValue );

    BOOL   m_bIsEnabled;
    WCHAR* m_pszPath;
};

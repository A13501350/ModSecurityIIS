// Ported from the v2 IIS connector (iis/moduleconfig.cpp). Version-agnostic:
// it only reads the IIS <system.webServer/ModSecurity> section via the
// administration COM API. The ModSecurity engine is no longer driven from
// here -- the connector loads rules lazily by configFile path.

#define WIN32_LEAN_AND_MEAN

#undef inline
#define inline inline

#include "httpserv.h"

#include "mymodule.h"
#include "mymodulefactory.h"
#include "moduleconfig.h"

HRESULT
MODSECURITY_STORED_CONTEXT::Initialize(
    IHttpContext *              pW3Context,
    IAppHostConfigException **  ppException
)
{
    HRESULT                    hr                       = S_OK;
    IAppHostAdminManager       *pAdminManager           = NULL;
    IAppHostElement            *pSessionTrackingElement = NULL;
    IAppHostPropertyException  *pPropertyException      = NULL;

    PCWSTR pszConfigPath = pW3Context->GetMetadata()->GetMetaPath();
    BSTR bstrUrlPath     = SysAllocString( pszConfigPath );

    pAdminManager = g_pHttpServer->GetAdminManager();

    if ( ( FAILED( hr ) ) || ( pAdminManager == NULL ) )
    {
        hr = E_UNEXPECTED;
        goto Failure;
    }

    hr = pAdminManager->GetAdminSection(
                                MODSECURITY_SECTION,
                                bstrUrlPath,
                                &pSessionTrackingElement );

    if ( FAILED( hr ) )
    {
        goto Failure;
    }

    if ( pSessionTrackingElement == NULL )
    {
        hr = E_UNEXPECTED;
        goto Failure;
    }

    hr = GetBooleanPropertyValue(
                pSessionTrackingElement,
                MODSECURITY_SECTION_ENABLED,
                &pPropertyException,
                &m_bIsEnabled);

    if ( FAILED( hr ) )
    {
        goto Failure;
    }

    if ( pPropertyException != NULL )
    {
        ppException = ( IAppHostConfigException** ) &pPropertyException;
        goto Failure;
    }

    if ( m_bIsEnabled == FALSE )
    {
        // No point reading further if the module is disabled for this URL.
        goto Failure;
    }

    hr = GetStringPropertyValue(
                pSessionTrackingElement,
                MODSECURITY_SECTION_CONFIGFILE,
                &pPropertyException,
                &m_pszPath);

    if ( FAILED( hr ) )
    {
        goto Failure;
    }

    if ( pPropertyException != NULL )
    {
        ppException = ( IAppHostConfigException** ) &pPropertyException;
        goto Failure;
    }

Failure:
    SysFreeString( bstrUrlPath );
    return hr;
}

HRESULT
MODSECURITY_STORED_CONTEXT::GetBooleanPropertyValue(
        IAppHostElement*            pElement,
        WCHAR*                      pszPropertyName,
        IAppHostPropertyException** pException,
        BOOL*                       pBoolValue )
{
    HRESULT                 hr              = S_OK;
    IAppHostProperty        *pProperty      = NULL;
    VARIANT                 vPropertyValue;

    if ( ( pElement == NULL ) || ( pszPropertyName == NULL ) ||
         ( pException == NULL ) || ( pBoolValue == NULL ) )
    {
        hr = E_INVALIDARG;
        goto Failure;
    }

    hr = pElement->GetPropertyByName( pszPropertyName, &pProperty );
    if ( FAILED( hr ) ) goto Failure;
    if ( pProperty == NULL ) { hr = E_UNEXPECTED; goto Failure; }

    VariantInit( &vPropertyValue );
    hr = pProperty->get_Value( &vPropertyValue );
    if ( FAILED( hr ) ) goto Failure;

    *pException = NULL;
    hr = pProperty->get_Exception( pException );
    if ( FAILED( hr ) ) goto Failure;
    if ( ( *pException ) != NULL ) goto Failure;

    *pBoolValue = ( vPropertyValue.boolVal == VARIANT_TRUE ) ? TRUE : FALSE;

Failure:
    VariantClear( &vPropertyValue );
    if ( pProperty != NULL ) { pProperty->Release(); pProperty = NULL; }
    return hr;
}

HRESULT
MODSECURITY_STORED_CONTEXT::GetStringPropertyValue(
        IAppHostElement*            pElement,
        WCHAR*                      pszPropertyName,
        IAppHostPropertyException** pException,
        WCHAR**                     ppszValue )
{
    HRESULT                 hr              = S_OK;
    IAppHostProperty        *pProperty      = NULL;
    DWORD                   dwLength;
    VARIANT                 vPropertyValue;

    if ( ( pElement == NULL ) || ( pszPropertyName == NULL ) ||
         ( pException == NULL ) || ( ppszValue == NULL ) )
    {
        hr = E_INVALIDARG;
        goto Failure;
    }

    *ppszValue = NULL;

    hr = pElement->GetPropertyByName( pszPropertyName, &pProperty );
    if ( FAILED( hr ) ) goto Failure;
    if ( pProperty == NULL ) { hr = E_UNEXPECTED; goto Failure; }

    VariantInit( &vPropertyValue );
    hr = pProperty->get_Value( &vPropertyValue );
    if ( FAILED( hr ) ) goto Failure;

    *pException = NULL;
    hr = pProperty->get_Exception( pException );
    if ( FAILED( hr ) ) goto Failure;
    if ( ( *pException ) != NULL ) goto Failure;

    dwLength = SysStringLen( vPropertyValue.bstrVal );
    *ppszValue = new WCHAR[ dwLength + 1 ];
    if ( ( *ppszValue ) == NULL ) { hr = E_OUTOFMEMORY; goto Failure; }

    wcsncpy( *ppszValue, vPropertyValue.bstrVal, dwLength );
    (*ppszValue)[ dwLength ] = L'\0';

Failure:
    VariantClear( &vPropertyValue );
    if ( pProperty != NULL ) { pProperty->Release(); pProperty = NULL; }
    return hr;
}

MODSECURITY_STORED_CONTEXT::~MODSECURITY_STORED_CONTEXT()
{
    if ( m_pszPath != NULL )
    {
        delete [] m_pszPath;
        m_pszPath = NULL;
    }
}

MODSECURITY_STORED_CONTEXT::MODSECURITY_STORED_CONTEXT():
    m_bIsEnabled ( FALSE ),
    m_pszPath( NULL )
{
}

DWORD
MODSECURITY_STORED_CONTEXT::GlobalWideCharToMultiByte(
        WCHAR*  pSource,
        DWORD   dwLengthSource,
        CHAR**  ppszDestination,
        USHORT* pdwLengthDestination )
{
    DWORD       dwResult    = NULL;
    DWORD       dwCount     = 0;

    if ( ( pSource == NULL ) || ( ppszDestination == NULL ) || ( pdwLengthDestination == NULL ) )
    {
        dwResult = ERROR_INVALID_PARAMETER;
        goto Exit;
    }

    *pdwLengthDestination = 0;
    *ppszDestination     = NULL;

    dwCount = WideCharToMultiByte(
                    CP_ACP, 0, pSource, dwLengthSource + 1,
                    *ppszDestination, 0, NULL, NULL );

    if ( 0 == dwCount )
    {
        dwResult = GetLastError ();
        if ( dwResult == 0 ) dwResult = ERROR_INVALID_DATA;
        goto Exit;
    }

    *ppszDestination = new CHAR[ dwCount + 1 ];
    if ( NULL == ( *ppszDestination ) )
    {
        dwResult = ERROR_OUTOFMEMORY;
        goto Exit;
    }

    SecureZeroMemory( ( *ppszDestination ), ( dwCount + 1 ) * sizeof ( CHAR ) );

    if ( 0 == WideCharToMultiByte(
                CP_ACP, 0, pSource, dwLengthSource + 1,
                *ppszDestination, dwCount, NULL, NULL ) )
    {
        dwResult = GetLastError();
        goto Exit;
    }

    *pdwLengthDestination = ( USHORT )dwCount;

Exit:
    if ( dwResult != 0 )
    {
        if ( pdwLengthDestination != NULL ) *pdwLengthDestination = 0;
        if ( ppszDestination != NULL )
        {
            if ( ( *ppszDestination ) != NULL )
            {
                delete [] ( *ppszDestination );
                ( *ppszDestination ) = NULL;
            }
        }
    }
    return dwResult;
}

HRESULT
MODSECURITY_STORED_CONTEXT::GetConfig(
    IHttpContext *   pContext,
    MODSECURITY_STORED_CONTEXT ** ppModuleConfig
)
{
    HRESULT                          hr                 = S_OK;
    MODSECURITY_STORED_CONTEXT *    pModuleConfig       = NULL;
    IHttpModuleContextContainer *   pMetadataContainer = NULL;
    IAppHostConfigException *        pException         = NULL;

    pMetadataContainer = pContext->GetMetadata()->GetModuleContextContainer();

    if ( pMetadataContainer == NULL )
    {
        hr = E_UNEXPECTED;
        return hr;
    }

    pModuleConfig = (MODSECURITY_STORED_CONTEXT *)pMetadataContainer->GetModuleContext( g_pModuleContext );
    if ( pModuleConfig != NULL )
    {
        // Found cached config for this (unique) configuration path.
        *ppModuleConfig = pModuleConfig;
        return S_OK;
    }

    // First request (or first after a config change -- IIS discards the
    // stored context when a change notification arrives for this path).
    pModuleConfig = new MODSECURITY_STORED_CONTEXT();
    if ( pModuleConfig == NULL )
    {
        return E_OUTOFMEMORY;
    }

    hr = pModuleConfig->Initialize( pContext, &pException );
    if ( FAILED( hr )  || pException != NULL )
    {
        pModuleConfig->CleanupStoredContext();
        pModuleConfig = NULL;
        hr = E_UNEXPECTED;
        return hr;
    }

    hr = pMetadataContainer->SetModuleContext( pModuleConfig, g_pModuleContext );
    if ( FAILED( hr ) )
    {
        pModuleConfig->CleanupStoredContext();
        pModuleConfig = NULL;

        if ( hr == HRESULT_FROM_WIN32( ERROR_ALREADY_ASSIGNED ) )
        {
            *ppModuleConfig = (MODSECURITY_STORED_CONTEXT *)pMetadataContainer->GetModuleContext( g_pModuleContext );
            return S_OK;
        }
    }

    *ppModuleConfig = pModuleConfig;
    return hr;
}

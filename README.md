# ModSecurityIIS

A native **IIS 7+** module that runs [ModSecurity v3 (libModSecurity)](https://github.com/owasp-modsecurity/ModSecurity)
as a connector. Unlike the older v2 `iis/` connector (which compiled the whole
Apache C engine + `standalone/` shims into the DLL), this project links
libModSecurity and implements a thin IIS-side connector that feeds
`IHttpContext` / `IHttpRequest` / `IHttpResponse` data into the v3
`ModSecurity` / `Rules` / `Transaction` API.

## Architecture

- **IIS side** (`src/ModSecurityIIS.cpp`, `moduleconfig.cpp`, `mymodulefactory.h`):
  version-agnostic — `RegisterModule`, `CHttpModule` notifications
  (`OnBeginRequest` / `OnSendResponse` / `OnPostEndRequest`), the
  `IHttpStoredContext` request/metadata state, and COM config reading of the
  `system.webServer/ModSecurity` section (`enabled` + `configFile`).
- **Connector side** (`src/connector.cpp`): a global `modsecurity::ModSecurity`
  singleton configured with `setConnectorInformation(...)` and a
  `setServerLogCb(...)` callback that routes engine logs to the Windows Event
  Viewer; a per-`configFile` `modsecurity::RulesSet` cache; and per-request
  `modsecurity::Transaction` data flow + `intervention()` handling.

## Prerequisites (Windows build machine)

- Visual Studio 2019+ with "Desktop development with C++"
- [Conan](https://conan.io/) 2.x on PATH (the engine's Windows build fetches its
  dependencies via `build/win32/conanfile.txt`: pcre2, libxml2, curl, lua, yajl,
  poco, dirent, lmdb, libmaxminddb)
- Git on PATH (to init the engine's nested submodules `others/libinjection` and
  `others/mbedtls`)
- IIS installed (the IIS Server API header `httpserv.h` ships with the Windows SDK)

> Note: the engine is built **from the submodule with Conan**, not via vcpkg.
> The earlier vcpkg-based plan was dropped because libModSecurity's Windows
> CMake uses Conan, not vcpkg.

## Build

```bat
# 1. Initialize the libModSecurity v3 submodule (URL/branch are in .gitmodules).
git submodule update --init --recursive

# 2. Configure & build. The top-level CMake automatically:
#      - inits the engine's nested submodules (libinjection, mbedtls)
#      - runs `conan install` for the engine's deps
#      - builds libModSecurity (build/win32) into build/libmodsecurity_build
#      - builds modsecurityiis.dll and copies libModSecurity.dll next to it
cmake -B build -S . -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

This produces `build/src/Release/modsecurityiis.dll` (plus a copy of
`libModSecurity.dll` alongside it). Deploy both DLLs to the IIS modules
directory.

## Enable in IIS

1. Register the native module and add the `system.webServer/ModSecurity`
   section (schema in `ModSecurity.xml`).
2. In `web.config` / `applicationHost.config`:

   ```xml
   <system.webServer>
     <ModSecurity enabled="true" configFile="C:\inetpub\modsecurity.conf" />
   </system.webServer>
   ```

3. Point `configFile` at a normal ModSecurity v3 `modsecurity.conf` (plus CRS
   if desired). Note v3 rule semantics differ from v2 — adjust the config
   accordingly.

## API verification status

All ModSecurity call sites are implemented against the **verified** v3 API
(checked against the `v3/master` submodule headers, libModSecurity 3.0.16):

- `ModSecurity()` ctor; `setConnectorInformation(const std::string&)` (not
  `setConnector`); logging via `setServerLogCb(ModSecLogCb)` where
  `ModSecLogCb = void(*)(void*, const void*)` — there is **no** virtual `log()`
  to override, so the engine is used as a plain instance, not subclassed.
- Rules container is `modsecurity::RulesSet` (the public `Rules` subclass
  inherits from it); `loadFromUri(const char*)` returns `int` (`< 0` = error);
  `getParserError()` returns `std::string`.
- `Transaction(ModSecurity*, RulesSet*, void*)` — 3rd arg is the per-transaction
  log-callback data; `processConnection(const char*, int, const char*, int)`;
  `processURI(const char*, const char*, const char*)`;
  `addRequestHeader`/`addResponseHeader` (`unsigned char*` overloads);
  `processRequestHeaders()` / `processRequestBody()` /
  `appendRequestBody(const unsigned char*, size_t)`;
  `processResponseHeaders(int, const std::string&)`;
  `processResponseBody()` / `appendResponseBody(const unsigned char*, size_t)`;
  `processLogging()`.
- Intervention is read via `tx->intervention(ModSecurityIntervention*)` (returns
  `bool`); the struct carries `disruptive`, `status`, `url`, `log`, and must be
  released with `modsecurity::intervention::free(&it)`.
- CMake target produced by libModSecurity is `modsecurity` (used by
  `target_link_libraries` in `CMakeLists.txt`).

The `extern "C"` `msc_*` equivalents exist in the same headers if a pure-C
connector is ever needed, but this project intentionally uses the C++ API.

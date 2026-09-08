@echo off
rem Builds ModSecurityIIS.msi from a built module directory.
rem
rem Requires the WiX Toolset v3 (heat.exe, candle.exe, light.exe on PATH).
rem v3 is deliberate: it is the last line published without the Open Source
rem Maintenance Fee, and it is preinstalled on GitHub's windows runners.
rem
rem Usage: iis\build_msi.bat [dll-dir] [version] [out-dir]
rem   dll-dir  directory holding modsecurityiis.dll (default build\Release)
rem   version  MSI ProductVersion, x.y.z           (default 1.0.0)
rem   out-dir  where the .wixobj/.msi go           (default build\msi)

setlocal
for %%I in ("%~dp0..") do set "REPO=%%~fI"

set "DLLDIR=%~1"
if "%DLLDIR%"=="" set "DLLDIR=%REPO%\build\Release"
set "VERSION=%~2"
if "%VERSION%"=="" set "VERSION=1.0.0"
set "OUT=%~3"
if "%OUT%"=="" set "OUT=%REPO%\build\msi"

rem A trailing backslash inside a quoted -d value escapes the closing quote,
rem which makes the preprocessor swallow every argument after it.
if "%DLLDIR:~-1%"=="\" set "DLLDIR=%DLLDIR:~0,-1%"

if not exist "%DLLDIR%\modsecurityiis.dll" goto :NoDll

where heat.exe >nul 2>nul
if errorlevel 1 goto :NoWix

if not exist "%OUT%" mkdir "%OUT%"
if errorlevel 1 exit /b 1

rem Harvest every DLL the build produced into the ModSecDlls component group
rem so the package matches the build output instead of a hard-coded file list.
heat.exe dir "%DLLDIR%" -cg ModSecDlls -dr INETSRV -gg -sreg -srd ^
    -var var.DllDir -out "%OUT%\dlls.wxs"
if errorlevel 1 exit /b 1

candle.exe -nologo -arch x64 -dVersion=%VERSION% -dDllDir="%DLLDIR%" ^
    -dRepoRoot="%REPO%" -ext WixUtilExtension -ext WixUIExtension ^
    -out "%OUT%\" "%REPO%\iis\installer.wxs" "%OUT%\dlls.wxs"
if errorlevel 1 exit /b 1

light.exe -nologo -ext WixUtilExtension -ext WixUIExtension ^
    -out "%OUT%\ModSecurityIIS.msi" "%OUT%\installer.wixobj" "%OUT%\dlls.wixobj"
if errorlevel 1 exit /b 1

echo build_msi: %OUT%\ModSecurityIIS.msi
exit /b 0

:NoDll
echo build_msi: modsecurityiis.dll not found in "%DLLDIR%" - build the module first.
exit /b 1

:NoWix
echo build_msi: WiX Toolset v3 (heat/candle/light) not found on PATH.
exit /b 1

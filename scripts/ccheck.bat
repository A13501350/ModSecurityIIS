@echo off
rem Syntax-only compile check for the connector (no link / no engine build).
rem Usage: run from a VS developer prompt, or let vcvarsall initialize below.
set VS_ROOT=%ProgramFiles%\Microsoft Visual Studio
set VCVARSALL=
for /d %%V in ("%VS_ROOT%\*" ) do (
    if exist "%%V\VC\Auxiliary\Build\vcvarsall.bat" (
        set "VCVARSALL=%%V\VC\Auxiliary\Build\vcvarsall.bat"
        goto :found
    )
)
echo ERROR: vcvarsall.bat not found under %VS_ROOT%
exit /b 1
:found
call "%VCVARSALL%" x64
set SRC=M:\temp\ModSecurityIIS
set LM=%SRC%\libmodsecurity
cl /Zs /c /nologo /EHsc /std:c++17 ^
   /DVERSION_IIS /D MSC_LARGE_STREAM_INPUT /D WIN32_LEAN_AND_MEAN /D NOMINMAX ^
   /I %SRC%\src ^
   /I %LM%\headers ^
   /I %LM%\src ^
   %SRC%\src\ModSecurityIIS.cpp
if errorlevel 1 (echo COMPILE_FAILED & exit /b 1) else (echo COMPILE_OK)

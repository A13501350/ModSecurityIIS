@echo off
rem Syntax-only compile check for the connector (no link / no engine build).
rem Usage: run from a VS developer prompt, or let vcvarsall initialize below.
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
set SRC=M:\temp\ModSecurityIIS
set LM=%SRC%\libmodsecurity
cl /Zs /c /nologo /EHsc /std:c++17 ^
   /DVERSION_IIS /D MSC_LARGE_STREAM_INPUT /D WIN32_LEAN_AND_MEAN /D NOMINMAX ^
   /I %SRC%\src ^
   /I %LM%\headers ^
   /I %LM%\src ^
   %SRC%\src\ModSecurityIIS.cpp
if errorlevel 1 (echo COMPILE_FAILED & exit /b 1) else (echo COMPILE_OK)

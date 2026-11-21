@echo off
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto no_vs

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR goto no_vs

call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
rc /nologo app.rc
if errorlevel 1 goto build_failed
cl /nologo /W4 /O2 /std:c++17 /EHsc /utf-8 /DUNICODE /D_UNICODE PhoneLinkCode.cpp MailImap.cpp app.res /Fe:PhoneLinkCode.exe /link /SUBSYSTEM:WINDOWS user32.lib shell32.lib advapi32.lib ole32.lib ws2_32.lib crypt32.lib secur32.lib
if errorlevel 1 goto build_failed
echo Build OK: PhoneLinkCode.exe
exit /b 0

:no_vs
echo [ERROR] Visual Studio C++ tools not found.
exit /b 1

:build_failed
echo [ERROR] Build failed.
exit /b 1

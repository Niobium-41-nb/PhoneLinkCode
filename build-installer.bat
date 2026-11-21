@echo off
setlocal
set "ROOT=%~dp0"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto no_vs

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR goto no_vs

call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
if not exist "%ROOT%PhoneLinkCode.exe" goto no_app

cd /d "%ROOT%installer"
rc /nologo /fo installer.res installer.rc
if errorlevel 1 goto build_failed
cl /nologo /W4 /O2 /MT /std:c++17 /EHsc /utf-8 /DUNICODE /D_UNICODE Installer.cpp installer.res /Fe:"%ROOT%PhoneLinkCode-Setup-1.0.0.exe" /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib shell32.lib advapi32.lib ole32.lib uuid.lib
if errorlevel 1 goto build_failed
echo Build OK: PhoneLinkCode-Setup-1.0.0.exe
exit /b 0

:no_vs
echo [ERROR] Visual Studio C++ tools not found.
exit /b 1

:no_app
echo [ERROR] PhoneLinkCode.exe not found. Run build.bat first.
exit /b 1

:build_failed
echo [ERROR] Installer build failed.
exit /b 1

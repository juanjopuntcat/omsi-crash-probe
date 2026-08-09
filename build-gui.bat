@echo off
setlocal

rem Build the native x86 GUI with static MSVC runtime and embedded resources.
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"

where cl.exe >nul 2>nul
if errorlevel 1 (
  if not exist "%VCVARS%" exit /b 1
  call "%VCVARS%" x86
  if errorlevel 1 exit /b 1
)

rc.exe /nologo /fo OmsiCrashProbeGui.res OmsiCrashProbeGui.rc
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /EHsc /std:c++17 /MT OmsiCrashProbeGui.cpp PatchCore.cpp PatchManifest.cpp OmsiCrashProbeGui.res /Fe:OmsiCrashProbe.exe /link /SUBSYSTEM:WINDOWS bcrypt.lib comctl32.lib comdlg32.lib shell32.lib user32.lib gdi32.lib
if errorlevel 1 exit /b 1
echo Built OmsiCrashProbe.exe

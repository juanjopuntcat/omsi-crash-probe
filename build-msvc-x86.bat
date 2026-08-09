@echo off
setlocal

rem Build OmsiCrashProbe as a 32-bit DLL. OMSI 2 is a 32-bit process, so a
rem 64-bit DLL would fail to load even if compilation succeeded.

rem Default Visual Studio Build Tools 2019 environment script on this machine.
rem If cl.exe is already available, the script leaves the current environment
rem alone; otherwise it calls vcvarsall.bat x86.
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"

where cl.exe >nul 2>nul
if errorlevel 1 (
  if not exist "%VCVARS%" (
    echo cl.exe was not found.
    echo Open "x86 Native Tools Command Prompt for VS" and run this script again.
    exit /b 1
  )
  call "%VCVARS%" x86
  if errorlevel 1 exit /b 1
)

rem Warn if the user accidentally runs from an x64 tools prompt. The build may
rem still work if cl.exe is x86, but this warning catches the common mistake.
if /I not "%VSCMD_ARG_TGT_ARCH%"=="x86" (
  echo Warning: this does not look like an x86 Visual Studio prompt.
  echo OMSI 2 is 32-bit, so the DLL must be built for x86/Win32.
)

rem /LD builds a DLL. The .def file forces undecorated export names
rem PluginStart and PluginFinalize even though the functions use __stdcall.
cl.exe /nologo /W4 /EHsc /LD OmsiCrashProbe.cpp /link /DEF:OmsiCrashProbe.def /OUT:OmsiCrashProbe.dll
if errorlevel 1 exit /b 1

echo Built OmsiCrashProbe.dll
echo Copy OmsiCrashProbe.dll and OmsiCrashProbe.opl to the OMSI plugins folder.

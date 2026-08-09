@echo off
setlocal

rem Build the native inspection/patching CLI. It is deliberately read-only
rem until mutation and rollback reach parity with the tested PowerShell path.
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"

where cl.exe >nul 2>nul
if errorlevel 1 (
  if not exist "%VCVARS%" exit /b 1
  call "%VCVARS%" x86
  if errorlevel 1 exit /b 1
)

cl.exe /nologo /W4 /EHsc /std:c++17 /MT OmsiPatchTool.cpp PatchCore.cpp /Fe:OmsiPatchTool.exe bcrypt.lib shell32.lib
if errorlevel 1 exit /b 1
echo Built OmsiPatchTool.exe

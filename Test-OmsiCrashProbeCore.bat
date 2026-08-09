@echo off
setlocal

rem Compile and run white-box tests as x86 without producing repo artifacts.
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
set "TEST_EXE=%TEMP%\OmsiCrashProbeCoreTests.exe"
set "TEST_OBJ=%TEMP%\OmsiCrashProbeCoreTests.obj"

where cl.exe >nul 2>nul
if errorlevel 1 (
  if not exist "%VCVARS%" exit /b 1
  call "%VCVARS%" x86
  if errorlevel 1 exit /b 1
)

cl.exe /nologo /W4 /EHsc Test-OmsiCrashProbeCore.cpp /Fo"%TEST_OBJ%" /Fe"%TEST_EXE%"
if errorlevel 1 exit /b 1

"%TEST_EXE%"
set "TEST_RESULT=%ERRORLEVEL%"
del /q "%TEST_EXE%" "%TEST_OBJ%" >nul 2>nul
exit /b %TEST_RESULT%

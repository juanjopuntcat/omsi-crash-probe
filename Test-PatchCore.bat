@echo off
setlocal

rem Compile and run the native PE/patch-core tests without repo build products.
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
set "TEST_SUFFIX=%RANDOM%-%RANDOM%"
set "TEST_DIR=%TEMP%\OmsiPatchCoreTests-%TEST_SUFFIX%"
set "TEST_EXE=%TEST_DIR%\OmsiPatchCoreTests.exe"
mkdir "%TEST_DIR%" >nul 2>nul
if errorlevel 1 exit /b 1

where cl.exe >nul 2>nul
if errorlevel 1 (
  if not exist "%VCVARS%" exit /b 1
  call "%VCVARS%" x86
  if errorlevel 1 exit /b 1
)

cl.exe /nologo /W4 /EHsc /std:c++17 /MT Test-PatchCore.cpp PatchCore.cpp PatchManifest.cpp /Fo"%TEST_DIR%\\" /Fd"%TEST_DIR%\vc.pdb" /Fe"%TEST_EXE%" bcrypt.lib
if errorlevel 1 exit /b 1
if not exist "%TEST_EXE%" (
  echo Native patch core test executable was not produced.
  exit /b 1
)

echo Running native patch core tests...
rem Isolate execution from the game's working directory as well as its binaries.
pushd "%TEST_DIR%"
if errorlevel 1 exit /b 1
"%TEST_EXE%"
set "TEST_RESULT=%ERRORLEVEL%"
popd
echo Native patch core test exit code: %TEST_RESULT%
rmdir /s /q "%TEST_DIR%" >nul 2>nul
exit /b %TEST_RESULT%

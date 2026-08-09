@echo off
setlocal

rem Enable IMAGE_FILE_LARGE_ADDRESS_AWARE on a specific OMSI executable.
rem The caller is responsible for making and verifying a backup first.

if "%~1"=="" (
  echo Usage: %~nx0 "full-path-to-Omsi.exe"
  exit /b 2
)

set "OMSI_EXE=%~1"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"

if not exist "%OMSI_EXE%" (
  echo Omsi.exe was not found: %OMSI_EXE%
  exit /b 3
)

where editbin.exe >nul 2>nul
if errorlevel 1 (
  if not exist "%VCVARS%" (
    echo editbin.exe and vcvarsall.bat were not found.
    exit /b 4
  )
  call "%VCVARS%" x86
  if errorlevel 1 exit /b 5
)

editbin.exe /nologo /largeaddressaware "%OMSI_EXE%"
if errorlevel 1 exit /b 6

echo Large Address Aware enabled: %OMSI_EXE%

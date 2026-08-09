param(
    # OMSI root folder. Override this if the Steam library is somewhere else.
    [string]$OmsiRoot = "E:\SteamLibrary\steamapps\common\OMSI 2"
)

# Stop on the first failure so we do not partially install one file and leave the
# plugin in a confusing state.
$ErrorActionPreference = "Stop"

# OMSI loads plugins from <OMSI root>\plugins. The DLL and .opl are expected to
# live next to this installer script.
$pluginDir = Join-Path $OmsiRoot "plugins"
$dll = Join-Path $PSScriptRoot "OmsiCrashProbe.dll"
$opl = Join-Path $PSScriptRoot "OmsiCrashProbe.opl"

# Refuse to install if the DLL has not been built yet.
if (-not (Test-Path -LiteralPath $dll)) {
    throw "Build OmsiCrashProbe.dll first. Expected: $dll"
}

# The .opl descriptor tells OMSI which DLL to load.
if (-not (Test-Path -LiteralPath $opl)) {
    throw "Missing OmsiCrashProbe.opl: $opl"
}

# Avoid creating a fake plugins directory if the OMSI root path is wrong.
if (-not (Test-Path -LiteralPath $pluginDir)) {
    throw "OMSI plugins folder not found: $pluginDir"
}

# Copy both runtime files. Existing files are overwritten only after all checks
# above pass.
Copy-Item -LiteralPath $dll -Destination (Join-Path $pluginDir "OmsiCrashProbe.dll") -Force
Copy-Item -LiteralPath $opl -Destination (Join-Path $pluginDir "OmsiCrashProbe.opl") -Force

Write-Host "Installed OmsiCrashProbe to:"
Write-Host $pluginDir

param(
    [string]$OmsiExe = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\Omsi.exe')).Path,
    [string]$InputPath = (Join-Path $PSScriptRoot 'ghidra-raise-sites-decoded.tsv'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ghidra-raise-sites-resolved.tsv')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $OmsiExe)) {
    throw "Omsi.exe not found: $OmsiExe"
}

if (-not (Test-Path -LiteralPath $InputPath)) {
    throw "Input TSV not found: $InputPath"
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class OmsiResourceNative {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int LoadString(IntPtr hInstance, uint uID, StringBuilder lpBuffer, int cchBufferMax);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool FreeLibrary(IntPtr hModule);
}
'@

$loadLibraryAsDataFile = 0x00000002
$module = [OmsiResourceNative]::LoadLibraryEx($OmsiExe, [IntPtr]::Zero, $loadLibraryAsDataFile)
if ($module -eq [IntPtr]::Zero) {
    throw "LoadLibraryEx failed for resources: $OmsiExe"
}

try {
    $rows = Import-Csv -LiteralPath $InputPath -Delimiter "`t"
    foreach ($row in $rows) {
        if (-not $row.messageResourceId) {
            continue
        }

        $rawId = $row.messageResourceId.Trim()
        $resourceId = if ($rawId.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
            [Convert]::ToUInt32($rawId.Substring(2), 16)
        }
        else {
            [Convert]::ToUInt32($rawId, 10)
        }

        $buffer = New-Object System.Text.StringBuilder 2048
        $length = [OmsiResourceNative]::LoadString($module, $resourceId, $buffer, $buffer.Capacity)
        if ($length -gt 0) {
            $row.messageText = $buffer.ToString()
        }
    }

    $rows | Export-Csv -LiteralPath $OutputPath -Delimiter "`t" -NoTypeInformation -Encoding UTF8
}
finally {
    [OmsiResourceNative]::FreeLibrary($module) | Out-Null
}

Write-Host "Wrote $OutputPath"

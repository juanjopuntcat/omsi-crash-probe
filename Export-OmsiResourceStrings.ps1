param(
    [string]$OmsiExe = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\Omsi.exe')).Path,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'omsi-resource-strings.tsv'),
    [int]$FirstId = 1,
    [int]$LastId = 65535
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $OmsiExe)) {
    throw "Omsi.exe not found: $OmsiExe"
}

# Load only the PE resource table. This does not execute OMSI code; Windows maps
# the executable as data so LoadStringW can resolve Delphi resource strings.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class OmsiResourceStringNative {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int LoadString(IntPtr hInstance, uint uID, StringBuilder lpBuffer, int cchBufferMax);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool FreeLibrary(IntPtr hModule);
}
'@

$loadLibraryAsDataFile = 0x00000002
$module = [OmsiResourceStringNative]::LoadLibraryEx($OmsiExe, [IntPtr]::Zero, $loadLibraryAsDataFile)
if ($module -eq [IntPtr]::Zero) {
    throw "LoadLibraryEx failed for resources: $OmsiExe"
}

try {
    $rows = New-Object System.Collections.Generic.List[object]

    # Delphi exception messages are stored as numbered string resources. Probe
    # the full 16-bit ID space and keep only IDs that Windows can resolve.
    for ($id = $FirstId; $id -le $LastId; ++$id) {
        $buffer = New-Object System.Text.StringBuilder 4096
        $length = [OmsiResourceStringNative]::LoadString($module, [uint32]$id, $buffer, $buffer.Capacity)
        if ($length -le 0) {
            continue
        }

        $rows.Add([pscustomobject]@{
            IdHex = ('0x{0:X4}' -f $id)
            IdDecimal = $id
            Length = $length
            Text = $buffer.ToString()
        })
    }

    $rows | Export-Csv -LiteralPath $OutputPath -Delimiter "`t" -NoTypeInformation -Encoding UTF8
}
finally {
    [OmsiResourceStringNative]::FreeLibrary($module) | Out-Null
}

Write-Host "Wrote $OutputPath"

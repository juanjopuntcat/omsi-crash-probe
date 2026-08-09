param(
    [string]$OmsiExe = (Join-Path (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path 'Omsi.exe'),
    [string]$StringXrefsPath = (Join-Path $PSScriptRoot 'ghidra-omsi-string-xrefs.tsv'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'omsi-string-pointer-refs.tsv'),
    [uint32]$ImageBase = 0x00400000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $OmsiExe)) {
    throw "Omsi.exe not found: $OmsiExe"
}

if (-not (Test-Path -LiteralPath $StringXrefsPath)) {
    throw "String xrefs TSV not found. Run Run-GhidraOmsiStringXrefs.ps1 first: $StringXrefsPath"
}

function ConvertTo-LittleEndianBytes {
    param([uint32]$Value)

    return [byte[]]@(
        [byte]($Value -band 0xff),
        [byte](($Value -shr 8) -band 0xff),
        [byte](($Value -shr 16) -band 0xff),
        [byte](($Value -shr 24) -band 0xff)
    )
}

function Find-PatternOffsets {
    param(
        [byte[]]$Bytes,
        [byte[]]$Pattern
    )

    $matches = New-Object System.Collections.Generic.List[uint32]
    $last = $Bytes.Length - $Pattern.Length
    for ($i = 0; $i -le $last; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $Pattern.Length; $j++) {
            if ($Bytes[$i + $j] -ne $Pattern[$j]) {
                $ok = $false
                break
            }
        }
        if ($ok) {
            $matches.Add([uint32]$i)
        }
    }
    return $matches
}

$bytes = [System.IO.File]::ReadAllBytes($OmsiExe)
$targets = Import-Csv -LiteralPath $StringXrefsPath -Delimiter "`t" |
    Where-Object { $_.xrefKind -eq 'none' } |
    Sort-Object target, stringRva -Unique

$rows = New-Object System.Collections.Generic.List[object]
foreach ($target in $targets) {
    $rva = [Convert]::ToUInt32(($target.stringRva -replace '^0x', ''), 16)
    $va = $ImageBase + $rva
    $pattern = ConvertTo-LittleEndianBytes -Value $va
    $offsets = Find-PatternOffsets -Bytes $bytes -Pattern $pattern

    foreach ($offset in $offsets) {
        $rows.Add([pscustomobject]@{
            Target = $target.target
            StringRva = ('0x{0:X8}' -f $rva)
            StringVa = ('0x{0:X8}' -f $va)
            PointerFileOffset = ('0x{0:X8}' -f $offset)
            PointerRvaApprox = ('0x{0:X8}' -f $offset)
            Text = $target.stringText
        })
    }
}

$rows | Export-Csv -LiteralPath $OutputPath -Delimiter "`t" -NoTypeInformation -Encoding UTF8
Write-Host "Targets scanned: $($targets.Count)"
Write-Host "Pointer references found: $($rows.Count)"
Write-Host "Wrote $OutputPath"

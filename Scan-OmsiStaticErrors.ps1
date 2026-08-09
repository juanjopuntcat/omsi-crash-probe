param(
    [string]$OmsiRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$OutDir = $PSScriptRoot,
    [int]$MinimumStringLength = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Keep this aligned with the project boundary agreed for static inspection.
$excludedDirectories = @(
    'SceneryObjects',
    'Sceneryobjects',
    'Splines',
    'maps',
    'OmniNavigation',
    'OmsiCrashProbe',
    'SDK',
    'Vehicles',
    'Addons'
)

$binaryExtensions = @(
    '.exe',
    '.dll',
    '.bpl',
    '.ocx'
)

$excludedRelativeFiles = @(
    'plugins\OmsiCrashProbe.dll'
)

function Get-RelativePathFromRoot {
    param([string]$Path)

    $rootPath = [System.IO.Path]::GetFullPath($OmsiRoot).TrimEnd('\') + '\'
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith($rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($rootPath.Length)
    }
    return $fullPath
}

# These tokens are intentionally broad. The first pass should find the embedded
# catalog of runtime/system/DirectX/Delphi errors, not decide yet which are bugs.
$interestingTokens = @(
    'Argument',
    'Adresse',
    'Address',
    'Arbeitsspeicher',
    'Bereich',
    'Bitmap',
    'bounds',
    'C06D',
    'context',
    'Direct3D',
    'Direct-3D',
    'D3DERR',
    'Device',
    'Division',
    'durch Null',
    'EAccessViolation',
    'EConvert',
    'EInvalid',
    'EOutOfMemory',
    'EZeroDivide',
    'Exception',
    'Fatal',
    'Fehler',
    'Gleitkomma',
    'Hilfe',
    'HRESULT',
    'Index',
    'invalid',
    'kontext',
    'Listenindex',
    'memory',
    'Out of',
    'resource',
    'Speicher',
    'Systemfehler',
    'ungültig',
    'Ungueltig',
    'Unknown',
    'Zugriff'
)

function Test-IsExcludedPath {
    param([string]$Path)

    $relative = Get-RelativePathFromRoot -Path $Path
    $parts = $relative -split '[\\/]'
    foreach ($part in $parts) {
        foreach ($excluded in $excludedDirectories) {
            if ([string]::Equals($part, $excluded, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }
    return $false
}

function Test-IsExcludedFile {
    param([string]$Path)

    $relative = Get-RelativePathFromRoot -Path $Path
    foreach ($excluded in $excludedRelativeFiles) {
        if ([string]::Equals($relative, $excluded, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-AsciiStrings {
    param(
        [byte[]]$Bytes,
        [int]$MinimumLength
    )

    $builder = New-Object System.Text.StringBuilder
    foreach ($byte in $Bytes) {
        $isPrintable = ($byte -ge 32 -and $byte -le 126) -or ($byte -ge 160)
        if ($isPrintable) {
            [void]$builder.Append([char]$byte)
            continue
        }

        if ($builder.Length -ge $MinimumLength) {
            $builder.ToString()
        }
        [void]$builder.Clear()
    }

    if ($builder.Length -ge $MinimumLength) {
        $builder.ToString()
    }
}

function Get-UnicodeLeStrings {
    param(
        [byte[]]$Bytes,
        [int]$MinimumLength
    )

    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt ($Bytes.Length - 1); $i += 2) {
        $low = $Bytes[$i]
        $high = $Bytes[$i + 1]
        $code = $low -bor ($high -shl 8)
        $isPrintable = ($code -ge 32 -and $code -le 126) -or ($code -ge 160 -and $code -le 65533)
        if ($isPrintable) {
            [void]$builder.Append([char]$code)
            continue
        }

        if ($builder.Length -ge $MinimumLength) {
            $builder.ToString()
        }
        [void]$builder.Clear()
    }

    if ($builder.Length -ge $MinimumLength) {
        $builder.ToString()
    }
}

function Test-IsInterestingString {
    param([string]$Text)

    foreach ($token in $interestingTokens) {
        if ($Text.IndexOf($token, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Normalize-LogString {
    param([string]$Text)

    $normalized = $Text -replace '\s+', ' '
    if ($normalized.Length -gt 500) {
        return $normalized.Substring(0, 500)
    }
    return $normalized
}

$inventoryPath = Join-Path $OutDir 'static-binary-inventory.tsv'
$stringsPath = Join-Path $OutDir 'static-error-strings.tsv'
$summaryPath = Join-Path $OutDir 'static-error-summary.md'

$binaries = Get-ChildItem -LiteralPath $OmsiRoot -Recurse -File |
    Where-Object {
        ($binaryExtensions -contains $_.Extension.ToLowerInvariant()) -and
        -not (Test-IsExcludedPath -Path $_.FullName) -and
        -not (Test-IsExcludedFile -Path $_.FullName)
    } |
    Sort-Object FullName

$inventory = foreach ($file in $binaries) {
    [pscustomobject]@{
        RelativePath = Get-RelativePathFromRoot -Path $file.FullName
        Length = $file.Length
        LastWriteTime = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        SHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash
    }
}

$matches = New-Object System.Collections.Generic.List[object]
foreach ($file in $binaries) {
    $relativePath = Get-RelativePathFromRoot -Path $file.FullName
    Write-Host "Scanning $relativePath"

    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($encoding in @('ansi', 'utf16le')) {
        if ($encoding -eq 'ansi') {
            $strings = Get-AsciiStrings -Bytes $bytes -MinimumLength $MinimumStringLength
        }
        else {
            $strings = Get-UnicodeLeStrings -Bytes $bytes -MinimumLength $MinimumStringLength
        }

        foreach ($text in $strings) {
            if (-not (Test-IsInterestingString -Text $text)) {
                continue
            }

            $normalized = Normalize-LogString -Text $text
            $key = "$encoding`t$normalized"
            if (-not $seen.Add($key)) {
                continue
            }

            $matches.Add([pscustomobject]@{
                RelativePath = $relativePath
                Encoding = $encoding
                Text = $normalized
            })
        }
    }
}

$inventory | Export-Csv -LiteralPath $inventoryPath -Delimiter "`t" -NoTypeInformation -Encoding UTF8
$matches | Sort-Object RelativePath, Text | Export-Csv -LiteralPath $stringsPath -Delimiter "`t" -NoTypeInformation -Encoding UTF8

$byFile = $matches |
    Group-Object RelativePath |
    Sort-Object @{ Expression = 'Count'; Descending = $true }, Name |
    Select-Object Name, Count

$summary = New-Object System.Collections.Generic.List[string]
$summary.Add('# OMSI Static Error String Summary')
$summary.Add('')
$summary.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$summary.Add("Root: $OmsiRoot")
$summary.Add('')
$summary.Add('Excluded directories: ' + ($excludedDirectories -join ', '))
$summary.Add('')
$summary.Add("Binaries scanned: $($binaries.Count)")
$summary.Add("Interesting strings found: $($matches.Count)")
$summary.Add('')
$summary.Add('## Matches By File')
$summary.Add('')
foreach ($row in $byFile) {
    $summary.Add("- $($row.Name): $($row.Count)")
}
$summary.Add('')
$summary.Add('## Output Files')
$summary.Add('')
$summary.Add("- static-binary-inventory.tsv")
$summary.Add("- static-error-strings.tsv")

Set-Content -LiteralPath $summaryPath -Value $summary -Encoding UTF8

Write-Host "Wrote $inventoryPath"
Write-Host "Wrote $stringsPath"
Write-Host "Wrote $summaryPath"

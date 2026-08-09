param(
    [string]$OmsiRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$ProbeLogPath = (Join-Path (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path 'probe.log'),
    [string]$LogfilePath = (Join-Path (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path 'logfile.txt'),
    [string]$KnownRvaSourcePath = (Join-Path $PSScriptRoot 'OmsiCrashProbe.cpp'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'last-crash-session-analysis.md'),
    [int]$Top = 12
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This script is intentionally a log analyzer, not a scanner. It reads only the
# current OMSI logfile, the probe log, and our source-side KnownRva table.
$forbiddenRoots = @('SceneryObjects', 'Sceneryobjects', 'Splines', 'maps', 'OmniNavigation', 'Vehicles', 'Addons', 'SDK')

function New-Counter {
    New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::OrdinalIgnoreCase)
}

function Add-Count {
    param(
        [System.Collections.Generic.Dictionary[string,int]]$Counter,
        [string]$Key,
        [int]$Amount = 1
    )

    if ([string]::IsNullOrWhiteSpace($Key)) {
        return
    }

    if ($Counter.ContainsKey($Key)) {
        $Counter[$Key] += $Amount
    }
    else {
        $Counter[$Key] = $Amount
    }
}

function Get-TopCounts {
    param(
        [System.Collections.Generic.Dictionary[string,int]]$Counter,
        [int]$Limit = $Top
    )

    $Counter.GetEnumerator() |
        Sort-Object @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key'; Descending = $false } |
        Select-Object -First $Limit
}

function Get-CounterSum {
    param([System.Collections.Generic.Dictionary[string,int]]$Counter)

    if ($Counter.Count -eq 0) {
        return 0
    }

    return ($Counter.Values | Measure-Object -Sum).Sum
}

function Get-OptionalUInt64 {
    param(
        [hashtable]$MatchTable,
        [string]$Name
    )

    if ($MatchTable.ContainsKey($Name) -and -not [string]::IsNullOrWhiteSpace($MatchTable[$Name])) {
        return [UInt64]$MatchTable[$Name]
    }

    return [UInt64]0
}

function Escape-Markdown {
    param([string]$Text)

    if ($null -eq $Text) {
        return ''
    }

    $Text.Replace('|', '\|')
}

function Convert-HexToUInt64 {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return 0
    }

    $clean = $Text.Trim()
    if ($clean.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
        $clean = $clean.Substring(2)
    }

    return [Convert]::ToUInt64($clean, 16)
}

function Convert-TimeOfDayToSeconds {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    if ($Text -notmatch '(?<hour>\d\d):(?<minute>\d\d):(?<second>\d\d)') {
        return $null
    }

    return ([int]$Matches.hour * 3600) + ([int]$Matches.minute * 60) + [int]$Matches.second
}

function Add-MarkdownTable {
    param(
        [System.Collections.Generic.List[string]]$Lines,
        [string[]]$Headers,
        [object[]]$Rows
    )

    $tableRows = @($Rows)
    $rowCount = ($tableRows | Measure-Object).Count
    if ($rowCount -eq 0) {
        $Lines.Add('_None found._')
        $Lines.Add('')
        return
    }

    $Lines.Add('| ' + (($Headers | ForEach-Object { Escape-Markdown $_ }) -join ' | ') + ' |')
    $Lines.Add('| ' + (($Headers | ForEach-Object { '---' }) -join ' | ') + ' |')
    foreach ($row in $tableRows) {
        $values = foreach ($header in $Headers) {
            Escape-Markdown ([string]$row.$header)
        }
        $Lines.Add('| ' + ($values -join ' | ') + ' |')
    }
    $Lines.Add('')
}

function Import-KnownRvaTable {
    param([string]$Path)

    $items = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Test-Path -LiteralPath $Path)) {
        return $items
    }

    # Parse rows like:
    # {0x00070890, 0x000708B2, "Bitmap invalid helper", "note", true},
    $pattern = '^\s*\{0x(?<start>[0-9A-Fa-f]+),\s*0x(?<end>[0-9A-Fa-f]+),\s*"(?<system>(?:[^"\\]|\\.)*)",\s*"(?<note>(?:[^"\\]|\\.)*)",\s*(?<caller>true|false)\},'
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -notmatch $pattern) {
            continue
        }

        $items.Add([pscustomobject]@{
            Start = Convert-HexToUInt64 $Matches.start
            End = Convert-HexToUInt64 $Matches.end
            System = $Matches.system
            Note = $Matches.note
            CallerContextMatters = [bool]::Parse($Matches.caller)
        })
    }

    return $items
}

function Find-KnownRva {
    param(
        [object[]]$KnownRvas,
        [UInt64]$Rva
    )

    foreach ($item in $KnownRvas) {
        if ($Rva -ge $item.Start -and $Rva -le $item.End) {
            return $item
        }
    }

    return $null
}

function Format-Rva {
    param([UInt64]$Rva)

    if ($Rva -eq 0) {
        return ''
    }

    return '0x{0:X8}' -f $Rva
}

function Test-GenericRuntimeKnownText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return $Text -match '(?i)Delphi|helper|exception class|exception raiser|constructor|raise site'
}

function Get-ProbableOwnerFrame {
    param(
        [UInt64]$Omsi1,
        [object]$Known1,
        [UInt64]$Omsi2,
        [object]$Known2
    )

    $ownerRva = $Omsi1
    $ownerKnown = if ($Known1) { $Known1.System } else { '' }
    $helperRva = 0
    $helperKnown = ''
    $reason = 'first OMSI stack candidate'
    $known1IsGeneric = $Known1 -and (Test-GenericRuntimeKnownText $Known1.System)
    $known2IsGeneric = $Known2 -and (Test-GenericRuntimeKnownText $Known2.System)

    if ($known1IsGeneric) {
        $helperRva = $Omsi1
        $helperKnown = $Known1.System

        if ($Omsi2 -ne 0 -and -not $known2IsGeneric) {
            $ownerRva = $Omsi2
            $ownerKnown = if ($Known2) { $Known2.System } else { '' }
            $reason = 'first frame is helper; using next OMSI stack candidate'
        }
        elseif ($Omsi2 -ne 0) {
            $ownerRva = $Omsi2
            $ownerKnown = 'unresolved helper chain'
            $reason = 'first two OMSI stack candidates are generic helpers'
        }
        else {
            $reason = 'helper frame with no next OMSI stack candidate'
        }
    }
    elseif ($Known1) {
        $reason = 'first frame has useful KnownRva label'
    }
    elseif ($Omsi1 -eq 0 -and $Omsi2 -ne 0) {
        $ownerRva = $Omsi2
        $ownerKnown = if ($Known2) { $Known2.System } else { '' }
        $reason = 'second OMSI stack candidate only'
    }

    [pscustomobject]@{
        OwnerRva = Format-Rva $ownerRva
        OwnerKnown = $ownerKnown
        HelperRva = Format-Rva $helperRva
        HelperKnown = $helperKnown
        Reason = $reason
    }
}

function Get-Family {
    param(
        [string]$Text,
        [string]$Code = ''
    )

    $combined = ''
    if ($null -ne $Text) {
        $combined += $Text
    }
    $combined += ' '
    if ($null -ne $Code) {
        $combined += $Code
    }
    $haystack = $combined.ToLowerInvariant()

    if ($haystack -match 'direct3d|direct9|d3d|device lost|device reset|e_outofmemory') {
        return 'Direct3D / texture memory'
    }
    if ($haystack -match 'bitmap|image|bild|graf|gdi|window device|system resources|systemressourcen') {
        return 'Graphics / bitmap / GDI resources'
    }
    if ($haystack -match 'stream|lesefehler|schreibfehler|file|datei') {
        return 'Stream / file IO'
    }
    if ($haystack -match 'speicher|memory|system-error|systemfehler|code 8|not enough') {
        return 'Memory / resource pressure'
    }
    if ($haystack -match 'float|gleitkomma|invalid-float|zero divide|division') {
        return 'Numeric / floating point'
    }
    if ($haystack -match 'integer|invalid-integer') {
        return 'Numeric / integer conversion'
    }
    if ($haystack -match 'range|bereich|list|index|argument') {
        return 'Bounds / list / argument checks'
    }
    if ($haystack -match 'accessviolation|zugriffsverletzung|c0000005') {
        return 'Access violation'
    }
    if ($haystack -match 'illegalinstruction|c000001d') {
        return 'Illegal instruction'
    }

    return 'Other / unknown'
}

function Get-SystemErrorCode8Bucket {
    param([string]$Context)

    $text = if ($null -eq $Context) { '' } else { $Context.ToLowerInvariant() }

    if ($text -match 'killnotneeded|\bknnc\b|notneededbuses|notneededcars') {
        return 'AI bus cleanup / memory management'
    }
    if ($text -match 'map\.translate|\btuv\b|refreshobject|kacheln') {
        return 'map translation / visibility update'
    }
    if ($text -match 'cv\.calculate|vehicle|vehicles\\|\.bus|\.ovh|\.o3d|script|var|plugin|sound|wav') {
        return 'vehicle / script / asset owner'
    }
    if ($text -match 'texture|textur|direct|d3d|grafik|bitmap|image|bild|gdi') {
        return 'graphics / texture / GDI pressure'
    }
    if ($text -match 'svs|system|resource|ressource|speicher|memory') {
        return 'system/resource pressure'
    }
    if ([string]::IsNullOrWhiteSpace($text)) {
        return 'unknown'
    }

    return 'other context'
}

function Get-KnownErrorCatalog {
    # These patterns codify the recurring OMSI errors collected from local
    # sessions, public logfiles, and static string analysis. The Origin field is
    # a triage hint, not proof of root cause.
    @(
        [pscustomobject]@{
            Id = 'access-violation-omsi'
            Match = '(?i)Zugriffsverletzung.*Omsi\.exe|AccessViolation.*Omsi\.exe'
            Family = 'Access violation'
            Origin = 'OMSI engine / Delphi runtime'
            Next = 'Use module+RVA, stack candidates, and KnownRva labels.'
        },
        [pscustomobject]@{
            Id = 'access-violation-null-read'
            Match = '(?i)Zugriffsverletzung.*Lesen von Adresse 0{8}|Access violation.*read.*0x?0{8}'
            Family = 'Access violation'
            Origin = 'Null or near-null pointer read'
            Next = 'Prioritize caller context; helper RVAs are often secondary.'
        },
        [pscustomobject]@{
            Id = 'access-violation-directsound'
            Match = '(?i)Zugriffsverletzung.*DSound\.dll|Access violation.*DSound\.dll'
            Family = 'Audio / DirectSound boundary'
            Origin = 'DirectSound DLL or OMSI audio caller'
            Next = 'Correlate with sound loading, device changes, and caller stack.'
        },
        [pscustomobject]@{
            Id = 'access-violation-d3d-driver'
            Match = '(?i)Zugriffsverletzung.*(d3d9|nvd3dum)\.dll|Access violation.*(d3d9|nvd3dum)\.dll'
            Family = 'Direct3D / driver boundary'
            Origin = 'Direct3D runtime/driver called by OMSI'
            Next = 'Correlate with texture pressure, device reset, and HRESULTs.'
        },
        [pscustomobject]@{
            Id = 'direct3d-reset'
            Match = '(?i)Direct-?3D-Device-Reset schlug fehl|Direct3D-Device lost|D3DERR_DEVICELOST|D3DERR_DEVICENOTRESET|D3DERR_INVALIDCALL'
            Family = 'Direct3D device lost/reset'
            Origin = 'OMSI Direct3D device reset path'
            Next = 'Check reset RVA labels, window focus/device loss, and resources.'
        },
        [pscustomobject]@{
            Id = 'direct3d-memory'
            Match = '(?i)D3DERR_OUTOFVIDEOMEMORY|E_OUTOFMEMORY|Texturladen - Direct9 Error|DirectX/texture out of memory'
            Family = 'Direct3D / texture memory'
            Origin = 'D3DX texture/image allocation path'
            Next = 'Compare with VAS largest-free block and texture failed paths.'
        },
        [pscustomobject]@{
            Id = 'texture-failed'
            Match = '(?i)Texture ".+" failed!'
            Family = 'Texture load failure'
            Origin = 'OMSI texture manager / D3DX callee'
            Next = 'Use the path as evidence only; do not scan asset folders.'
        },
        [pscustomobject]@{
            Id = 'bitmap-image-format'
            Match = '(?i)Bitmap ist|Unbekannte Bilddatei|ungueltiges Bild|ung.ltiges Bild|unknown image'
            Family = 'Bitmap / image format'
            Origin = 'Bitmap loader, image parser, or GDI allocation path'
            Next = 'Correlate with bitmap RVAs, Systemfehler Code 8, and GDI count.'
        },
        [pscustomobject]@{
            Id = 'system-error-code-8'
            Match = '(?i)Systemfehler\.\s+Code:\s*8'
            Family = 'Memory / resource pressure'
            Origin = 'Win32 GetLastError path surfaced by OMSI'
            Next = 'Check private memory, VAS fragmentation, GDI, and USER counts.'
        },
        [pscustomobject]@{
            Id = 'omsi-out-of-memory'
            Match = '(?i)Zu wenig Arbeitsspeicher|Out of memory|insufficient memory'
            Family = 'Memory / resource pressure'
            Origin = 'OMSI, Delphi runtime, or D3DX allocation failure'
            Next = 'Use surrounding function tag such as P.KillNotNeededBuses.'
        },
        [pscustomobject]@{
            Id = 'bounds-list-range'
            Match = '(?i)Fehler bei Bereich|Bereichspr|Argument au.erhalb|Listenindex|array bounds'
            Family = 'Bounds / list / argument checks'
            Origin = 'Delphi range/list/argument guard'
            Next = 'Use attached OMSI context tag and caller stack if present.'
        },
        [pscustomobject]@{
            Id = 'numeric-float'
            Match = '(?i)Gleitkommawert|Gleitkommadivision|floating|ZeroDivide|division durch null'
            Family = 'Numeric / floating point'
            Origin = 'Delphi numeric conversion or arithmetic path'
            Next = 'Distinguish bad input conversion from true arithmetic divide.'
        },
        [pscustomobject]@{
            Id = 'invalid-variable-name'
            Match = '(?i)Variablenname.*ung(?:.|ue)ltig|invalid variable'
            Family = 'Script / variable binding'
            Origin = 'OMSI script command parser'
            Next = 'Use command text and vehicle path already present in logfile.'
        },
        [pscustomobject]@{
            Id = 'external-c06d007e'
            Match = '(?i)C06D007E|requested resource is in use|angeforderte Ressource'
            Family = 'External / resource in use'
            Origin = 'External exception or OS resource contention'
            Next = 'Correlate with module, file access, plugins, and timing.'
        },
        [pscustomobject]@{
            Id = 'missing-context-help'
            Match = '(?i)Keine kontextsensitive Hilfe'
            Family = 'Low-priority UI/help runtime'
            Origin = 'Delphi/VCL help system'
            Next = 'Usually deprioritize unless it appears beside a fatal error.'
        }
    )
}

function Analyze-Logfile {
    param(
        [string]$Path,
        [object[]]$KnownErrorCatalog
    )

    $result = [ordered]@{
        Exists = Test-Path -LiteralPath $Path
        Path = $Path
        LineCount = 0
        Categories = New-Counter
        KnownErrorPatterns = New-Counter
        ErrorTexts = New-Counter
        SystemErrorContexts = New-Counter
        SystemErrorBuckets = New-Counter
        SystemErrorPrecursors = New-Object 'System.Collections.Generic.List[object]'
        SystemErrorPrecursorsCaptured = $false
        TextureFailures = New-Counter
        Direct9TextureErrors = New-Counter
        Direct3DResetErrors = New-Counter
        NumericScriptContexts = New-Object 'System.Collections.Generic.List[object]'
        TimeFirst = ''
        TimeLast = ''
        SystemErrorFirst = ''
        SystemErrorLast = ''
        TextureFailureFirst = ''
        TextureFailureLast = ''
        Direct9TextureErrorFirst = ''
        Direct9TextureErrorLast = ''
        Direct3DResetFirst = ''
        Direct3DResetLast = ''
    }

    if (-not $result.Exists) {
        return [pscustomobject]$result
    }

    $previousWasSystemCode8 = $false
    $pendingSystemCode8Time = ''
    $recentLogLines = New-Object 'System.Collections.Generic.Queue[object]'
    $logLines = @(Get-Content -LiteralPath $Path)
    for ($lineIndex = 0; $lineIndex -lt $logLines.Count; ++$lineIndex) {
        $line = $logLines[$lineIndex]
        $result.LineCount += 1

        $lineTime = ''
        if ($line -match '^\s*\d+\s+(?<time>\d\d:\d\d:\d\d)\s+-') {
            $lineTime = $Matches.time
            if (-not $result.TimeFirst) {
                $result.TimeFirst = $lineTime
            }
            $result.TimeLast = $lineTime
        }

        if ($line -match '(?i)\b(Error|Warning|Fatal Error|Direct9 Error)\b') {
            Add-Count $result.ErrorTexts ($line.Trim())
        }

        $categoryHits = @()
        if ($line -match '(?i)Systemfehler\.\s+Code:\s*8') { $categoryHits += 'Systemfehler Code 8 / OS memory resources' }
        if ($line -match '(?i)E_OUTOFMEMORY|D3DERR_OUTOFVIDEOMEMORY|out of memory') { $categoryHits += 'DirectX/texture out of memory' }
        if ($line -match '(?i)Texturladen - Direct9 Error') { $categoryHits += 'Texture load Direct9 error' }
        if ($line -match '(?i)Texture ".+" failed!') { $categoryHits += 'Texture failed' }
        if ($line -match '(?i)Direct3D-Device lost|Direct-3D-Device-Reset|D3DERR_DEVICELOST|D3DERR_INVALIDCALL') { $categoryHits += 'Direct3D device lost/reset' }
        if ($line -match '(?i)Zugriffsverletzung|Access violation|AccessViolation') { $categoryHits += 'Access violation' }
        if ($line -match '(?i)Fehler bei Bereich|Bereichspr|Argument ausserhalb|Argument au.erhalb|Listenindex') { $categoryHits += 'Bounds/list/range checks' }
        if ($line -match '(?i)Gleitkomma|floating|division durch null|ZeroDivide') { $categoryHits += 'Floating point/conversion' }
        if ($line -match '(?i)Variablenname.*ung(?:.|ue)ltig|invalid variable|SC_ErrorInCommand') { $categoryHits += 'Script variable/command' }
        if ($line -match '(?i)Bitmap ist|ungueltiges Bild|ung.ltiges Bild|Unbekannte Bilddatei') { $categoryHits += 'Bitmap/image format' }
        if ($line -match '(?i)The requested resource is in use|angeforderte Ressource') { $categoryHits += 'Resource in use' }

        foreach ($category in $categoryHits) {
            Add-Count $result.Categories $category
        }

        foreach ($knownError in $KnownErrorCatalog) {
            if ($line -match $knownError.Match) {
                Add-Count $result.KnownErrorPatterns $knownError.Id
            }
        }

        if ($result.NumericScriptContexts.Count -lt 20 -and
            $line -match '(?i)Gleitkommawert|Gleitkommadivision|ZeroDivide|division durch null|Variablenname.*ung(?:.|ue)ltig|invalid variable|SC_ErrorInCommand') {
            $contextStart = [math]::Max(0, $lineIndex - 2)
            $contextEnd = [math]::Min($logLines.Count - 1, $lineIndex + 2)
            $nearby = for ($contextIndex = $contextStart; $contextIndex -le $contextEnd; ++$contextIndex) {
                $prefix = if ($contextIndex -eq $lineIndex) { '>> ' } else { '' }
                $prefix + $logLines[$contextIndex].Trim()
            }
            $result.NumericScriptContexts.Add([pscustomobject]@{
                Time = $lineTime
                Family = if ($line -match '(?i)Variablenname|invalid variable|SC_ErrorInCommand') { 'Script command' } else { 'Numeric / floating point' }
                Context = $nearby -join ' || '
            })
        }

        if ($line -match '(?i)Systemfehler\.\s+Code:\s*8') {
            if (-not $result.SystemErrorPrecursorsCaptured) {
                foreach ($precursor in $recentLogLines) {
                    $result.SystemErrorPrecursors.Add($precursor)
                }
                $result.SystemErrorPrecursorsCaptured = $true
            }
            $previousWasSystemCode8 = $true
            $pendingSystemCode8Time = $lineTime
            if ($lineTime) {
                if (-not $result.SystemErrorFirst) {
                    $result.SystemErrorFirst = $lineTime
                }
                $result.SystemErrorLast = $lineTime
            }
            continue
        }

        if ($previousWasSystemCode8) {
            $previousWasSystemCode8 = $false
            $context = $line.Trim()
            if ($context -match ':\s*(?<tail>[^:]+(?:\([^)]*\))?)\s*$') {
                $context = $Matches.tail.Trim()
            }
            Add-Count $result.SystemErrorContexts $context
            Add-Count $result.SystemErrorBuckets (Get-SystemErrorCode8Bucket $context)
            if ($pendingSystemCode8Time) {
                if (-not $result.SystemErrorFirst) {
                    $result.SystemErrorFirst = $pendingSystemCode8Time
                }
                $result.SystemErrorLast = $pendingSystemCode8Time
            }
            $pendingSystemCode8Time = ''
        }

        if ($line -match 'Texture\s+"(?<path>[^"]+)"\s+failed!') {
            Add-Count $result.TextureFailures $Matches.path
            if ($lineTime) {
                if (-not $result.TextureFailureFirst) {
                    $result.TextureFailureFirst = $lineTime
                }
                $result.TextureFailureLast = $lineTime
            }
        }

        if ($line -match '(?i)Texturladen - Direct9 Error:\s*(?<error>[A-Z0-9_]+|0x[0-9A-Fa-f]+|Unknown)') {
            Add-Count $result.Direct9TextureErrors $Matches.error
            if ($lineTime) {
                if (-not $result.Direct9TextureErrorFirst) {
                    $result.Direct9TextureErrorFirst = $lineTime
                }
                $result.Direct9TextureErrorLast = $lineTime
            }
        }

        if ($line -match '(?i)Direct-?3D-Device-Reset schlug fehl,\s*Fehler:\s*(?<error>[A-Z0-9_]+|0x[0-9A-Fa-f]+|Unknown)') {
            Add-Count $result.Direct3DResetErrors $Matches.error
            if ($lineTime) {
                if (-not $result.Direct3DResetFirst) {
                    $result.Direct3DResetFirst = $lineTime
                }
                $result.Direct3DResetLast = $lineTime
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $recentLogLines.Enqueue([pscustomobject]@{
                Time = $lineTime
                Line = $line.Trim()
            })
            while ($recentLogLines.Count -gt 8) {
                [void]$recentLogLines.Dequeue()
            }
        }
    }

    return [pscustomobject]$result
}

function Analyze-ProbeLog {
    param(
        [string]$Path,
        [object[]]$KnownRvas
    )

    $result = [ordered]@{
        Exists = Test-Path -LiteralPath $Path
        Path = $Path
        TotalLineCount = 0
        LineCount = 0
        SessionStartLine = 1
        ExceptionEvents = New-Object 'System.Collections.Generic.List[object]'
        SignatureRows = New-Object 'System.Collections.Generic.List[object]'
        KnownRvaHits = New-Counter
        Families = New-Counter
        Modules = New-Counter
        OwnerFrames = New-Counter
        MemorySnapshots = New-Object 'System.Collections.Generic.List[object]'
        VasThresholdEvents = New-Object 'System.Collections.Generic.List[object]'
        ExecutablePageCacheHits = [UInt64]0
        ExecutablePageCacheMisses = [UInt64]0
        ExecutablePageCacheSlots = [UInt64]0
        ExecutableLargeAddressAware = $null
        ExecutableCharacteristics = ''
        Started = $false
        Finalized = $false
    }

    if (-not $result.Exists) {
        return [pscustomobject]$result
    }

    # probe.log may contain several OMSI runs appended together. Analyze the
    # newest session by default so it lines up with the current logfile.txt.
    $allLines = @(Get-Content -LiteralPath $Path)
    $result.TotalLineCount = $allLines.Length
    $startIndex = 0
    for ($i = 0; $i -lt $allLines.Length; ++$i) {
        if ($allLines[$i] -match '^OmsiCrashProbe PluginStart') {
            $startIndex = $i
        }
    }
    $result.SessionStartLine = $startIndex + 1
    $sessionLines = if ($allLines.Length -eq 0) {
        @()
    }
    elseif ($startIndex -ge $allLines.Length - 1) {
        @($allLines[$startIndex])
    }
    else {
        @($allLines[$startIndex..($allLines.Length - 1)])
    }

    $pendingSignature = $null
    foreach ($line in $sessionLines) {
        $result.LineCount += 1

        if ($line -match '^OmsiCrashProbe PluginStart') {
            $result.Started = $true
        }
        elseif ($line -match '^OmsiCrashProbe PluginFinalize') {
            $result.Finalized = $true
        }

        if ($line -match '^\s+(?<name>[^\\/:*?"<>|\s]+\.dll|Omsi\.exe)\s+base=0x[0-9A-Fa-f]+\s+size=0x[0-9A-Fa-f]+\s+path=') {
            Add-Count $result.Modules $Matches.name
        }

        if ($line -match '^MemorySnapshot(?: time="(?<time>[^"]+)")? reason="(?<reason>[^"]+)" privateKB=(?<private>\d+) workingSetKB=(?<working>\d+) peakWorkingSetKB=(?<peak>\d+) pagefileKB=(?<pagefile>\d+) commitAvailMB=(?<commit>\d+) physAvailMB=(?<phys>\d+) vasFreeMB=(?<vasfree>\d+) vasLargestFreeMB=(?<largest>\d+) gdiObjects=(?<gdi>\d+) userObjects=(?<user>\d+)(?: countersOk=\d+ systemOk=\d+)?(?: vasFreeRanges=(?<freeranges>\d+) vasTopFreeMB=(?<top1>\d+),(?<top2>\d+),(?<top3>\d+) vasCommitPrivateMB=(?<commitprivate>\d+) vasCommitMappedMB=(?<commitmapped>\d+) vasCommitImageMB=(?<commitimage>\d+) vasCommittedRegions=(?<committedregions>\d+) vasReservedRegions=(?<reservedregions>\d+)(?: vasReservedMB=(?<reservedmb>\d+) vasTopReservedMB=(?<reservedtop1>\d+),(?<reservedtop2>\d+),(?<reservedtop3>\d+) vasPrivateRegions=(?<privateregions>\d+) vasMappedRegions=(?<mappedregions>\d+) vasImageRegions=(?<imageregions>\d+))?)?') {
            $snapshotTime = if ($Matches.ContainsKey('time')) { $Matches.time } else { '' }
            $snapshot = [pscustomobject]@{
                Time = $snapshotTime
                TimeSeconds = Convert-TimeOfDayToSeconds $snapshotTime
                Reason = $Matches.reason
                PrivateKB = [UInt64]$Matches.private
                WorkingSetKB = [UInt64]$Matches.working
                PeakWorkingSetKB = [UInt64]$Matches.peak
                PagefileKB = [UInt64]$Matches.pagefile
                CommitAvailMB = [UInt64]$Matches.commit
                PhysAvailMB = [UInt64]$Matches.phys
                VasFreeMB = [UInt64]$Matches.vasfree
                VasLargestFreeMB = [UInt64]$Matches.largest
                GdiObjects = [UInt64]$Matches.gdi
                UserObjects = [UInt64]$Matches.user
                VasFreeRanges = Get-OptionalUInt64 $Matches 'freeranges'
                VasTopFree1MB = Get-OptionalUInt64 $Matches 'top1'
                VasTopFree2MB = Get-OptionalUInt64 $Matches 'top2'
                VasTopFree3MB = Get-OptionalUInt64 $Matches 'top3'
                VasCommitPrivateMB = Get-OptionalUInt64 $Matches 'commitprivate'
                VasCommitMappedMB = Get-OptionalUInt64 $Matches 'commitmapped'
                VasCommitImageMB = Get-OptionalUInt64 $Matches 'commitimage'
                VasCommittedRegions = Get-OptionalUInt64 $Matches 'committedregions'
                VasReservedRegions = Get-OptionalUInt64 $Matches 'reservedregions'
                VasReservedMB = Get-OptionalUInt64 $Matches 'reservedmb'
                VasTopReserved1MB = Get-OptionalUInt64 $Matches 'reservedtop1'
                VasTopReserved2MB = Get-OptionalUInt64 $Matches 'reservedtop2'
                VasTopReserved3MB = Get-OptionalUInt64 $Matches 'reservedtop3'
                VasPrivateRegions = Get-OptionalUInt64 $Matches 'privateregions'
                VasMappedRegions = Get-OptionalUInt64 $Matches 'mappedregions'
                VasImageRegions = Get-OptionalUInt64 $Matches 'imageregions'
            }
            $result.MemorySnapshots.Add($snapshot)
            continue
        }

        if ($line -match '^VasThresholdCrossed time="(?<time>[^"]+)" thresholdMB=(?<threshold>\d+) largestFreeMB=(?<largest>\d+) freeMB=(?<free>\d+) privateKB=(?<private>\d+) gdiObjects=(?<gdi>\d+) userObjects=(?<user>\d+) reason="(?<reason>[^"]+)"') {
            $result.VasThresholdEvents.Add([pscustomobject]@{
                Time = $Matches.time
                ThresholdMB = [UInt64]$Matches.threshold
                LargestFreeMB = [UInt64]$Matches.largest
                FreeMB = [UInt64]$Matches.free
                PrivateMB = [math]::Round(([double]$Matches.private / 1024), 1)
                GdiObjects = [UInt64]$Matches.gdi
                UserObjects = [UInt64]$Matches.user
                Reason = $Matches.reason
            })
            continue
        }

        if ($line -match '^ExecutablePageCache hits=(?<hits>\d+) misses=(?<misses>\d+) slots=(?<slots>\d+)') {
            $result.ExecutablePageCacheHits = [UInt64]$Matches.hits
            $result.ExecutablePageCacheMisses = [UInt64]$Matches.misses
            $result.ExecutablePageCacheSlots = [UInt64]$Matches.slots
            continue
        }

        if ($line -match '^ExecutableFlags validPe=(?<valid>[01]) largeAddressAware=(?<laa>[01]) characteristics=(?<characteristics>0x[0-9A-Fa-f]+)') {
            if ($Matches.valid -eq '1') {
                $result.ExecutableLargeAddressAware = $Matches.laa -eq '1'
                $result.ExecutableCharacteristics = $Matches.characteristics.ToUpperInvariant()
            }
            continue
        }

        if ($line -match '^\[(?<time>[^\]]+)\]\s+exception=(?<name>\S+)\s+occurrence=(?<occurrence>\d+)\s+code=0x(?<code>[0-9A-Fa-f]+)\s+address=0x(?<address>[0-9A-Fa-f]+)\s+module=(?<module>\S+)\s+base=0x(?<base>[0-9A-Fa-f]+)\s+rva=0x(?<rva>[0-9A-Fa-f]+)') {
            $rva = Convert-HexToUInt64 $Matches.rva
            $known = if ($Matches.module -ieq 'Omsi.exe') { Find-KnownRva $KnownRvas $rva } else { $null }
            $family = Get-Family (($Matches.name + ' ' + $(if ($known) { $known.System } else { '' }))) ('0x' + $Matches.code)
            Add-Count $result.Families $family
            $result.ExceptionEvents.Add([pscustomobject]@{
                Time = $Matches.time
                Exception = $Matches.name
                Code = '0x' + $Matches.code.ToUpperInvariant()
                Module = $Matches.module
                Rva = ('0x{0:X8}' -f $rva)
                Known = if ($known) { $known.System } else { '' }
                Family = $family
            })
            continue
        }

        if ($line -match '^\s+known-rva source=(?<source>\S+)(?:\s+esp\+0x(?<esp>[0-9A-Fa-f]+))?\s+rva=0x(?<rva>[0-9A-Fa-f]+)\s+system="(?<system>[^"]+)"\s+callerContext=(?<context>\S+)\s+note="(?<note>[^"]*)"') {
            Add-Count $result.KnownRvaHits $Matches.system
            Add-Count $result.Families (Get-Family ($Matches.system + ' ' + $Matches.note))
            continue
        }

        if ($line -match '^\s+count=(?<count>\d+)\s+code=(?<codeName>[^/]+)/0x(?<code>[0-9A-Fa-f]+)\s+raiseRva=0x(?<raise>[0-9A-Fa-f]+)\s+p0=0x(?<p0>[0-9A-Fa-f]+)\s+p2=0x(?<p2>[0-9A-Fa-f]+)\s+omsi1=0x(?<omsi1>[0-9A-Fa-f]+)\s+omsi2=0x(?<omsi2>[0-9A-Fa-f]+)\s+first="(?<first>[^"]+)"\s+last="(?<last>[^"]+)"') {
            $omsi1 = Convert-HexToUInt64 $Matches.omsi1
            $omsi2 = Convert-HexToUInt64 $Matches.omsi2
            $known1 = Find-KnownRva $KnownRvas $omsi1
            $known2 = Find-KnownRva $KnownRvas $omsi2
            $knownValues = @()
            if ($known1) {
                $knownValues += $known1.System
            }
            if ($known2) {
                $knownValues += $known2.System
            }
            $knownText = ($knownValues | Where-Object { $_ }) -join ' / '
            $family = Get-Family ($Matches.codeName + ' ' + $knownText) ('0x' + $Matches.code)
            $owner = Get-ProbableOwnerFrame $omsi1 $known1 $omsi2 $known2
            $ownerKey = $owner.OwnerRva
            if ($owner.OwnerKnown) {
                $ownerKey += ' ' + $owner.OwnerKnown
            }

            $pendingSignature = [pscustomobject]@{
                Count = [int]$Matches.count
                Code = $Matches.codeName + '/0x' + ($Matches.code).ToUpperInvariant()
                RaiseRva = '0x' + ($Matches.raise).ToUpperInvariant()
                Omsi1 = '0x' + ($Matches.omsi1).ToUpperInvariant()
                Omsi2 = '0x' + ($Matches.omsi2).ToUpperInvariant()
                Known = $knownText
                Family = $family
                OwnerRva = $owner.OwnerRva
                OwnerKnown = $owner.OwnerKnown
                HelperRva = $owner.HelperRva
                HelperKnown = $owner.HelperKnown
                OwnerReason = $owner.Reason
                First = $Matches.first
                Last = $Matches.last
            }
            $result.SignatureRows.Add($pendingSignature)
            Add-Count $result.Families $family $pendingSignature.Count
            Add-Count $result.OwnerFrames $ownerKey $pendingSignature.Count
            continue
        }

        if ($pendingSignature -and $line -match '^\s+known omsi1="(?<k1>[^"]+)"\s+omsi2="(?<k2>[^"]+)"') {
            $knownText = (($Matches.k1, $Matches.k2) | Where-Object { $_ -and $_ -ne '<unknown>' }) -join ' / '
            if ($knownText) {
                $pendingSignature.Known = $knownText
                $pendingSignature.Family = Get-Family ($pendingSignature.Code + ' ' + $knownText)
            }
            $pendingSignature = $null
            continue
        }

        if ($line -match '^Repeated exception signature count=(?<count>\d+)\s+code=0x(?<code>[0-9A-Fa-f]+).*?(?:omsi1System="(?<k1>[^"]*)")?(?:\s+omsi2System="(?<k2>[^"]*)")?') {
            # Milestone rows are cumulative counters, so adding them would
            # massively over-count noisy signatures. The final shutdown summary
            # contains the authoritative count when PluginFinalize is present.
            continue
        }
    }

    return [pscustomobject]$result
}

function New-CountRows {
    param(
        [System.Collections.Generic.Dictionary[string,int]]$Counter,
        [string]$NameHeader,
        [int]$Limit = $Top
    )

    @(Get-TopCounts $Counter $Limit | ForEach-Object {
        $row = [ordered]@{}
        $row[$NameHeader] = $_.Key
        $row['Count'] = $_.Value
        [pscustomobject]$row
    })
}

function New-KnownErrorRows {
    param(
        [System.Collections.Generic.Dictionary[string,int]]$Counter,
        [object[]]$Catalog,
        [int]$Limit = $Top
    )

    $catalogById = @{}
    foreach ($entry in $Catalog) {
        $catalogById[$entry.Id] = $entry
    }

    @(Get-TopCounts $Counter $Limit | ForEach-Object {
        $entry = $catalogById[$_.Key]
        [pscustomobject]@{
            Pattern = if ($entry) { $entry.Id } else { $_.Key }
            Family = if ($entry) { $entry.Family } else { '' }
            Origin = if ($entry) { $entry.Origin } else { '' }
            Count = $_.Value
            Next = if ($entry) { $entry.Next } else { '' }
        }
    })
}

function New-NearestMemoryRows {
    param(
        [object[]]$Snapshots,
        [string]$Signal,
        [string]$TimeText
    )

    $targetSeconds = Convert-TimeOfDayToSeconds $TimeText
    if ($null -eq $targetSeconds) {
        return @()
    }

    $timedSnapshots = @($Snapshots | Where-Object { $null -ne $_.TimeSeconds })
    if ($timedSnapshots.Count -eq 0) {
        return @()
    }

    $before = @($timedSnapshots |
        Where-Object { $_.TimeSeconds -le $targetSeconds } |
        Sort-Object @{ Expression = { $targetSeconds - $_.TimeSeconds }; Descending = $false } |
        Select-Object -First 1)

    $after = @($timedSnapshots |
        Where-Object { $_.TimeSeconds -ge $targetSeconds } |
        Sort-Object @{ Expression = { $_.TimeSeconds - $targetSeconds }; Descending = $false } |
        Select-Object -First 1)

    $seen = @{}
    @($before + $after | Where-Object {
        $key = '{0}|{1}|{2}' -f $_.Time, $_.Reason, $_.VasLargestFreeMB
        if ($seen.ContainsKey($key)) {
            return $false
        }
        $seen[$key] = $true
        return $true
    } | ForEach-Object {
        $side = if ($_.TimeSeconds -le $targetSeconds) { 'before' } else { 'after' }
        [pscustomobject]@{
            Signal = $Signal
            SignalTime = $TimeText
            Snapshot = $side
            SnapshotTime = $_.Time
            DeltaSeconds = [math]::Abs($_.TimeSeconds - $targetSeconds)
            Reason = $_.Reason
            PrivateMB = [math]::Round($_.PrivateKB / 1024, 1)
            LargestFreeVasMB = $_.VasLargestFreeMB
            GdiObjects = $_.GdiObjects
            UserObjects = $_.UserObjects
        }
    })
}

function New-MemorySummaryRows {
    param([object[]]$Snapshots)

    if ($Snapshots.Count -eq 0) {
        return @()
    }

    $privateMax = ($Snapshots | Sort-Object PrivateKB -Descending | Select-Object -First 1)
    $workingMax = ($Snapshots | Sort-Object WorkingSetKB -Descending | Select-Object -First 1)
    $largestMin = ($Snapshots | Sort-Object VasLargestFreeMB | Select-Object -First 1)
    $vasMin = ($Snapshots | Sort-Object VasFreeMB | Select-Object -First 1)
    $gdiMax = ($Snapshots | Sort-Object GdiObjects -Descending | Select-Object -First 1)
    $userMax = ($Snapshots | Sort-Object UserObjects -Descending | Select-Object -First 1)

    @(
        [pscustomobject]@{ Metric = 'max private MB'; Value = [math]::Round($privateMax.PrivateKB / 1024, 1); Reason = $privateMax.Reason; Time = $privateMax.Time },
        [pscustomobject]@{ Metric = 'max working set MB'; Value = [math]::Round($workingMax.WorkingSetKB / 1024, 1); Reason = $workingMax.Reason; Time = $workingMax.Time },
        [pscustomobject]@{ Metric = 'min free VAS MB'; Value = $vasMin.VasFreeMB; Reason = $vasMin.Reason; Time = $vasMin.Time },
        [pscustomobject]@{ Metric = 'min largest free VAS block MB'; Value = $largestMin.VasLargestFreeMB; Reason = $largestMin.Reason; Time = $largestMin.Time },
        [pscustomobject]@{ Metric = 'max GDI objects'; Value = $gdiMax.GdiObjects; Reason = $gdiMax.Reason; Time = $gdiMax.Time },
        [pscustomobject]@{ Metric = 'max USER objects'; Value = $userMax.UserObjects; Reason = $userMax.Reason; Time = $userMax.Time }
    )
}

function New-VasVerdictRows {
    param(
        [object[]]$Snapshots,
        [object]$LogSummary
    )

    if ($Snapshots.Count -eq 0) {
        return @()
    }

    $minLargest = ($Snapshots | Sort-Object VasLargestFreeMB | Select-Object -First 1)
    $code8Count = Get-CounterSum $LogSummary.Categories
    if ($LogSummary.Categories.ContainsKey('Systemfehler Code 8 / OS memory resources')) {
        $code8Count = $LogSummary.Categories['Systemfehler Code 8 / OS memory resources']
    }
    else {
        $code8Count = 0
    }
    $textureCount = (Get-CounterSum $LogSummary.Direct9TextureErrors) + (Get-CounterSum $LogSummary.TextureFailures)
    $dominantCode8 = Get-TopCounts $LogSummary.SystemErrorContexts 1 | Select-Object -First 1

    $verdict = 'No critical VAS exhaustion evidence'
    $next = 'Keep correlating failures with memory snapshots.'
    if ($minLargest.VasLargestFreeMB -le 16 -and ($code8Count -gt 0 -or $textureCount -gt 0)) {
        $verdict = 'Critical 32-bit VAS exhaustion / fragmentation'
        $next = 'Prioritize largest-free VAS, texture/bitmap allocation paths, and repeated map/vehicle owners.'
    }
    elseif ($minLargest.VasLargestFreeMB -le 64) {
        $verdict = 'Severe contiguous VAS pressure'
        $next = 'Watch for Direct3D, GDI, bitmap, and Systemfehler Code 8 bursts near this timestamp.'
    }
    elseif ($minLargest.VasLargestFreeMB -le 128) {
        $verdict = 'Low contiguous VAS headroom'
        $next = 'This may still fail large texture/bitmap allocations even when total free VAS looks usable.'
    }

    @(
        [pscustomobject]@{
            Verdict = $verdict
            MinLargestFreeVasMB = $minLargest.VasLargestFreeMB
            At = $minLargest.Time
            PrivateMB = [math]::Round($minLargest.PrivateKB / 1024, 1)
            FreeVasMB = $minLargest.VasFreeMB
            GdiObjects = $minLargest.GdiObjects
            UserObjects = $minLargest.UserObjects
            SystemCode8 = $code8Count
            TextureSignals = $textureCount
            DominantCode8Context = if ($dominantCode8) { $dominantCode8.Key } else { '' }
            Next = $next
        }
    )
}

function New-VasPressureRows {
    param(
        [object[]]$Snapshots,
        [int]$Limit = $Top
    )

    @($Snapshots |
        Sort-Object VasLargestFreeMB, Time |
        Select-Object -First $Limit |
        ForEach-Object {
            $topFree = if ($_.VasTopFree1MB -gt 0 -or $_.VasTopFree2MB -gt 0 -or $_.VasTopFree3MB -gt 0) {
                "$($_.VasTopFree1MB),$($_.VasTopFree2MB),$($_.VasTopFree3MB)"
            }
            else {
                ''
            }
            $topReserved = if ($_.VasTopReserved1MB -gt 0 -or $_.VasTopReserved2MB -gt 0 -or $_.VasTopReserved3MB -gt 0) {
                "$($_.VasTopReserved1MB),$($_.VasTopReserved2MB),$($_.VasTopReserved3MB)"
            }
            else {
                ''
            }

            [pscustomobject]@{
                Time = $_.Time
                Reason = $_.Reason
                PrivateMB = [math]::Round($_.PrivateKB / 1024, 1)
                FreeVasMB = $_.VasFreeMB
                LargestFreeVasMB = $_.VasLargestFreeMB
                TopFreeVasMB = $topFree
                FreeRanges = if ($_.VasFreeRanges -gt 0) { $_.VasFreeRanges } else { '' }
                CommitPrivateMB = if ($_.VasCommitPrivateMB -gt 0) { $_.VasCommitPrivateMB } else { '' }
                CommitMappedMB = if ($_.VasCommitMappedMB -gt 0) { $_.VasCommitMappedMB } else { '' }
                CommitImageMB = if ($_.VasCommitImageMB -gt 0) { $_.VasCommitImageMB } else { '' }
                ReservedMB = if ($_.VasReservedMB -gt 0) { $_.VasReservedMB } else { '' }
                TopReservedMB = $topReserved
                RegionTypes = if ($_.VasPrivateRegions -gt 0 -or $_.VasMappedRegions -gt 0 -or $_.VasImageRegions -gt 0) { "$($_.VasPrivateRegions)/$($_.VasMappedRegions)/$($_.VasImageRegions)" } else { '' }
                GdiObjects = $_.GdiObjects
                UserObjects = $_.UserObjects
            }
        })
}

function New-SuspiciousSignalRows {
    param(
        [object]$LogSummary,
        [object]$ProbeSummary,
        [int]$Limit = $Top
    )

    $rows = New-Object 'System.Collections.Generic.List[object]'

    foreach ($hit in Get-TopCounts $LogSummary.KnownErrorPatterns $Limit) {
        $rows.Add([pscustomobject]@{
            Source = 'OMSI logfile'
            Signal = 'known pattern: ' + $hit.Key
            Count = $hit.Value
            Why = 'Recurring public/runtime error text.'
        })
    }

    foreach ($hit in Get-TopCounts $LogSummary.SystemErrorBuckets $Limit) {
        $rows.Add([pscustomobject]@{
            Source = 'OMSI logfile'
            Signal = 'Systemfehler Code 8 bucket: ' + $hit.Key
            Count = $hit.Value
            Why = 'OS memory/resource failure with following OMSI context line.'
        })
    }

    foreach ($hit in Get-TopCounts $LogSummary.Direct3DResetErrors $Limit) {
        $rows.Add([pscustomobject]@{
            Source = 'OMSI logfile'
            Signal = 'Direct3D reset error: ' + $hit.Key
            Count = $hit.Value
            Why = 'Device reset failed; separate from texture allocation errors.'
        })
    }

    foreach ($hit in Get-TopCounts $LogSummary.Direct9TextureErrors $Limit) {
        $rows.Add([pscustomobject]@{
            Source = 'OMSI logfile'
            Signal = 'Direct9 texture error: ' + $hit.Key
            Count = $hit.Value
            Why = 'Texture/image allocation or upload failed.'
        })
    }

    foreach ($hit in Get-TopCounts $ProbeSummary.OwnerFrames $Limit) {
        $rows.Add([pscustomobject]@{
            Source = 'probe.log'
            Signal = 'owner frame: ' + $hit.Key
            Count = $hit.Value
            Why = 'First-chance exception signature grouped by probable OMSI owner.'
        })
    }

    foreach ($hit in Get-TopCounts $ProbeSummary.KnownRvaHits $Limit) {
        $rows.Add([pscustomobject]@{
            Source = 'probe.log'
            Signal = 'KnownRVA: ' + $hit.Key
            Count = $hit.Value
            Why = 'Static Ghidra label seen in a runtime stack or exception frame.'
        })
    }

    @($rows | Sort-Object Count -Descending | Select-Object -First $Limit)
}

$knownRvas = Import-KnownRvaTable $KnownRvaSourcePath
$knownErrorCatalog = Get-KnownErrorCatalog
$logSummary = Analyze-Logfile $LogfilePath $knownErrorCatalog
$probeSummary = Analyze-ProbeLog $ProbeLogPath $knownRvas

$lines = New-Object 'System.Collections.Generic.List[string]'
$lines.Add('# OMSI crash/session analysis')
$lines.Add('')
$lines.Add(('Generated: {0:yyyy-MM-dd HH:mm:ss zzz}' -f (Get-Date)))
$lines.Add('')
$lines.Add('## Inputs')
$lines.Add('')
$lines.Add('- OMSI root: `' + $OmsiRoot + '`')
$lines.Add('- OMSI logfile: `' + $LogfilePath + '`')
$lines.Add('- Probe log: `' + $ProbeLogPath + '`')
$lines.Add('- KnownRva source: `' + $KnownRvaSourcePath + '`')
$lines.Add("- KnownRva entries loaded: $($knownRvas.Count)")
$lines.Add('')
$lines.Add('Forbidden content folders were not scanned. Asset paths shown below come only from log text already written by OMSI.')
$lines.Add('')

$lines.Add('## OMSI logfile')
$lines.Add('')
if (-not $logSummary.Exists) {
    $lines.Add('_OMSI logfile not found._')
    $lines.Add('')
}
else {
    $lines.Add("- Lines: $($logSummary.LineCount)")
    if ($logSummary.TimeFirst -or $logSummary.TimeLast) {
        $lines.Add("- Time span in logfile: $($logSummary.TimeFirst) .. $($logSummary.TimeLast)")
    }
    $lines.Add('')

    $lines.Add('### Log categories')
    $lines.Add('')
    Add-MarkdownTable $lines @('Category', 'Count') (New-CountRows $logSummary.Categories 'Category' $Top)

    $lines.Add('### Known error patterns')
    $lines.Add('')
    Add-MarkdownTable $lines @('Pattern', 'Family', 'Origin', 'Count', 'Next') (New-KnownErrorRows $logSummary.KnownErrorPatterns $knownErrorCatalog $Top)

    $lines.Add('### Numeric and script diagnostic context')
    $lines.Add('')
    Add-MarkdownTable $lines @('Time', 'Family', 'Context') @($logSummary.NumericScriptContexts | ForEach-Object { $_ })

    $lines.Add('### Systemfehler Code 8 contexts')
    $lines.Add('')
    Add-MarkdownTable $lines @('Context', 'Count') (New-CountRows $logSummary.SystemErrorContexts 'Context' $Top)

    $lines.Add('### Systemfehler Code 8 buckets')
    $lines.Add('')
    Add-MarkdownTable $lines @('Bucket', 'Count') (New-CountRows $logSummary.SystemErrorBuckets 'Bucket' $Top)

    $lines.Add('### Lines before first Systemfehler Code 8')
    $lines.Add('')
    Add-MarkdownTable $lines @('Time', 'Line') @($logSummary.SystemErrorPrecursors | ForEach-Object { $_ })

    $lines.Add('### Systemfehler Code 8 memory correlation')
    $lines.Add('')
    $systemCode8MemoryRows = @()
    $systemCode8MemoryRows += New-NearestMemoryRows $probeSummary.MemorySnapshots 'first Systemfehler Code 8' $logSummary.SystemErrorFirst
    $systemCode8MemoryRows += New-NearestMemoryRows $probeSummary.MemorySnapshots 'last Systemfehler Code 8' $logSummary.SystemErrorLast
    Add-MarkdownTable $lines @('Signal', 'SignalTime', 'Snapshot', 'SnapshotTime', 'DeltaSeconds', 'Reason', 'PrivateMB', 'LargestFreeVasMB', 'GdiObjects', 'UserObjects') $systemCode8MemoryRows

    $lines.Add('### Texture failures')
    $lines.Add('')
    $textureTimingRows = @(
        [pscustomobject]@{
            Signal = 'Texture failed'
            First = $logSummary.TextureFailureFirst
            Last = $logSummary.TextureFailureLast
            Count = ($logSummary.TextureFailures.Values | Measure-Object -Sum).Sum
        },
        [pscustomobject]@{
            Signal = 'Texturladen Direct9 Error'
            First = $logSummary.Direct9TextureErrorFirst
            Last = $logSummary.Direct9TextureErrorLast
            Count = ($logSummary.Direct9TextureErrors.Values | Measure-Object -Sum).Sum
        }
    ) | Where-Object { $_.Count -gt 0 }
    Add-MarkdownTable $lines @('Signal', 'First', 'Last', 'Count') $textureTimingRows

    $lines.Add('### Direct9 texture error codes')
    $lines.Add('')
    Add-MarkdownTable $lines @('Error', 'Count') (New-CountRows $logSummary.Direct9TextureErrors 'Error' $Top)

    $lines.Add('### Direct3D reset timing')
    $lines.Add('')
    $direct3DResetTimingRows = @(
        [pscustomobject]@{
            Signal = 'Direct3D reset failed'
            First = $logSummary.Direct3DResetFirst
            Last = $logSummary.Direct3DResetLast
            Count = ($logSummary.Direct3DResetErrors.Values | Measure-Object -Sum).Sum
        }
    ) | Where-Object { $_.Count -gt 0 }
    Add-MarkdownTable $lines @('Signal', 'First', 'Last', 'Count') $direct3DResetTimingRows

    $lines.Add('### Direct3D reset error codes')
    $lines.Add('')
    Add-MarkdownTable $lines @('Error', 'Count') (New-CountRows $logSummary.Direct3DResetErrors 'Error' $Top)

    $lines.Add('### Texture failure memory correlation')
    $lines.Add('')
    $textureMemoryRows = @()
    $textureMemoryRows += New-NearestMemoryRows $probeSummary.MemorySnapshots 'first texture failure' $logSummary.TextureFailureFirst
    $textureMemoryRows += New-NearestMemoryRows $probeSummary.MemorySnapshots 'last texture failure' $logSummary.TextureFailureLast
    Add-MarkdownTable $lines @('Signal', 'SignalTime', 'Snapshot', 'SnapshotTime', 'DeltaSeconds', 'Reason', 'PrivateMB', 'LargestFreeVasMB', 'GdiObjects', 'UserObjects') $textureMemoryRows

    $lines.Add('### Texture failure paths')
    $lines.Add('')
    Add-MarkdownTable $lines @('Texture', 'Count') (New-CountRows $logSummary.TextureFailures 'Texture' $Top)
}

$lines.Add('## Probe log')
$lines.Add('')
if (-not $probeSummary.Exists) {
    $lines.Add('_Probe log not found._')
    $lines.Add('')
}
else {
    $lines.Add("- Total lines in probe.log: $($probeSummary.TotalLineCount)")
    $lines.Add("- Lines in analyzed latest session: $($probeSummary.LineCount)")
    $lines.Add("- Latest session starts at probe.log line: $($probeSummary.SessionStartLine)")
    $lines.Add("- PluginStart seen: $($probeSummary.Started)")
    $lines.Add("- PluginFinalize seen: $($probeSummary.Finalized)")
    $lines.Add("- Exception events with full records: $($probeSummary.ExceptionEvents.Count)")
    $lines.Add("- Final signature rows: $($probeSummary.SignatureRows.Count)")
    $lines.Add("- Memory snapshots: $($probeSummary.MemorySnapshots.Count)")
    if ($null -ne $probeSummary.ExecutableLargeAddressAware) {
        $lines.Add("- Large Address Aware: $($probeSummary.ExecutableLargeAddressAware) ($($probeSummary.ExecutableCharacteristics))")
    }
    if ($probeSummary.ExecutablePageCacheHits -gt 0 -or $probeSummary.ExecutablePageCacheMisses -gt 0) {
        $cacheTotal = $probeSummary.ExecutablePageCacheHits + $probeSummary.ExecutablePageCacheMisses
        $cacheHitRate = if ($cacheTotal -gt 0) { [math]::Round(100 * $probeSummary.ExecutablePageCacheHits / $cacheTotal, 1) } else { 0 }
        $lines.Add("- Executable-page cache: $($probeSummary.ExecutablePageCacheHits) hits, $($probeSummary.ExecutablePageCacheMisses) misses, $cacheHitRate% hit rate")
    }
    $lines.Add('')

    $lines.Add('### Probe families')
    $lines.Add('')
    Add-MarkdownTable $lines @('Family', 'Count') (New-CountRows $probeSummary.Families 'Family' $Top)

    $lines.Add('### Probable owner frames')
    $lines.Add('')
    Add-MarkdownTable $lines @('OwnerFrame', 'Count') (New-CountRows $probeSummary.OwnerFrames 'OwnerFrame' $Top)

    $lines.Add('### Final exception signatures')
    $lines.Add('')
    $signatureRows = @($probeSummary.SignatureRows | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object {
        [pscustomobject]@{
            Count = $_.Count
            Code = $_.Code
            Family = $_.Family
            OwnerRva = $_.OwnerRva
            OwnerKnown = $_.OwnerKnown
            HelperRva = $_.HelperRva
            HelperKnown = $_.HelperKnown
            Known = $_.Known
            Omsi1 = $_.Omsi1
            Omsi2 = $_.Omsi2
            First = $_.First
            Last = $_.Last
        }
    })
    Add-MarkdownTable $lines @('Count', 'Code', 'Family', 'OwnerRva', 'OwnerKnown', 'HelperRva', 'HelperKnown', 'Known', 'Omsi1', 'Omsi2', 'First', 'Last') $signatureRows

    $lines.Add('### Full exception events')
    $lines.Add('')
    $eventRows = @($probeSummary.ExceptionEvents | Select-Object -First $Top | ForEach-Object {
        [pscustomobject]@{
            Time = $_.Time
            Exception = $_.Exception
            Code = $_.Code
            Module = $_.Module
            Rva = $_.Rva
            Known = $_.Known
            Family = $_.Family
        }
    })
    Add-MarkdownTable $lines @('Time', 'Exception', 'Code', 'Module', 'Rva', 'Known', 'Family') $eventRows

    $lines.Add('### Known RVA hits')
    $lines.Add('')
    Add-MarkdownTable $lines @('KnownRva', 'Count') (New-CountRows $probeSummary.KnownRvaHits 'KnownRva' $Top)

    $lines.Add('### Memory snapshots')
    $lines.Add('')
    Add-MarkdownTable $lines @('Metric', 'Value', 'Reason', 'Time') (New-MemorySummaryRows $probeSummary.MemorySnapshots)

    $lines.Add('### VAS exhaustion verdict')
    $lines.Add('')
    Add-MarkdownTable $lines @('Verdict', 'MinLargestFreeVasMB', 'At', 'PrivateMB', 'FreeVasMB', 'GdiObjects', 'UserObjects', 'SystemCode8', 'TextureSignals', 'DominantCode8Context', 'Next') (New-VasVerdictRows $probeSummary.MemorySnapshots $logSummary)

    $lines.Add('### VAS pressure snapshots')
    $lines.Add('')
    Add-MarkdownTable $lines @('Time', 'Reason', 'PrivateMB', 'FreeVasMB', 'LargestFreeVasMB', 'TopFreeVasMB', 'FreeRanges', 'CommitPrivateMB', 'CommitMappedMB', 'CommitImageMB', 'ReservedMB', 'TopReservedMB', 'RegionTypes', 'GdiObjects', 'UserObjects') (New-VasPressureRows $probeSummary.MemorySnapshots $Top)

    $lines.Add('### VAS threshold crossings')
    $lines.Add('')
    Add-MarkdownTable $lines @('Time', 'ThresholdMB', 'LargestFreeMB', 'FreeMB', 'PrivateMB', 'GdiObjects', 'UserObjects', 'Reason') @($probeSummary.VasThresholdEvents | Select-Object -First $Top)
}

$lines.Add('## Top suspicious signals')
$lines.Add('')
Add-MarkdownTable $lines @('Source', 'Signal', 'Count', 'Why') (New-SuspiciousSignalRows $logSummary $probeSummary $Top)

$lines.Add('## Session interpretation')
$lines.Add('')
$dominantProbeFamily = Get-TopCounts $probeSummary.Families 1 | Select-Object -First 1
$dominantLogCategory = Get-TopCounts $logSummary.Categories 1 | Select-Object -First 1

if ($dominantProbeFamily) {
    $lines.Add("- Dominant probe family: $($dominantProbeFamily.Key) ($($dominantProbeFamily.Value) weighted hits).")
}
if ($dominantLogCategory) {
    $lines.Add("- Dominant OMSI logfile category: $($dominantLogCategory.Key) ($($dominantLogCategory.Value) hits).")
}
if ($logSummary.Categories.ContainsKey('DirectX/texture out of memory') -or $logSummary.Categories.ContainsKey('Texture load Direct9 error')) {
    $lines.Add('- OMSI reported DirectX texture allocation failures; correlate this with probe VAS/GDI snapshots when available.')
}
if ($dominantProbeFamily -and $dominantProbeFamily.Key -eq 'Numeric / floating point' -and ($logSummary.Categories.ContainsKey('DirectX/texture out of memory') -or $logSummary.Categories.ContainsKey('Texture load Direct9 error'))) {
    $lines.Add('- The probe is dominated by handled Delphi numeric conversion exceptions, but the OMSI logfile points more directly at texture/resource exhaustion for this session.')
}
if ($logSummary.Categories.ContainsKey('Systemfehler Code 8 / OS memory resources')) {
    $lines.Add('- OMSI reported Systemfehler Code 8. In this game this usually needs process memory, VAS fragmentation, GDI handles, and texture pressure checked together.')
}
$collisionMeshPrecursor = @($logSummary.SystemErrorPrecursors | Where-Object { $_.Line -match '(?i)collision mesh without unloading|Kollisionsmesh' } | Select-Object -First 1)
if ($collisionMeshPrecursor.Count -gt 0) {
    $lines.Add('- The first Code 8 burst was preceded by an OMSI PhysObj warning about loading another collision mesh without unloading the previous one during tile refresh. This is an engine-state correlation, not proof that the logged asset is defective.')
}
$vasVerdict = New-VasVerdictRows $probeSummary.MemorySnapshots $logSummary | Select-Object -First 1
if ($vasVerdict -and $vasVerdict.Verdict -match 'Critical|Severe') {
    $lines.Add("- VAS verdict: $($vasVerdict.Verdict); smallest largest-free block was $($vasVerdict.MinLargestFreeVasMB) MB at $($vasVerdict.At).")
}
if ($logSummary.Direct3DResetErrors.Count -gt 0) {
    $resetNames = ((Get-TopCounts $logSummary.Direct3DResetErrors 3 | ForEach-Object { $_.Key }) -join ', ')
    $lines.Add("- OMSI reported Direct3D device reset failures: $resetNames.")
}
if ($probeSummary.SignatureRows.Count -eq 0 -and $probeSummary.ExceptionEvents.Count -eq 0) {
    $lines.Add('- No probe exception signatures were found. This can happen if OMSI did not load the plugin or the session ended before interesting first-chance exceptions.')
}
$lines.Add('')

$outputDir = Split-Path -Parent $OutputPath
if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$lines | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Host "Wrote $OutputPath"
Write-Host "KnownRva entries loaded: $($knownRvas.Count)"
if ($dominantLogCategory) {
    Write-Host "Top OMSI logfile category: $($dominantLogCategory.Key) ($($dominantLogCategory.Value))"
}
if ($dominantProbeFamily) {
    Write-Host "Top probe family: $($dominantProbeFamily.Key) ($($dominantProbeFamily.Value))"
}

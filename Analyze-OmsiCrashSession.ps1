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
            Match = '(?i)Systemfehler\.\s+Code:\s*8|not enough memory resources|No hay suficientes recursos de memoria'
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
            Match = '(?i)Variablenname.*ung.ltig|invalid variable'
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
        TextureFailures = New-Counter
        TimeFirst = ''
        TimeLast = ''
    }

    if (-not $result.Exists) {
        return [pscustomobject]$result
    }

    $previousWasSystemCode8 = $false
    foreach ($line in Get-Content -LiteralPath $Path) {
        $result.LineCount += 1

        if ($line -match '^\s*\d+\s+(?<time>\d\d:\d\d:\d\d)\s+-') {
            if (-not $result.TimeFirst) {
                $result.TimeFirst = $Matches.time
            }
            $result.TimeLast = $Matches.time
        }

        if ($line -match '(?i)\b(Error|Warning|Fatal Error|Direct9 Error)\b') {
            Add-Count $result.ErrorTexts ($line.Trim())
        }

        $categoryHits = @()
        if ($line -match '(?i)Systemfehler\.\s+Code:\s*8|No hay suficientes recursos de memoria|not enough memory resources') { $categoryHits += 'Systemfehler Code 8 / OS memory resources' }
        if ($line -match '(?i)E_OUTOFMEMORY|D3DERR_OUTOFVIDEOMEMORY|out of memory') { $categoryHits += 'DirectX/texture out of memory' }
        if ($line -match '(?i)Texturladen - Direct9 Error') { $categoryHits += 'Texture load Direct9 error' }
        if ($line -match '(?i)Texture ".+" failed!') { $categoryHits += 'Texture failed' }
        if ($line -match '(?i)Direct3D-Device lost|Direct-3D-Device-Reset|D3DERR_DEVICELOST|D3DERR_INVALIDCALL') { $categoryHits += 'Direct3D device lost/reset' }
        if ($line -match '(?i)Zugriffsverletzung|Access violation|AccessViolation') { $categoryHits += 'Access violation' }
        if ($line -match '(?i)Fehler bei Bereich|Bereichspr|Argument ausserhalb|Argument au.erhalb|Listenindex') { $categoryHits += 'Bounds/list/range checks' }
        if ($line -match '(?i)Gleitkomma|floating|division durch null|ZeroDivide') { $categoryHits += 'Floating point/conversion' }
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

        if ($line -match '(?i)Systemfehler\.\s+Code:\s*8') {
            $previousWasSystemCode8 = $true
            continue
        }

        if ($previousWasSystemCode8) {
            $previousWasSystemCode8 = $false
            $context = $line.Trim()
            if ($context -match ':\s*(?<tail>[^:]+(?:\([^)]*\))?)\s*$') {
                $context = $Matches.tail.Trim()
            }
            Add-Count $result.SystemErrorContexts $context
        }

        if ($line -match 'Texture\s+"(?<path>[^"]+)"\s+failed!') {
            Add-Count $result.TextureFailures $Matches.path
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
        MemorySnapshots = New-Object 'System.Collections.Generic.List[object]'
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

        if ($line -match '^MemorySnapshot reason="(?<reason>[^"]+)" privateKB=(?<private>\d+) workingSetKB=(?<working>\d+) peakWorkingSetKB=(?<peak>\d+) pagefileKB=(?<pagefile>\d+) commitAvailMB=(?<commit>\d+) physAvailMB=(?<phys>\d+) vasFreeMB=(?<vasfree>\d+) vasLargestFreeMB=(?<largest>\d+) gdiObjects=(?<gdi>\d+) userObjects=(?<user>\d+)') {
            $snapshot = [pscustomobject]@{
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
            }
            $result.MemorySnapshots.Add($snapshot)
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

            $pendingSignature = [pscustomobject]@{
                Count = [int]$Matches.count
                Code = $Matches.codeName + '/0x' + ($Matches.code).ToUpperInvariant()
                RaiseRva = '0x' + ($Matches.raise).ToUpperInvariant()
                Omsi1 = '0x' + ($Matches.omsi1).ToUpperInvariant()
                Omsi2 = '0x' + ($Matches.omsi2).ToUpperInvariant()
                Known = $knownText
                Family = $family
                First = $Matches.first
                Last = $Matches.last
            }
            $result.SignatureRows.Add($pendingSignature)
            Add-Count $result.Families $family $pendingSignature.Count
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
        [pscustomobject]@{ Metric = 'max private MB'; Value = [math]::Round($privateMax.PrivateKB / 1024, 1); Reason = $privateMax.Reason },
        [pscustomobject]@{ Metric = 'max working set MB'; Value = [math]::Round($workingMax.WorkingSetKB / 1024, 1); Reason = $workingMax.Reason },
        [pscustomobject]@{ Metric = 'min free VAS MB'; Value = $vasMin.VasFreeMB; Reason = $vasMin.Reason },
        [pscustomobject]@{ Metric = 'min largest free VAS block MB'; Value = $largestMin.VasLargestFreeMB; Reason = $largestMin.Reason },
        [pscustomobject]@{ Metric = 'max GDI objects'; Value = $gdiMax.GdiObjects; Reason = $gdiMax.Reason },
        [pscustomobject]@{ Metric = 'max USER objects'; Value = $userMax.UserObjects; Reason = $userMax.Reason }
    )
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

    $lines.Add('### Systemfehler Code 8 contexts')
    $lines.Add('')
    Add-MarkdownTable $lines @('Context', 'Count') (New-CountRows $logSummary.SystemErrorContexts 'Context' $Top)

    $lines.Add('### Texture failures')
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
    $lines.Add('')

    $lines.Add('### Probe families')
    $lines.Add('')
    Add-MarkdownTable $lines @('Family', 'Count') (New-CountRows $probeSummary.Families 'Family' $Top)

    $lines.Add('### Final exception signatures')
    $lines.Add('')
    $signatureRows = @($probeSummary.SignatureRows | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object {
        [pscustomobject]@{
            Count = $_.Count
            Code = $_.Code
            Family = $_.Family
            Known = $_.Known
            Omsi1 = $_.Omsi1
            Omsi2 = $_.Omsi2
            First = $_.First
            Last = $_.Last
        }
    })
    Add-MarkdownTable $lines @('Count', 'Code', 'Family', 'Known', 'Omsi1', 'Omsi2', 'First', 'Last') $signatureRows

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
    Add-MarkdownTable $lines @('Metric', 'Value', 'Reason') (New-MemorySummaryRows $probeSummary.MemorySnapshots)
}

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

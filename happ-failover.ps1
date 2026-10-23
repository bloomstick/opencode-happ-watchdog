#Requires -Version 5.1
<#
.SYNOPSIS
  happ-failover watchdog: on OpenCode rate-limit errors (provider limits plus the
  per-IP free usage limit listed in the RateLimitPattern), switch Happ to a random
  previously unused, unbanned server (via the happd named-pipe protocol), fully restart
  the OpenCode desktop app (stop before changing the server, start after), and send
  "continue" prompts to the affected top-level sessions.

.DESCRIPTION
  Reverse-engineered and verified in live use:
   - happd named pipe \\.\pipe\happd-<session>: 4-byte BIG-ENDIAN length + compact JSON
   - actions: client-hello, get-privilege, list, stop, kill, start, stdin, close-stdin, heartbeat
   - xray.exe is spawned by the daemon with no args; config is delivered via a 'stdin' action
   - the GUI process (Happ.exe) keeps generated xray configs in memory -> templates & server params
   - HKCU\Software\Happ\OrganizationDefaults\Preferences holds lastServer* (current server)

  Usage:
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -TestInit
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -TestSwitch
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -TestSessions
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -TestProbe
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -Watch
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -BanServer host:port
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -UnbanServer host:port
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -ListBanned
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -ForkSession ses_id
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -ListBurned
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -UnburnSession ses_id
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -CaptureAll [-CaptureSeconds 120]
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -ListServers
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -Watch [-Interactive] [-ProjectDir <dir>]
#>
param(
    [switch]$TestInit,
    [switch]$TestSwitch,
    [switch]$TestSessions,
    [switch]$TestProbe,
    [switch]$SwitchProbe,
    [switch]$Watch,
    [switch]$Interactive,
    [string]$BanServer,
    [string]$UnbanServer,
    [switch]$ListBanned,
    [string]$ForkSession,
    [string]$UnburnSession,
    [switch]$ListBurned,
    [switch]$CaptureAll,
    [switch]$ListServers,
    [int]$CaptureSeconds = 120,
    [int]$PollSeconds = 5,
    [int]$CooldownSec = 120,
    [string]$ProjectDir = ''
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Script:Cfg = @{
    ToolDir           = $PSScriptRoot
    StatePath         = (Join-Path $PSScriptRoot 'state.json')
    BansPath          = (Join-Path $PSScriptRoot 'bans.json')
    LogPath           = (Join-Path $PSScriptRoot 'failover.log')
    ConfigCacheDir    = (Join-Path $PSScriptRoot 'configs')
    CapturesDir       = (Join-Path $PSScriptRoot 'captures')
    OpLogPath         = "$env:USERPROFILE\.local\share\opencode\log\opencode.log"
    # directory context for `opencode api` (sessions of the project to be healed);
    # defaults to the directory the script was launched from, can be set with -ProjectDir
    ProjectDir        = ''
    HappRegPath       = 'HKCU:\Software\Happ\OrganizationDefaults\Preferences'
    XrayExe           = 'C:\Program Files\FlyFrogLLC\Happ\core\xray.exe'
    XrayWorkDir       = 'C:\Program Files\FlyFrogLLC\Happ\core'
    ProcessId         = 'xray-core'
    ContinueText      = 'continue'
    RateLimitPattern  = '(Rate limit exceeded|Too many requests|Free usage limit reached|Free usage exceeded)'
    QuotaBanPattern   = 'Free usage limit reached\. Subscribe to OpenCode Go to keep going: https://opencode\.ai/go'
    EndpointPattern   = 'Endpoint is unavailable'
    ContinueDelaySec  = 5     # wait after app/service (re)connect before continue prompts
    RestartOpenCode   = $true
    TopLevelOnly      = $true
    # A session that was in flight when a server switch happened must not be
    # prompted again on the new exit IP: a session already flagged by the
    # provider can flag the new IP with its first request. After a switch the
    # watchdog forks every session it is about to resume (local DB copy, no
    # provider request), tags the old one [burned], and prompts the fork.
    SessionForkEnabled = $true
    SessionForkMaxDepth = 6     # fork-of-fork chain cap for one root session
    SessionForkMaxPerHour = 30  # safety valve against a switch/fork runaway
    MaxSwitchAttempts = 6
    FailSkipMin       = 60     # servers whose last switch-verify failed are demoted for this many minutes
    ExitIpFreshMin    = 45     # demote servers whose last observed exit IP was still in use within this window (per-IP free-quota freshness)
    FastRetrySec       = 8     # shorter cooldown for another failure shortly after a switch
    ConsecutiveWindowSec = 180 # how long a follow-up failure counts as a consecutive timeout
    FastVerifyTries    = 2     # verification attempts after a fast switch
    FastVerifyTimeoutSec = 4   # curl timeout per fast verification attempt
    TunExe             = 'C:\Program Files\FlyFrogLLC\Happ\tun\sing-box.exe'
    TunConfigPath      = (Join-Path $env:LOCALAPPDATA 'Happ\config.json')
    TunIface           = 'happ-tun'
    TunAddress         = '172.18.0.1/30'
    TunAddressV6       = 'fd6e:a81b:704f:1211::2'
    TunDns             = '1.1.1.1'
    OpenCodeExe       = "$env:LOCALAPPDATA\Programs\@opencodedesktop\OpenCode.exe"
    OpenCodeProcess   = 'OpenCode'
    OpenCodeStopSec   = 20
    OpenCodeStartSec  = 120
    HeartbeatSec      = 15
    WebCheckUrl       = 'https://api.ipify.org/?format=json'
    AffectedWindowMin = 120
    SessionResumeFreshMin = 15  # automatic post-switch resume: ignore failures older than this many minutes
    ConnResetPattern   = 'ECONNRESET|Connection lost while reading the response'
    ConnResetWindowSec = 180    # count connection-loss failures within this window
    ConnResetMinCount  = 3      # threshold within the window -> full server failover
    ConnResetScanSec   = 20     # API-level scan cadence (ECONNRESET never reaches opencode.log)
    TimeoutPattern     = '(?i)(timed out|timeout|ETIMEDOUT)'  # session-level provider timeout errors
    TimeoutInstantSec  = 120    # timeout within this window after our continue -> server is bad, ban it
    TunnelScanSec      = 30     # system-route health probe cadence
    ProbeUrl2          = 'https://checkip.amazonaws.com'
    ProbeTimeoutSec    = 8
    CaptureWindowSec   = 1800  # [U] capture window; [U] again stops sooner
    CaptureIntervalSec = 0.3   # pause between memory scans
}

# public: resolve the OpenCode project context (defaults to the launch directory)
if (-not $ProjectDir) { $ProjectDir = (Get-Location).Path }
$Script:Cfg.ProjectDir = $ProjectDir

foreach ($p in @($Script:Cfg.ToolDir, $Script:Cfg.ConfigCacheDir, $Script:Cfg.CapturesDir)) {
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
}

# console renderer state - declared before any Log call can run
$Script:LayoutReady = $false
$Script:EventRing = New-Object System.Collections.Generic.List[string]
$Script:RingCap = 400
$Script:LastWinW = -1
$Script:LastWinH = -1
$Script:PendingWinW = -1
$Script:PendingWinH = -1
$Script:PendingWinAt = $null
$Script:BansEditor = $null
$Script:SuppressRender = $false
$Script:Capture = $null

function Log([string]$msg) {
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    if ($Script:LayoutReady) {
        try { Write-ConsoleEvent $line } catch { try { Write-Host $line } catch { } }
    } else {
        try { Write-Host $line } catch { }
    }
    try { $line | Out-File $Script:Cfg.LogPath -Append -Encoding utf8 } catch { }
}

function Add-RingEvent([string]$msg) {
    # dashboard-only event (also useful before the interactive layout exists)
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    try { $Script:EventRing.Add([string]$line) } catch { }
    while ($Script:EventRing.Count -gt $Script:RingCap) {
        try { $Script:EventRing.RemoveAt(0) } catch { break }
    }
    if ($Script:LayoutReady -and -not $Script:SuppressRender) {
        try { if (Get-Command Render-Frame -ErrorAction SilentlyContinue) { Render-Frame } } catch { }
    }
}

# ------------------------------------------------------------------- state
function Initialize-StateMaps {
    $changed = $false
    foreach ($name in @('used','prompted','reliability','sessions')) {
        $prop = $Script:State.PSObject.Properties[$name]
        if (-not $prop -or $null -eq $prop.Value) {
            Add-Member -InputObject $Script:State -NotePropertyName $name -NotePropertyValue (New-Object PSObject) -Force
            $changed = $true
        }
    }
    return $changed
}
function Load-State {
    if (Test-Path $Script:Cfg.StatePath) {
        try { $Script:State = Get-Content $Script:Cfg.StatePath -Raw -Encoding utf8 | ConvertFrom-Json } catch { $Script:State = $null }
    }
    if ($null -eq $Script:State) { $Script:State = New-Object PSObject }
    if (Initialize-StateMaps) { Save-State }
    Load-Bans
}
function Save-State {
    try { $Script:State | ConvertTo-Json -Depth 8 | Set-Content $Script:Cfg.StatePath -Encoding utf8 } catch { Log "state save failed: $_" }
}

# ------------------------------------------------------------------- bans
# Bans are deliberately kept in their own file: clearing "used" must never
# clear them, and an external -BanServer write must not be overwritten by the
# watchdog saving state.json.
function Load-Bans {
    $map = $null
    if (Test-Path $Script:Cfg.BansPath) {
        try {
            $text = Get-Content $Script:Cfg.BansPath -Raw -Encoding utf8
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $raw = $text | ConvertFrom-Json
                if ($raw -is [array]) { Log 'bans file is not a JSON object - keeping the current ban list' }
                elseif ($raw -is [System.Management.Automation.PSCustomObject]) { $map = $raw }
                else { Log 'bans file is not a JSON object - keeping the current ban list' }
            } else {
                Log 'bans file is empty - keeping the current ban list'
            }
        } catch { Log ("bans load failed: " + $_.Exception.Message) }
    } else {
        $map = New-Object PSObject
    }
    if ($null -ne $map) { $Script:Bans = $map }
    elseif (-not $Script:Bans) { $Script:Bans = New-Object PSObject }
}
function Save-Bans {
    try {
        $tmp = $Script:Cfg.BansPath + '.tmp'
        $Script:Bans | ConvertTo-Json -Depth 4 | Set-Content $tmp -Encoding utf8
        Move-Item -Force -Path $tmp -Destination $Script:Cfg.BansPath
    } catch {
        Log "bans save failed: $_"
        try { Remove-Item ($Script:Cfg.BansPath + '.tmp') -Force -ErrorAction SilentlyContinue } catch { }
    }
}
function Get-ServerKey([object]$srv) {
    if (-not $srv -or -not $srv.host) { return $null }
    # A profile-aware server carries its own key (host:port#profileHash).
    # Endpoint-only objects fall back to host:port.
    try {
        if ($srv.PSObject.Properties['key'] -and $srv.key) { return [string]$srv.key }
    } catch { }
    return ('{0}:{1}' -f $srv.host, $srv.port)
}
function Test-ServerBanned([string]$key) {
    if (-not $key) { return $false }
    if (-not $Script:Bans) { Load-Bans }
    if (-not $Script:Bans) { return $false }
    if ([bool]$Script:Bans.PSObject.Properties[$key]) { return $true }
    # An endpoint ban is a wildcard: it also covers every profile on that
    # endpoint, so bans created before profile capture stay effective.
    if ($key -match '^(.+:[0-9]{1,5})#[0-9a-fA-F]+$') {
        return [bool]$Script:Bans.PSObject.Properties[$Matches[1]]
    }
    return $false
}
function Get-BannedEntries {
    if (-not $Script:Bans) { Load-Bans }
    if (-not $Script:Bans) { return @() }
    return @($Script:Bans.PSObject.Properties | Sort-Object Name)
}
function Get-BanInfo([object]$value) {
    # Old bans are plain timestamps -> manual. Automatic quota bans are stored
    # as objects so the editor can distinguish them without guessing.
    $at = ''; $source = ''; $reason = ''; $kind = ''
    if ($value -is [string]) {
        $at = [string]$value
    } elseif ($null -ne $value) {
        try { $at = [string]$value.at } catch { }
        try { $source = [string]$value.source } catch { }
        try { $reason = [string]$value.reason } catch { }
        try { $kind = [string]$value.kind } catch { }
        if (-not $kind) {
            try { if ([bool]$value.auto) { $kind = 'auto' } } catch { }
        }
    }
    if (-not $kind) { $kind = 'manual' }
    $auto = ($kind -in @('auto','quota','limit')) -or
            ($source -match 'quota|free usage|limit') -or
            ($reason -match 'quota|free usage|limit')
    return [pscustomobject]@{
        at = $at; source = $source; reason = $reason; kind = $kind; auto = [bool]$auto
    }
}
function Get-ServerBanInfo([string]$key) {
    if (-not $key) { return $null }
    if (-not $Script:Bans) { Load-Bans }
    if (-not $Script:Bans) { return $null }
    $banKey = $key
    $wildcard = $false
    $prop = $Script:Bans.PSObject.Properties[$banKey]
    if (-not $prop -and $key -match '^(.+:[0-9]{1,5})#[0-9a-fA-F]+$') {
        $banKey = $Matches[1]
        $prop = $Script:Bans.PSObject.Properties[$banKey]
        $wildcard = [bool]$prop
    }
    if (-not $prop) { return $null }
    $info = Get-BanInfo $prop.Value
    $info | Add-Member -NotePropertyName key -NotePropertyValue $banKey -Force
    $info | Add-Member -NotePropertyName wildcard -NotePropertyValue $wildcard -Force
    $info | Add-Member -NotePropertyName requestedKey -NotePropertyValue $key -Force
    return $info
}
function Add-AutoBannedServer([string]$key, [string]$reason = 'free usage limit') {
    # Keep a manual ban manual if it already exists; otherwise create a
    # quota-specific exact ban (even when an endpoint wildcard covers a profile).
    if (-not $key) { return $false }
    Load-Bans
    if ($Script:Bans.PSObject.Properties[$key]) {
        Log ("server is already banned: " + $key)
        return $false
    }
    $record = [pscustomobject]@{
        at     = (Get-Date -Format 'o')
        source = 'automatic'
        reason = $reason
        kind   = 'auto'
    }
    Add-Member -InputObject $Script:Bans -NotePropertyName $key -NotePropertyValue $record -Force
    Save-Bans
    Log ("AUTO-BANNED {0} [{1}] - orange in the bans editor; clear-used does not affect bans" -f $key, $reason)
    return $true
}
function Add-BannedServer([string]$key, [string]$source = '') {
    if (-not $key) { return $false }
    Load-Bans
    if (Test-ServerBanned $key) {
        Log ("server is already banned: " + $key)
        return $false
    }
    Add-Member -InputObject $Script:Bans -NotePropertyName $key -NotePropertyValue (Get-Date -Format 'o') -Force
    Save-Bans
    Log ("BANNED {0}{1} - it will never be selected again (clear-used does not affect bans)" -f $key, $(if ($source) { ' [' + $source + ']' } else { '' }))
    return $true
}
function Remove-BannedServer([string]$key) {
    if (-not $key) { return $false }
    Load-Bans
    if (-not (Test-ServerBanned $key)) {
        Log ("server is not banned: " + $key)
        return $false
    }
    $Script:Bans.PSObject.Properties.Remove($key) | Out-Null
    Save-Bans
    Log ("UNBANNED " + $key + " - it can be selected again")
    return $true
}
function Resolve-ServerKey([string]$value) {
    if (-not $value) { return $null }
    $value = $value.Trim()
    if ($value -ieq 'current') {
        $cur = Get-ActiveServer
        if (-not $cur) { return $null }
        return (Get-ServerKey $cur)
    }
    if ($value -match '^(.+):([0-9]{1,5})#([0-9a-fA-F]+)$') {
        $port = [int]$Matches[2]
        if ($port -ge 1 -and $port -le 65535) { return ('{0}:{1}#{2}' -f $Matches[1].Trim(), $port, $Matches[3].ToLowerInvariant()) }
        return $null
    }
    if ($value -match '^(.+):([0-9]{1,5})$') {
        $port = [int]$Matches[2]
        if ($port -ge 1 -and $port -le 65535) { return ('{0}:{1}' -f $Matches[1].Trim(), $port) }
        return $null
    }
    if ($value -match '^(.+)_([0-9]{1,5})$') {
        $port = [int]$Matches[2]
        if ($port -ge 1 -and $port -le 65535) { return ('{0}:{1}' -f $Matches[1].Trim(), $port) }
    }
    return $null
}

# ------------------------------------------------------------------- registry
function Get-HappCurrentServer {
    $p = Get-ItemProperty -Path $Script:Cfg.HappRegPath -ErrorAction SilentlyContinue
    if ($p -and $p.lastServerHost) {
        return [pscustomobject]@{
            guid = [string]$p.lastServerGuid
            name = [string]$p.lastServerName
            host = [string]$p.lastServerHost
            port = [int]$p.lastServerPort
            sub  = $p.lastSubscription
        }
    }
    return $null
}

# The Happ registry is NOT updated by a pipe-based switch, so it keeps naming
# the server that was active when the GUI last wrote it. Track the real active
# endpoint ourselves and only adopt the registry again when its key changes
# (meaning the user picked a different server in the Happ UI).
function Format-ServerLabel([object]$srv) {
    if (-not $srv -or -not $srv.host) { return '(unknown)' }
    $key = Get-ServerKey $srv
    $name = ''
    try { if ($srv.PSObject.Properties['name']) { $name = ([string]$srv.name).Trim() } } catch { }
    if ($name) { return ('{0} ({1})' -f $key, $name) }
    return $key
}

function New-ActiveRecord([object]$srv, [string]$source) {
    $name = ''
    $key = Get-ServerKey $srv
    try { if ($srv.PSObject.Properties['name']) { $name = [string]$srv.name } } catch { }
    if (-not $name) { $name = Get-CachedServerName ([string]$srv.host) ([int]$srv.port) $key }
    $name = $name.Trim()
    return [pscustomobject]@{
        host   = [string]$srv.host
        port   = [int]$srv.port
        name   = $name
        key    = $key
        since  = (Get-Date -Format 'o')
        source = $source
    }
}

function Get-ActiveServer {
    if (-not $Script:State) { Load-State }
    $reg = Get-HappCurrentServer
    $active = $null
    $seen = $null
    try { if ($Script:State.PSObject.Properties['active']) { $active = $Script:State.active } } catch { }
    try { if ($Script:State.PSObject.Properties['registrySeen']) { $seen = $Script:State.registrySeen } } catch { }
    if ($active -and -not $active.host) { $active = $null }

    $regKey = $null
    $regChanged = $false
    if ($reg -and $reg.host) {
        $regKey = Get-ServerKey $reg
        if ($seen -and $seen.host) {
            $seenKey = Get-ServerKey $seen
            $identityChanged = ($seenKey -ne $regKey)
            # A profile switch can keep host:port identical but change the name.
            $nameChanged = ([string]$seen.name -ne '' -and [string]$reg.name -ne '' -and
                            [string]$seen.name -ne [string]$reg.name)
            $guidChanged = ([string]$seen.guid -ne [string]$reg.guid)
            if ($identityChanged -or $nameChanged -or $guidChanged) { $regChanged = $true }
        } else {
            # No registry snapshot yet (first run after state migration). The
            # registry is the GUI's authoritative selection; do not keep a
            # stale endpoint from an old watchdog run.
            $regChanged = $true
        }
    }

    $changed = $false
    $adoptedLive = $false
    if (-not $active) {
        # The Happ registry is often blank after a manual reconnect. The running
        # core still has live outbound connections to the real server, so use the
        # dominant cached endpoint as a fallback (and to migrate old state).
        $live = Get-LiveServerFromCore
        if ($live) {
            $active = New-ActiveRecord $live 'live'
            $adoptedLive = $true
            $changed = $true
            Log ("active server inferred from running core: {0} ({1} live connections)" -f (Format-ServerLabel $active), $live.connections)
        }
    } elseif (-not $reg -or -not $reg.host) {
        # Saved state can outlive a Happ restart or a manual reconnect. If the
        # registry is blank, compare the active endpoint with the dominant live
        # connection and adopt it after a short settling period. Keep the saved
        # profile key when only the profile identity differs.
        $live = Get-LiveServerFromCore
        if ($live) {
            $activeKey = Get-ServerKey $active
            $activeBase = $activeKey
            if ($activeBase -match '#[0-9a-fA-F]+$') { $activeBase = $activeBase -replace '#[0-9a-fA-F]+$', '' }
            $liveKey = ('{0}:{1}' -f $live.host, $live.port)
            $age = 9999.0
            try {
                if ($active.since) {
                    $age = ((Get-Date) - [datetime]::Parse([string]$active.since)).TotalSeconds
                }
            } catch { }
            if ($activeBase -ne $liveKey -and $age -gt 60 -and [int]$live.connections -ge 5) {
                $active = New-ActiveRecord $live 'live'
                $adoptedLive = $true
                $changed = $true
                Log ("active server corrected from running core: {0} ({1} live connections)" -f (Format-ServerLabel $active), $live.connections)
            }
        }
    }
    # If state and the Happ registry disagree, the live xray connections are the
    # tie-breaker. This also repairs state written by older builds that adopted
    # the registry snapshot without adopting its active server.
    if ($reg -and $reg.host -and $active -and -not $adoptedLive) {
        $activeBase = Get-ServerKey $active
        if ($activeBase -match '#[0-9a-fA-F]+$') { $activeBase = $activeBase -replace '#[0-9a-fA-F]+$', '' }
        if ($activeBase -ne $regKey) {
            $regLive = Get-EndpointLiveConnections ([string]$reg.host) ([int]$reg.port)
            $activeLive = Get-EndpointLiveConnections ([string]$active.host) ([int]$active.port)
            if ($regLive -ge 2 -and $regLive -gt $activeLive) {
                $regChanged = $true
                Log ("registry server {0} has {1} live connections; adopting it over stale state {2}" -f $regKey, $regLive, $activeBase)
            } elseif ($activeLive -ge 2 -and $activeLive -gt $regLive) {
                $regChanged = $false
            }
        }
    }

    $adoptRegistry = $regChanged
    if ($adoptRegistry -and $active -and -not $seen) {
        $activeBase = Get-ServerKey $active
        if ($activeBase -match '#[0-9a-fA-F]+$') { $activeBase = $activeBase -replace '#[0-9a-fA-F]+$', '' }
        if ($activeBase -eq $regKey) { $adoptRegistry = $false }
    }
    if ($reg -and $reg.host -and (-not $active -or ($adoptRegistry -and -not $adoptedLive))) {
        # If the registry name matches a captured profile (e.g. a country on
        # the same endpoint as another server), preserve that profile identity.
        $regTarget = $reg
        $profile = Find-CachedProfileForEndpoint ([string]$reg.host) ([int]$reg.port) ([string]$reg.name)
        if ($profile) { $regTarget = $profile }
        $active = New-ActiveRecord $regTarget 'registry'
        $changed = $true
    }

    if ($reg -and $reg.host) {
        $seenKey = $null
        if ($seen -and $seen.host) { $seenKey = Get-ServerKey $seen }
        if (-not $seen -or $regKey -ne $seenKey -or
            [string]$seen.guid -ne [string]$reg.guid -or
            [string]$seen.name -ne [string]$reg.name) {
            $seen = [pscustomobject]@{
                guid = [string]$reg.guid
                name = [string]$reg.name
                host = [string]$reg.host
                port = [int]$reg.port
                key  = $regKey
            }
            $changed = $true
        }
    }

    if ($changed) {
        if ($active) { $Script:State | Add-Member -NotePropertyName active -NotePropertyValue $active -Force }
        if ($seen) { $Script:State | Add-Member -NotePropertyName registrySeen -NotePropertyValue $seen -Force }
        Save-State
    }
    $Script:ActiveServer = $active
    return $active
}

function Set-ActiveServer([object]$srv) {
    if (-not $srv -or -not $srv.host) { return }
    if (-not $Script:State) { Load-State }
    $key = Get-ServerKey $srv
    $name = ''
    try { if ($srv.PSObject.Properties['name']) { $name = [string]$srv.name } } catch { }
    if (-not $name) { $name = Get-CachedServerName ([string]$srv.host) ([int]$srv.port) $key }
    if (-not $name) {
        try {
            if ($Script:State.active -and (Get-ServerKey $Script:State.active) -eq $key) {
                $name = [string]$Script:State.active.name
            }
        } catch { }
        if (-not $name) {
            $reg = Get-HappCurrentServer
            if ($reg -and (Get-ServerKey $reg) -eq $key) { $name = [string]$reg.name }
        }
    }
    $name = $name.Trim()
    $rec = [pscustomobject]@{
        host   = [string]$srv.host
        port   = [int]$srv.port
        name   = $name
        key    = $key
        since  = (Get-Date -Format 'o')
        source = 'switch'
    }
    $Script:State | Add-Member -NotePropertyName active -NotePropertyValue $rec -Force
    $Script:ActiveServer = $rec
    Save-State
}

# ------------------------------------------------------------------- happd pipe client (burst model)
# Empirically established daemon behavior:
#   - a connection processes every frame written in the same back-to-back burst as the hello
#   - frames written later on the same connection are ignored
#   - the connection OWNS the process spawned in its burst; daemon kills owned
#     records when the owning client disconnects
$Script:DaemonUtil = [pscustomobject]@{ Client = $null; LastBeat = $null }
$Script:PipeRecv = New-Object System.Collections.Generic.List[int]
$Script:OwnedClient = $null
$Script:OwnedBurst = $null
$Script:OwnedTun = $null

function Start-TunBurst {
    # replicate the GUI's system-wide tunnel: daemon start-tun on the sing-box TUN
    param([string]$configPath, [switch]$Fast)
    if (-not (Test-Path $configPath)) { Log ("TUN config missing: " + $configPath); return $null }
    $msgs = @(
        @{
            action = 'start-tun'
            'process-id' = 'sing-box-tun'
            'executable' = $Script:Cfg.TunExe
            'arguments' = @('-c', $configPath)
            'working-dir' = (Split-Path $Script:Cfg.TunExe)
            'address' = $Script:Cfg.TunAddress
            'address-v6' = $Script:Cfg.TunAddressV6
            'iface' = $Script:Cfg.TunIface
            'tun-dns-override' = $Script:Cfg.TunDns
            'auto-restart' = $true
            'max-restart-attempts' = 3
            'restart-delay-ms' = 1000
        }
    )
    $burst = New-Burst -messages $msgs -rids @('tun-start')
    if (-not $burst) { Log 'start-tun burst failed'; return $null }
    Start-Sleep -Milliseconds $(if ($Fast) { 650 } else { 1200 })
    $resp = Read-FramesFrom $burst.Client $burst.Recv -MaxMs $(if ($Fast) { 900 } else { 2500 })
    foreach ($f in $resp) {
        if ($f.'request-id' -eq 'tun-start') { Log ("start-tun resp: status=" + $f.status + $(if ($f.message) { ' ' + $f.message } else { '' })) }
    }
    return $burst
}

function Get-PlainRouteIp {
    param([int]$TimeoutSec = 10)
    try {
        $raw = & curl.exe -s --max-time ([Math]::Max(1, [int]$TimeoutSec)) $Script:Cfg.WebCheckUrl 2>$null
        $joined = ($raw -join '')
        $ip = $null
        try { $ip = ($joined | ConvertFrom-Json).ip } catch { }
        if (-not $ip) { if ($joined -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $ip = $Matches[1] } }
        return [string]$ip
    } catch { return '' }
}

function Compare-JoinKey($a, $b) { return ("$a" -eq "$b") }

function Get-DaemonPipeName {
    $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -like '*\happd-*' }
    if (-not $pipes) { return $null }
    $first = @($pipes)[0]
    return [regex]::Match($first, 'happd-[\dA-Za-z]+$').Value
}

function Open-DaemonSocket {
    $name = Get-DaemonPipeName
    if (-not $name) { return $null }
    try {
        $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
        $c.Connect(1500)
        return $c
    } catch {
        Log ("daemon connect failed: " + $_.Exception.Message)
        return $null
    }
}

function Write-FrameTo {
    param($client, [hashtable]$obj)
    $j = ConvertTo-Json -InputObject $obj -Compress -Depth 30
    $bytes = [Text.Encoding]::UTF8.GetBytes($j)
    $frame = New-Object byte[] (4 + $bytes.Length)
    $lenBytes = [BitConverter]::GetBytes([uint32]$bytes.Length)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }   # big endian on the wire
    [Array]::Copy($lenBytes, $frame, 4)
    [Array]::Copy($bytes, 0, $frame, 4, $bytes.Length)
    try {
        $client.Write($frame, 0, $frame.Length)
        $client.Flush()
        return $true
    } catch {
        Log ("daemon write failed: " + $_.Exception.Message)
        return $false
    }
}

function Read-FramesFrom {
    param($client, [System.Collections.Generic.List[int]]$recv, [int]$MaxMs = 1200)
    $end = (Get-Date).AddMilliseconds($MaxMs)
    $all = New-Object System.Collections.Generic.List[object]
    $chunk = New-Object byte[] 262144
    while ((Get-Date) -lt $end) {
        if ($recv.Count -ge 4) {
            $ln = (($recv[0] * 0x1000000) + ($recv[1] * 0x10000) + ($recv[2] * 0x100) + $recv[3])
            if ($ln -gt 0 -and $recv.Count -ge (4 + $ln)) {
                $payload = New-Object byte[] $ln
                for ($i = 0; $i -lt $ln; $i++) { $payload[$i] = [byte]$recv[4 + $i] }
                $recv.RemoveRange(0, 4 + $ln)
                $txt = [Text.Encoding]::UTF8.GetString($payload)
                try { $all.Add(($txt | ConvertFrom-Json)) } catch { Log ("daemon json parse failed: " + $txt.Substring(0, [Math]::Min(200, $txt.Length))) }
                continue
            }
        }
        try {
            $task = $client.ReadAsync($chunk, 0, $chunk.Length, [System.Threading.CancellationToken]::None)
            if (-not $task.Wait(300)) { continue }
            $n = $task.Result
            if ($n -eq 0) {
                Log 'daemon closed connection'
                return $all
            }
            for ($i = 0; $i -lt $n; $i++) { $recv.Add($chunk[$i]) }
            if ($recv.Count -gt 8388608) { $recv.RemoveRange(0, 4194304) }
        } catch {
            Log ("daemon read failed: " + $_.Exception.Message)
            return $all
        }
    }
    return $all
}

function Send-Daemon {
    # one fresh connection per call (utility): hello + request written back-to-back
    param([hashtable]$obj, [string]$rid = $null, [int]$WaitMs = 2500)
    if (-not $rid) { $rid = 'rq' + (Get-Random) }
    $obj['request-id'] = $rid
    $c = Open-DaemonSocket
    if (-not $c) { return @() }
    $recv = New-Object System.Collections.Generic.List[int]
    $helloId = 'hello-' + (Get-Random)
    $ok1 = Write-FrameTo $c (@{ action = 'client-hello'; version = '4.3.0'; 'request-id' = $helloId })
    $ok2 = Write-FrameTo $c $obj
    if (-not ($ok1 -and $ok2)) { try { $c.Dispose() } catch {}; return @() }
    $out = New-Object System.Collections.Generic.List[object]
    $deadline = (Get-Date).AddMilliseconds($WaitMs)
    while ((Get-Date) -lt $deadline) {
        $left = [int](($deadline - (Get-Date)).TotalMilliseconds)
        if ($left -gt 800) { $left = 800 }
        if ($left -lt 100) { $left = 100 }
        $frames = Read-FramesFrom $c $recv -MaxMs $left
        if ($frames) { foreach ($f in $frames) { $out.Add($f) } }
        foreach ($f in $out) {
            if (Compare-JoinKey $f.'request-id' $rid) {
                try { $c.Dispose() } catch {}
                return $out
            }
        }
    }
    try { $c.Dispose() } catch {}
    return $out
}

function Get-DaemonProcess {
    $r = Send-Daemon -obj @{ action = 'list' } -WaitMs 3500
    foreach ($f in $r) {
        if ($f.status -eq 'success' -and $f.processes) {
            foreach ($p in $f.processes) {
                if (Compare-JoinKey $p.'process-id' $Script:Cfg.ProcessId) { return $p }
            }
        }
    }
    return $null
}

# ------------------------------------------------------------------- GUI memory scan
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class MemApi {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buffer, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MBI info, uint len);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Sequential)]
    public struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }

    public class Hit { public byte[] Data; }

    // full-process scan: returns up to maxTotal context slices around needle hits
    public static List<Hit> Scan(int pid, string[] needles, int maxTotal, int before, int after) {
        List<Hit> hits = new List<Hit>();
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return hits;
        IntPtr addr = IntPtr.Zero;
        long maxAddr = 0x7FFFFFFEFFFF;
        int found = 0;
        byte[] region = null;
        while (addr.ToInt64() < maxAddr && found < maxTotal) {
            MBI mbi;
            if (VirtualQueryEx(h, addr, out mbi, (uint)Marshal.SizeOf(typeof(MBI))) == 0) break;
            long size = mbi.RegionSize.ToInt64();
            IntPtr next = (IntPtr)((long)addr + Math.Max(size, (long)0x1000));
            if (size > 0 && size <= 48L*1024*1024 && mbi.State == 0x1000) {
                if (region == null || region.Length < size) region = new byte[size];
                IntPtr read;
                if (ReadProcessMemory(h, addr, region, (IntPtr)size, out read)) {
                    int n = (int)read;
                    for (int k = 0; k < needles.Length && found < maxTotal; k++) {
                        byte[] nb = System.Text.Encoding.ASCII.GetBytes(needles[k]);
                        int i = 0;
                        while (n - i >= nb.Length && found < maxTotal) {
                            int pos = IndexOfSub(region, i, n, nb);
                            if (pos < 0) break;
                            i = pos + nb.Length;
                            int start = Math.Max(0, pos - before);
                            int len = Math.Min((pos + after) - start, n - start);
                            byte[] slice = new byte[len];
                            Array.Copy(region, start, slice, 0, len);
                            hits.Add(new Hit{ Data = slice });
                            found++;
                        }
                    }
                }
            }
            addr = next;
        }
        CloseHandle(h);
        return hits;
    }

    static int IndexOfSub(byte[] b, int from, int to, byte[] needle) {
        for (int i = from; i <= to - needle.Length; i++) {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++) { if (b[i + j] != needle[j]) { ok = false; break; } }
            if (ok) return i;
        }
        return -1;
    }
}
'@

function Get-JsonConfigFromText([string]$text) {
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches($text, '"outbounds"')) {
        $idx = $m.Index
        $limit = [Math]::Max(0, $idx - 20000)
        $start = $idx
        while ($start -ge $limit) {
            if ($text[$start] -eq '{') {
                $frag = $text.Substring($start)
                $depth = 0; $inStr = $false; $esc = $false; $endIdx = -1
                for ($i = 0; $i -lt $frag.Length; $i++) {
                    $ch = $frag[$i]
                    if ($esc) { $esc = $false; continue }
                    if ($ch -eq '\') { $esc = $true; continue }
                    if ($ch -eq '"') { $inStr = (-not $inStr); continue }
                    if ($inStr) { continue }
                    if ($ch -eq '{') { $depth++ }
                    elseif ($ch -eq '}') { $depth--; if ($depth -eq 0) { $endIdx = $i; break } }
                }
                if ($endIdx -gt 0 -and $endIdx -gt 400) {
                    $cand = $frag.Substring(0, $endIdx + 1)
                    if ($cand -match '"outbounds"' -and $cand.Length -gt 600) {
                        try {
                            $o = $cand | ConvertFrom-Json
                            if ($o.outbounds) { $found.Add($o) }
                            break
                        } catch { }
                    }
                }
            }
            $start--
        }
    }
    return $found
}

function Update-ConfigCache {
    Log 'scanning GUI memory for server configs...'
    $gui = Get-Process Happ -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $gui) { Log 'Happ GUI not running'; return 0 }
    $needles = @('"outbounds"', '"protocol":"vless"', '"protocol": "vless"')
    $hits = [MemApi]::Scan($gui.Id, $needles, 150, 300, 26000)
    Log ("memory scan: " + $hits.Count + " hits")
    $saved = 0
    $aliases = 0
    $total = (Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json' -ErrorAction SilentlyContinue).Count
    foreach ($hit in $hits) {
        $text = [Text.Encoding]::UTF8.GetString($hit.Data)
        foreach ($o in (Get-JsonConfigFromText $text)) {
            Repair-CacheConfigKeys $o
            foreach ($ob in @($o.outbounds)) {
                if ($ob.protocol -notin @('vless','hysteria','vmess','trojan') -or -not $ob.settings) { continue }
                $addr = ''
                $port = 0
                try {
                    if ($ob.settings.vnext -and $ob.settings.vnext[0]) {
                        $addr = [string]$ob.settings.vnext[0].address
                        $port = [int]$ob.settings.vnext[0].port
                    } elseif ($ob.protocol -eq 'hysteria' -and $ob.settings.address) {
                        $addr = [string]$ob.settings.address
                        $port = [int]$ob.settings.port
                    }
                } catch { }
                if ($addr -in @('0.0.0.0','::','localhost','auto-wifi.local') -or $addr -like '127.*') { continue }
                if (-not $addr -or $port -lt 1 -or $port -gt 65535) {
                    Log ("cache skip: captured config has no usable address (remarks '" + ([string]$o.remarks) + "')")
                    continue
                }
                $key = ('{0}_{1}' -f $addr, $port)
                $file = Join-Path $Script:Cfg.ConfigCacheDir ($key + '.json')
                if (-not (Test-Path $file)) {
                    try {
                        $o | ConvertTo-Json -Depth 30 | Set-Content $file -Encoding utf8
                        $saved++; $total++
                        Log ("cached config: " + $key)
                    } catch { Log ("cache save failed " + $key + ": " + $_.Exception.Message) }
                } elseif (Add-CacheAlias $file ([string]$o.remarks)) {
                    $aliases++
                    Log ("cached alias: " + ([string]$o.remarks) + " -> " + $key)
                }
            }
        }
    }
    Log ("config cache scan done: new=$saved aliases=$aliases total=$total")
    return ($saved + $aliases)
}

# --------------------------------------------------------------- capture mode
# [U] / -CaptureAll: the tool runs the persistent Happ memory scanner while the
# user clicks Happ -> ... -> Ping all, then imports the snapshots and refreshes
# the cache. The scanner stays a child process so the dashboard never blocks on
# a full memory scan; its output is tailed into the event log.
function Get-PythonLauncher {
    foreach ($name in @('python', 'python3')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandType -eq 'Application' } | Select-Object -First 1
        if ($cmd -and $cmd.Source -and (Test-Path $cmd.Source)) {
            return [pscustomobject]@{ exe = [string]$cmd.Source; prefix = '' }
        }
    }
    $cmd = Get-Command py -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandType -eq 'Application' } | Select-Object -First 1
    if ($cmd -and $cmd.Source -and (Test-Path $cmd.Source)) {
        return [pscustomobject]@{ exe = [string]$cmd.Source; prefix = '-3' }
    }
    return $null
}

function Get-CaptureFileCount {
    return @(Get-ChildItem $Script:Cfg.CapturesDir -Filter 'capture-*.json' -File -ErrorAction SilentlyContinue).Count
}

function Read-CaptureProcessOutput {
    if (-not $Script:Capture) { return }
    try {
        $outLog = [string]$Script:Capture.outLog
        if (Test-Path $outLog) {
            $lines = @(Get-Content $outLog -Encoding UTF8 -ErrorAction Stop)
            $last = [int]$Script:Capture.lastOut
            if ($last -lt 0) { $last = 0 }
            for ($i = $last; $i -lt $lines.Count; $i++) {
                $line = [string]$lines[$i]
                if (-not $line.Trim()) { continue }
                if ($line -match '^CAPTURE ') {
                    Log ('[capture] ' + $line)
                } elseif ($line -match '^unique configs captured:') {
                    Log ('[capture] ' + $line)
                } elseif ($line -match '(?i)(traceback|error|exception|failed)') {
                    Log ('[capture] ' + $line)
                }
            }
            $Script:Capture.lastOut = $lines.Count
        }
    } catch { }
    try {
        $errLog = [string]$Script:Capture.errLog
        if (Test-Path $errLog) {
            $errLines = @(Get-Content $errLog -Encoding UTF8 -ErrorAction Stop)
            $last = [int]$Script:Capture.lastErr
            if ($last -lt 0) { $last = 0 }
            for ($i = $last; $i -lt $errLines.Count; $i++) {
                $line = [string]$errLines[$i]
                if ($line.Trim()) { Log ('[capture] ' + $line) }
            }
            $Script:Capture.lastErr = $errLines.Count
        }
    } catch { }
}

function Import-CapturedProfiles {
    $py = Get-PythonLauncher
    if (-not $py) {
        Log 'profile import skipped: Python 3 was not found'
        return 0
    }
    $script = Join-Path $Script:Cfg.ToolDir 'import-happ-profiles.py'
    if (-not (Test-Path $script)) {
        Log ('profile import skipped: missing ' + $script)
        return 0
    }
    $argv = @()
    if ($py.prefix) { $argv += $py.prefix }
    $argv += @($script, '--captures', $Script:Cfg.CapturesDir, '--cache', $Script:Cfg.ConfigCacheDir)
    $created = 0
    try {
        $out = & $py.exe @argv 2>&1
        foreach ($line in @($out)) {
            $s = [string]$line
            if (-not $s.Trim()) { continue }
            if ($s -match '^create=(\d+)') {
                $created = [int]$Matches[1]
                Log ('[import] ' + $s)
            } elseif ($s -match '^(created |PARSE FAIL|usage:|import-happ-profiles\.py: error)') {
                Log ('[import] ' + $s)
            }
        }
    } catch {
        Log ('profile import failed: ' + $_.Exception.Message)
    }
    return $created
}

function Start-CaptureMode {
    param([int]$Seconds = 0)
    if ($Script:Capture) {
        Log 'continuous capture is already running - press [U] to stop and import'
        return $false
    }
    if (-not (Get-Process Happ -ErrorAction SilentlyContinue | Select-Object -First 1)) {
        Log 'continuous capture: Happ GUI is not running'
        return $false
    }
    $py = Get-PythonLauncher
    if (-not $py) {
        Log 'continuous capture needs Python 3 (python.exe or py.exe) - install Python or run the capture scripts manually'
        return $false
    }
    $script = Join-Path $Script:Cfg.ToolDir 'capture-happ-memory.py'
    if (-not (Test-Path $script)) {
        Log ('continuous capture: missing ' + $script)
        return $false
    }
    if ($Seconds -le 0) { $Seconds = [int]$Script:Cfg.CaptureWindowSec }
    if (-not (Test-Path $Script:Cfg.CapturesDir)) {
        New-Item -ItemType Directory -Force -Path $Script:Cfg.CapturesDir | Out-Null
    }
    $outLog = Join-Path $Script:Cfg.CapturesDir 'capture-run.out.log'
    $errLog = Join-Path $Script:Cfg.CapturesDir 'capture-run.err.log'
    foreach ($f in @($outLog, $errLog)) {
        try { Remove-Item $f -Force -ErrorAction SilentlyContinue } catch { }
    }
    # Python always expects a dot decimal separator; -f would use the local
    # culture and turn 0.3 into 0,3 on a Russian Windows install.
    $interval = ([double]$Script:Cfg.CaptureIntervalSec).ToString([Globalization.CultureInfo]::InvariantCulture)
    $argLine = '"{0}" --seconds {1} --interval {2} --out "{3}"' -f $script, $Seconds, $interval, $Script:Cfg.CapturesDir
    if ($py.prefix) { $argLine = $py.prefix + ' ' + $argLine }
    try {
        $proc = Start-Process -FilePath $py.exe -ArgumentList $argLine `
            -WorkingDirectory $Script:Cfg.ToolDir -WindowStyle Hidden `
            -RedirectStandardOutput $outLog -RedirectStandardError $errLog -PassThru
    } catch {
        Log ('continuous capture failed to start: ' + $_.Exception.Message)
        return $false
    }
    $Script:Capture = @{
        proc     = $proc
        started  = Get-Date
        seconds  = $Seconds
        outLog   = $outLog
        errLog   = $errLog
        lastOut  = 0
        lastErr  = 0
        baseline = (Get-CaptureFileCount)
    }
    Log ("continuous capture ON for {0}s - run Happ -> ... -> Ping all now; press [U] to stop and import" -f $Seconds)
    return $true
}

function Stop-CaptureMode {
    param([switch]$NoImport)
    if (-not $Script:Capture) { return }
    $cap = $Script:Capture
    try {
        if ($cap.proc -and -not $cap.proc.HasExited) {
            $cap.proc.Kill()
            $null = $cap.proc.WaitForExit(5000)
        }
    } catch { }
    Read-CaptureProcessOutput
    $Script:Capture = $null
    $count = Get-CaptureFileCount
    $newCount = [Math]::Max(0, $count - [int]$cap.baseline)
    Log ("continuous capture stopped: {0} capture file(s) on disk ({1} new)" -f $count, $newCount)
    if ($NoImport) { return }
    if ($newCount -le 0) {
        Log 'no new captures - did you run Happ -> ... -> Ping all while capture was ON?'
    }
    $created = Import-CapturedProfiles
    try { Update-ConfigCache | Out-Null } catch { Log ('cache refresh failed: ' + $_.Exception.Message) }
    $cacheCount = @(Get-CachedServerList).Count
    Log ("server cache refreshed: {0} entries; imported {1} new profile file(s) - press [L] to view the list" -f $cacheCount, $created)
}

function Update-CaptureMode {
    if (-not $Script:Capture) { return }
    Read-CaptureProcessOutput
    $p = $Script:Capture.proc
    if ($p -and $p.HasExited) {
        Log ("capture scanner exited (code {0}) - importing captures" -f $p.ExitCode)
        Stop-CaptureMode
    }
}

function Show-CachedServers {
    if (-not $Script:State) { Load-State }
    $list = @(Get-CachedServerList | Sort-Object host, port, key)
    $endpoints = @($list | ForEach-Object { '{0}:{1}' -f $_.host, $_.port } | Sort-Object -Unique).Count
    $profiles = @($list | Where-Object { $_.profileHash }).Count
    $active = Get-ActiveServer
    $activeKey = $null
    if ($active) { $activeKey = Get-ServerKey $active }
    Write-Host ''
    Write-Host ("cached servers: {0} ({1} endpoints, {2} profiles)" -f $list.Count, $endpoints, $profiles)
    foreach ($srv in $list) {
        $key = Get-ServerKey $srv
        $name = ([string](Get-CachedServerName ([string]$srv.host) ([int]$srv.port) $key)).Trim()
        $tags = @()
        if ($activeKey -and $key -eq $activeKey) { $tags += 'active' }
        if (Test-ServerBanned $key) { $tags += 'banned' }
        try { if ($Script:State.used.PSObject.Properties[$key]) { $tags += 'used' } } catch { }
        $suffix = ''
        if ($tags.Count) { $suffix = '  [' + ($tags -join ', ') + ']' }
        Write-Host ("{0,-46} {1}{2}" -f $key, $name, $suffix)
    }
    Write-Host ''
}

function Get-ServerFromCacheKey([string]$key) {
    # Profile files are <host>_<port>__<hash>.json. They represent a distinct
    # credential/transport profile that can share host:port with another server.
    if ($key -match '^(.+)_([0-9]{1,5})__([0-9a-fA-F]+)$') {
        $port = 0
        if (-not [int]::TryParse($Matches[2], [ref]$port)) { return $null }
        if ($port -lt 1 -or $port -gt 65535) { return $null }
        $hostName = $Matches[1]
        $hash = $Matches[3].ToLowerInvariant()
        return [pscustomobject]@{
            host        = $hostName
            port        = $port
            key         = ('{0}:{1}#{2}' -f $hostName, $port, $hash)
            profileHash = $hash
        }
    }
    $li = $key.LastIndexOf('_')
    if ($li -lt 1) { return $null }
    $hostName = $key.Substring(0, $li)
    $port = 0
    if (-not [int]::TryParse($key.Substring($li + 1), [ref]$port)) { return $null }
    if ($port -lt 1 -or $port -gt 65535) { return $null }
    return [pscustomobject]@{
        host        = $hostName
        port        = $port
        key         = ('{0}:{1}' -f $hostName, $port)
        profileHash = ''
    }
}

function Get-CachedConfigPath([string]$srvHost, [int]$srvPort, [string]$Key = '') {
    $hash = ''
    if ($Key -and ($Key -match '#([0-9a-fA-F]+)$')) { $hash = $Matches[1].ToLowerInvariant() }
    if ($hash) {
        return (Join-Path $Script:Cfg.ConfigCacheDir ("{0}_{1}__{2}.json" -f $srvHost, $srvPort, $hash))
    }
    return (Join-Path $Script:Cfg.ConfigCacheDir ("{0}_{1}.json" -f $srvHost, $srvPort))
}

function Find-CachedProfileForEndpoint([string]$srvHost, [int]$srvPort, [string]$Name) {
    if (-not $srvHost -or $srvPort -lt 1 -or $srvPort -gt 65535) { return $null }
    $wanted = ([string]$Name).Trim()
    if (-not $wanted) { return $null }
    $pattern = ('{0}_{1}__*.json' -f $srvHost, $srvPort)
    foreach ($f in @(Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter $pattern -File -ErrorAction SilentlyContinue)) {
        try {
            $cfg = Get-Content $f.FullName -Raw -Encoding utf8 | ConvertFrom-Json
            Repair-CacheConfigKeys $cfg
            $remarks = ([string]$cfg.remarks).Trim()
            if ($remarks -and $remarks -ieq $wanted) {
                return (Get-ServerFromCacheKey $f.BaseName)
            }
        } catch { }
    }
    return $null
}

function Get-CachedServerList {
    $list = @()
    foreach ($f in (Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json' -ErrorAction SilentlyContinue)) {
        try { $srv = Get-ServerFromCacheKey $f.BaseName } catch { $srv = $null }
        if ($srv) { $list += $srv }
    }
    return $list
}

function Get-ShuffledItems {
    param([object[]]$Items)
    $arr = @($Items)
    for ($i = $arr.Count - 1; $i -gt 0; $i--) {
        $j = Get-Random -Minimum 0 -Maximum ($i + 1)
        $tmp = $arr[$i]
        $arr[$i] = $arr[$j]
        $arr[$j] = $tmp
    }
    return $arr
}

# ------------------------------------------------------------------- reliability
# Per-server switch history so that server choice gets smarter over time:
#  - every switch is verified by an exit-IP test; success/failure and the exit IP are
#    recorded per server ('SWITCH OK' -> ok=true + exit IP; 'exit check failed' -> fail)
#  - a server that just failed verify is demoted for FailSkipMin minutes (it costs a
#    full attempt slot: pipe burst + verify retries + revert),
#  - a server whose last observed exit IP was seen within ExitIpFreshMin is demoted:
#    OpenCode's free-model quota is per public exit IP, so a recently exited IP is a
#    wall the switch would land on; servers never switched to carry no record and
#    stay fully preferred.
function Get-ReliabilityRecord([string]$key) {
    if (-not $key) { return $null }
    $rel = $Script:State.reliability
    if (-not $rel) { return $null }
    $p = $rel.PSObject.Properties[$key]
    if ($p) { return $p.Value }
    return $null
}
function Update-Reliability([string]$key, [bool]$ok, [string]$exitIp = '') {
    if (-not $key) { return }
    $rel = $Script:State.reliability
    if (-not $rel) {
        $rel = New-Object PSObject
        Add-Member -InputObject $Script:State -NotePropertyName reliability -NotePropertyValue $rel -Force
    }
    $rec = Get-ReliabilityRecord $key
    if (-not $rec) {
        $rec = New-Object PSObject
        Add-Member -InputObject $rel -NotePropertyName $key -NotePropertyValue $rec -Force
    }
    $now = Get-Date -Format 'o'
    if ($ok) {
        Add-Member -InputObject $rec -NotePropertyName lastOk -NotePropertyValue $now -Force
        Add-Member -InputObject $rec -NotePropertyName lastFail -NotePropertyValue '' -Force
        $okCount = 0
        try { $okCount = [int]$rec.okCount } catch { }
        Add-Member -InputObject $rec -NotePropertyName okCount -NotePropertyValue ($okCount + 1) -Force
        Add-Member -InputObject $rec -NotePropertyName failStreak -NotePropertyValue 0 -Force
    } else {
        Add-Member -InputObject $rec -NotePropertyName lastFail -NotePropertyValue $now -Force
        $failCount = 0
        try { $failCount = [int]$rec.failCount } catch { }
        $failStreak = 0
        try { $failStreak = [int]$rec.failStreak } catch { }
        Add-Member -InputObject $rec -NotePropertyName failCount -NotePropertyValue ($failCount + 1) -Force
        Add-Member -InputObject $rec -NotePropertyName failStreak -NotePropertyValue ($failStreak + 1) -Force
    }
    if ($exitIp) {
        Add-Member -InputObject $rec -NotePropertyName lastExitIp -NotePropertyValue ([string]$exitIp) -Force
        Add-Member -InputObject $rec -NotePropertyName lastExitAt -NotePropertyValue $now -Force
    }
    Save-State
}
function Test-RecentFail([string]$key) {
    $rec = Get-ReliabilityRecord $key
    if (-not $rec -or -not $rec.lastFail) { return $false }
    try {
        # parse into [datetime] - subtracting DateTimeOffset from DateTime throws
        $t = [datetime]::Parse([string]$rec.lastFail)
        if (((Get-Date) - $t).TotalMinutes -lt $Script:Cfg.FailSkipMin) { return $true }
    } catch { }
    return $false
}
function Get-RecentExitIpSet {
    # exit IPs observed (on any server) within the freshness window - candidates whose
    # own last exit IP is in this set would land on a burdened IP again
    $set = @{}
    $rel = $Script:State.reliability
    if (-not $rel) { return $set }
    foreach ($p in $rel.PSObject.Properties) {
        $ip = $p.Value.lastExitIp
        $at = $p.Value.lastExitAt
        if (-not $ip -or -not $at) { continue }
        try {
            $t = [datetime]::Parse([string]$at)
            if (((Get-Date) - $t).TotalMinutes -lt $Script:Cfg.ExitIpFreshMin) { $set[[string]$ip] = $true }
        } catch { }
    }
    return $set
}
function Optimize-CandidateOrder {
    # Re-order switch candidates: preferred servers first (shuffled, so distribution
    # stays even inside the preferred group), demoted ones last (still reachable when
    # nothing stronger exists; the attempt loop walks the list top-down until a
    # switch verifies). Never empties the list - the rotation-cycle-2 reset stays
    # triggered only by true exhaustion of the unused pool.
    param([object[]]$Candidates)
    $result = [pscustomobject]@{
        ordered     = @()
        preferred   = 0
        recentFail  = 0
        staleExitIp = 0
        bogusHost   = 0
    }
    $pref = @()
    $fall = @()
    $recentIps = Get-RecentExitIpSet
    foreach ($srv in $Candidates) {
        $key = Get-ServerKey $srv
        if (-not $key) { continue }
        if (([string]$srv.host -eq '0.0.0.0') -or ([string]$srv.host -match '^127\.')) { $result.bogusHost++; $fall += $srv; continue }
        if (Test-RecentFail $key) { $result.recentFail++; $fall += $srv; continue }
        $rec = Get-ReliabilityRecord $key
        if ($rec -and $rec.lastExitIp -and $recentIps.ContainsKey([string]$rec.lastExitIp)) { $result.staleExitIp++; $fall += $srv; continue }
        $pref += $srv
    }
    $result.preferred = $pref.Count
    foreach ($s in @(Get-ShuffledItems $pref)) { $result.ordered = @($result.ordered) + $s }
    foreach ($s in @(Get-ShuffledItems $fall)) { $result.ordered = @($result.ordered) + $s }
    return $result
}

function Get-CachedOutbound {
    param([string]$srvHost, [int]$srvPort, [string]$ProfileKey = '')
    $file = Get-CachedConfigPath $srvHost $srvPort $ProfileKey
    if (-not (Test-Path $file)) { return $null }
    try {
        $tpl = Get-Content $file -Raw -Encoding utf8 | ConvertFrom-Json
        Repair-CacheConfigKeys $tpl
        foreach ($ob in $tpl.outbounds) {
            if ($ob.protocol -notin @('vless','hysteria','vmess','trojan') -or -not $ob.settings) { continue }
            if ($ob.settings.vnext -and $ob.settings.vnext[0]) {
                $v = $ob.settings.vnext[0]
                if ($v.address -eq $srvHost -and $v.port -eq $srvPort) { return $ob }
            } elseif ($ob.protocol -eq 'hysteria' -and $ob.settings.address) {
                if ([string]$ob.settings.address -eq $srvHost -and [int]$ob.settings.port -eq $srvPort) { return $ob }
            }
        }
    } catch { }
    return $null
}

function Get-CachedServerName([string]$srvHost, [int]$srvPort, [string]$ProfileKey = '') {
    $file = Get-CachedConfigPath $srvHost $srvPort $ProfileKey
    if (-not (Test-Path $file)) {
        if ($ProfileKey -and $ProfileKey -match '#') {
            # Keep the endpoint label as a fallback if a profile file vanished.
            $file = Get-CachedConfigPath $srvHost $srvPort
        }
        if (-not (Test-Path $file)) { return '' }
    }
    try {
        $cfg = Get-Content $file -Raw -Encoding utf8 | ConvertFrom-Json
        if ($cfg.remarks) { return ([string]$cfg.remarks).Trim() }
    } catch { }
    return ''
}

function Repair-CacheConfigKeys([object]$obj) {
    # Memory captures occasionally contain a control byte where one letter of a
    # JSON key was overwritten. Recover the two keys that matter for endpoint
    # extraction. Without this a config can land in the cache as "_443.json".
    if ($null -eq $obj) { return }
    if ($obj -is [System.Collections.IList] -and $obj -isnot [string]) {
        foreach ($x in @($obj)) { Repair-CacheConfigKeys $x }
        return
    }
    if ($obj -is [System.Management.Automation.PSCustomObject]) {
        foreach ($prop in @($obj.PSObject.Properties)) {
            $key = [string]$prop.Name
            $fixed = $key
            if ($key -match '^add[\x00-\x1F]ess$') { $fixed = 'address' }
            elseif ($key -match '^stre[\x00-\x1F]mSettings$') { $fixed = 'streamSettings' }
            if ($fixed -ne $key) {
                $value = $prop.Value
                try { $obj.PSObject.Properties.Remove($key) } catch { }
                Add-Member -InputObject $obj -NotePropertyName $fixed -NotePropertyValue $value -Force
            }
            Repair-CacheConfigKeys $prop.Value
        }
    }
}

function Get-CachedConfigMeta([object]$cfg) {
    $remarks = ''
    try { $remarks = ([string]$cfg.remarks).Trim() } catch { }
    foreach ($ob in @($cfg.outbounds)) {
        if (-not $ob -or $ob.protocol -notin @('vless','vmess','trojan','hysteria')) { continue }
        $addr = ''
        $port = 0
        try {
            if ($ob.settings.vnext -and $ob.settings.vnext[0]) {
                $v = $ob.settings.vnext[0]
                if ($v.address) { $addr = [string]$v.address }
                if ($v.port) { $port = [int]$v.port }
            } elseif ($ob.settings.address) {
                $addr = [string]$ob.settings.address
                if ($ob.settings.port) { $port = [int]$ob.settings.port }
            }
        } catch { }
        if ($addr -and $port -ge 1 -and $port -le 65535) {
            return [pscustomobject]@{ host = $addr; port = $port; remarks = $remarks }
        }
    }
    return $null
}

function Get-CachedServerAliasMap {
    # Endpoint -> every captured display name for that endpoint. A valid
    # host_port file is the primary name; malformed files (e.g. a corrupted
    # address) and remarksAliases contribute alternate names.
    $files = @(Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json' -File -ErrorAction SilentlyContinue)
    $stamp = 0L
    foreach ($f in $files) {
        if ($f.LastWriteTimeUtc.Ticks -gt $stamp) { $stamp = $f.LastWriteTimeUtc.Ticks }
    }
    $signature = ('{0}|{1}|{2}' -f $files.Count, $stamp, $Script:Cfg.ConfigCacheDir)
    if ($Script:CachedAliasMap -and $Script:CacheAliasSignature -eq $signature) {
        return $Script:CachedAliasMap
    }
    $map = @{}
    foreach ($f in $files) {
        if ($f.BaseName -match '__[0-9a-fA-F]+$') { continue }
        if ($f.BaseName -notmatch '^(.+)_(\d+)$') { continue }
        $key = $Matches[1] + ':' + $Matches[2]
        try { $cfg = Get-Content $f.FullName -Raw -Encoding utf8 | ConvertFrom-Json } catch { continue }
        Repair-CacheConfigKeys $cfg
        if (-not $map.ContainsKey($key)) { $map[$key] = New-Object System.Collections.Generic.List[string] }
        $names = @()
        try { if ($cfg.remarks) { $names += ([string]$cfg.remarks).Trim() } } catch { }
        try { foreach ($a in @($cfg.remarksAliases)) { if ($a) { $names += ([string]$a).Trim() } } } catch { }
        foreach ($n in $names) {
            if ($n -and -not $map[$key].Contains($n)) { $map[$key].Add($n) }
        }
    }
    foreach ($f in $files) {
        if ($f.BaseName -match '__[0-9a-fA-F]+$') { continue }
        if ($f.BaseName -match '^(.+)_(\d+)$') { continue }
        try { $cfg = Get-Content $f.FullName -Raw -Encoding utf8 | ConvertFrom-Json } catch { continue }
        Repair-CacheConfigKeys $cfg
        $meta = Get-CachedConfigMeta $cfg
        if (-not $meta) { continue }
        $key = $meta.host + ':' + $meta.port
        if (-not $map.ContainsKey($key)) { $map[$key] = New-Object System.Collections.Generic.List[string] }
        $n = ([string]$meta.remarks).Trim()
        if ($n -and -not $map[$key].Contains($n)) { $map[$key].Add($n) }
    }
    $Script:CachedAliasMap = $map
    $Script:CacheAliasSignature = $signature
    return $map
}

function Add-CacheAlias([string]$file, [string]$name) {
    $name = ([string]$name).Trim()
    if (-not $file -or -not $name -or -not (Test-Path $file)) { return $false }
    try {
        $cfg = Get-Content $file -Raw -Encoding utf8 | ConvertFrom-Json
        $primary = ''
        try { $primary = ([string]$cfg.remarks).Trim() } catch { }
        if ($name -eq $primary) { return $false }
        $aliases = @()
        try { $aliases = @($cfg.remarksAliases | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) } catch { }
        if ($aliases -contains $name) { return $false }
        $aliases = @($aliases) + $name
        $cfg | Add-Member -NotePropertyName remarksAliases -NotePropertyValue @($aliases) -Force
        $tmp = $file + '.tmp'
        $cfg | ConvertTo-Json -Depth 30 | Set-Content $tmp -Encoding utf8
        Move-Item -Force -Path $tmp -Destination $file
        return $true
    } catch {
        Log ("cache alias failed for " + $file + ": " + $_.Exception.Message)
        return $false
    }
}

function Get-CachedEndpointIpMap {
    # Resolve cached domain endpoints so live xray connections (which use IPs)
    # can be mapped back to host:port keys. Do this rarely; DNS can be slow.
    $now = Get-Date
    try {
        if ($Script:EndpointIpMap -and $Script:EndpointIpMapAt -and
            ($now - $Script:EndpointIpMapAt).TotalMinutes -lt 10) {
            return $Script:EndpointIpMap
        }
    } catch { }

    $byHost = @{}
    try {
        Get-ChildItem -Path $Script:Cfg.ConfigCacheDir -Filter '*.json' -File -ErrorAction Stop | ForEach-Object {
            $srv = Get-ServerFromCacheKey $_.BaseName
            if (-not $srv -or $srv.profileHash) { return }
            $h = [string]$srv.host
            if (-not $h -or $h -match '^\d{1,3}(\.\d{1,3}){3}$' -or $h -match ':') { return }
            if ($h -in @('auto-wifi.local','auto-lte.local','localhost')) { return }
            if (-not $byHost.ContainsKey($h)) { $byHost[$h] = New-Object System.Collections.Generic.List[int] }
            if (-not $byHost[$h].Contains([int]$srv.port)) { $byHost[$h].Add([int]$srv.port) }
        }
    } catch { return @{} }

    $map = @{}
    foreach ($h in @($byHost.Keys)) {
        $ips = @()
        try {
            $ips = @(Resolve-DnsName -Name $h -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
                Where-Object { $_.IPAddress } | ForEach-Object { [string]$_.IPAddress })
        } catch { $ips = @() }
        foreach ($ip in $ips) {
            foreach ($port in @($byHost[$h])) {
                $k = ('{0}:{1}' -f $ip, $port)
                if (-not $map.ContainsKey($k)) { $map[$k] = ('{0}:{1}' -f $h, $port) }
                elseif ($map[$k] -ne ('{0}:{1}' -f $h, $port)) { $map[$k] = $null }
            }
        }
    }
    $Script:EndpointIpMap = $map
    $Script:EndpointIpMapAt = $now
    return $map
}

function Get-LiveServerFromCore {
    # Best-effort fallback for when state and the Happ registry are both blank:
    # xray keeps many TCP connections to the server it is actually proxying
    # through. Rank cached endpoints by established connection count and accept
    # only a clear winner. (UDP-only transports simply fall through.)
    $now = Get-Date
    $last = $null
    try { $last = $Script:LastLiveCoreProbe } catch { }
    if ($last -and ($now - $last).TotalSeconds -lt 5) { return $null }
    $Script:LastLiveCoreProbe = $now

    $cached = @{}
    try {
        Get-ChildItem -Path $Script:Cfg.ConfigCacheDir -Filter '*.json' -File -ErrorAction Stop | ForEach-Object {
            $srv = Get-ServerFromCacheKey $_.BaseName
            if (-not $srv -or $srv.profileHash) { return }
            $cached[('{0}:{1}' -f $srv.host, $srv.port)] = $true
        }
    } catch { return $null }
    if ($cached.Count -eq 0) { return $null }

    $procs = @(Get-Process xray -ErrorAction SilentlyContinue)
    if (-not $procs) { return $null }

    $allCounts = @{}
    $counts = @{}
    foreach ($proc in $procs) {
        try {
            $conns = @(Get-NetTCPConnection -OwningProcess $proc.Id -State Established -ErrorAction SilentlyContinue)
        } catch { continue }
        foreach ($c in $conns) {
            if (-not $c.RemoteAddress) { continue }
            $addr = ([string]$c.RemoteAddress) -replace '^::ffff:', ''
            $key = ('{0}:{1}' -f $addr, [int]$c.RemotePort)
            if ($allCounts.ContainsKey($key)) { $allCounts[$key]++ } else { $allCounts[$key] = 1 }
            if (-not $cached.ContainsKey($key)) { continue }
            if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts[$key] = 1 }
        }
    }
    if ($allCounts.Count -eq 0) { return $null }

    $needDns = ($counts.Count -eq 0)
    if (-not $needDns) {
        foreach ($entry in @($allCounts.GetEnumerator())) {
            if (-not $cached.ContainsKey([string]$entry.Key) -and [int]$entry.Value -ge 2) {
                $needDns = $true
                break
            }
        }
    }
    if ($needDns) {
        $ipMap = Get-CachedEndpointIpMap
        foreach ($entry in @($allCounts.GetEnumerator())) {
            if ($cached.ContainsKey([string]$entry.Key)) { continue }
            $mapped = $null
            if ($ipMap -and $ipMap.ContainsKey([string]$entry.Key)) { $mapped = $ipMap[[string]$entry.Key] }
            if (-not $mapped) { continue }
            if ($counts.ContainsKey($mapped)) { $counts[$mapped] += [int]$entry.Value }
            else { $counts[$mapped] = [int]$entry.Value }
        }
    }
    if ($counts.Count -eq 0) { return $null }
    $ranked = @($counts.GetEnumerator() | Sort-Object Value -Descending)
    $top = $ranked[0]
    if ([int]$top.Value -lt 2) { return $null }
    if ($ranked.Count -gt 1 -and [int]$ranked[1].Value -ge [int]$top.Value) { return $null }
    $sep = ([string]$top.Key).LastIndexOf(':')
    if ($sep -lt 1) { return $null }
    return [pscustomobject]@{
        host        = ([string]$top.Key).Substring(0, $sep)
        port        = [int]([string]$top.Key).Substring($sep + 1)
        connections = [int]$top.Value
    }
}

function Get-EndpointLiveConnections {
    # Count established xray connections to a specific endpoint, even when the
    # active server was selected manually in Happ and is not in our cache.
    param([string]$srvHost, [int]$srvPort)
    if (-not $srvHost -or $srvPort -lt 1) { return 0 }
    $now = Get-Date
    $cacheKey = ('{0}:{1}' -f $srvHost, $srvPort)
    try {
        if ($Script:EndpointLiveCache -and $Script:EndpointLiveCache.ContainsKey($cacheKey)) {
            $hit = $Script:EndpointLiveCache[$cacheKey]
            if (($now - $hit.at).TotalSeconds -lt 3) { return [int]$hit.count }
        }
    } catch { }
    $ips = @()
    if ($srvHost -match '^\d{1,3}(\.\d{1,3}){3}$') {
        $ips = @($srvHost)
    } else {
        try {
            $ips = @(Resolve-DnsName -Name $srvHost -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
                Where-Object { $_.IPAddress } | ForEach-Object { [string]$_.IPAddress })
        } catch { $ips = @() }
    }
    $count = 0
    if ($ips.Count -gt 0) {
        foreach ($proc in @(Get-Process xray -ErrorAction SilentlyContinue)) {
            try {
                $conns = @(Get-NetTCPConnection -OwningProcess $proc.Id -State Established -ErrorAction SilentlyContinue)
            } catch { continue }
            foreach ($c in $conns) {
                $addr = ([string]$c.RemoteAddress) -replace '^::ffff:', ''
                if ([int]$c.RemotePort -eq $srvPort -and ($ips -contains $addr)) { $count++ }
            }
        }
    }
    if (-not $Script:EndpointLiveCache) { $Script:EndpointLiveCache = @{} }
    $Script:EndpointLiveCache[$cacheKey] = [pscustomobject]@{ at = $now; count = $count }
    return $count
}

function Get-FallbackTemplate {
    # A manually selected server is sometimes not present in the captured Happ
    # memory cache. A cached full config still supplies the same inbound and
    # routing skeleton; Build-Config replaces every server outbound with the
    # requested target. Prefer a valid recently written config.
    $files = @(Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    foreach ($f in $files) {
        try {
            $tpl = Get-Content $f.FullName -Raw -Encoding utf8 | ConvertFrom-Json
            Repair-CacheConfigKeys $tpl
            $hasInbound = @($tpl.inbounds | Where-Object { $_.protocol -eq 'socks' }).Count -gt 0
            $hasServer = @($tpl.outbounds | Where-Object {
                $_.protocol -in @('vless','hysteria','vmess','trojan') -and $_.settings
            }).Count -gt 0
            if ($hasInbound -and $hasServer) {
                Log ("active server template unavailable; using cached template {0}" -f $f.BaseName)
                return $tpl
            }
        } catch { }
    }
    return $null
}

function Get-CurrentTemplate {
    param([object]$Server, [switch]$Fast)
    $Script:LastTemplateFallback = $false
    if (-not $Server) { $Server = Get-ActiveServer }
    if (-not $Server -or -not $Server.host) { Log 'cannot determine the active server'; return $null }
    $serverKey = Get-ServerKey $Server
    $file = Get-CachedConfigPath ([string]$Server.host) ([int]$Server.port) $serverKey
    if (-not (Test-Path $file) -and $serverKey -match '#') {
        $file = Get-CachedConfigPath ([string]$Server.host) ([int]$Server.port)
    }
    if (Test-Path $file) {
        try {
            $tpl = Get-Content $file -Raw -Encoding utf8 | ConvertFrom-Json
            Repair-CacheConfigKeys $tpl
            return $tpl
        } catch { Log ("template parse failed: " + $_.Exception.Message) }
    }
    if ($Fast) {
        # Do not spend seconds scanning the GUI on an urgent switch. A cached
        # full config is enough to build the target tunnel.
        $fastFallback = Get-FallbackTemplate
        if ($fastFallback) {
            $Script:LastTemplateFallback = $true
            return $fastFallback
        }
    }
    Log ("active server {0}_{1} not in cache; scanning GUI memory..." -f $Server.host, $Server.port)
    Update-ConfigCache | Out-Null
    $file = Get-CachedConfigPath ([string]$Server.host) ([int]$Server.port) $serverKey
    if (-not (Test-Path $file) -and $serverKey -match '#') {
        $file = Get-CachedConfigPath ([string]$Server.host) ([int]$Server.port)
    }
    if (Test-Path $file) {
        try {
            $tpl = Get-Content $file -Raw -Encoding utf8 | ConvertFrom-Json
            Repair-CacheConfigKeys $tpl
            return $tpl
        } catch { }
    }
    $fallback = Get-FallbackTemplate
    if ($fallback) {
        $Script:LastTemplateFallback = $true
        return $fallback
    }
    Log "active server template unavailable"
    return $null
}

# ------------------------------------------------------------------- config builder
function Build-Config {
    param([object]$Template, [object]$NewOutbound)
    $cfg = $Template | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    $newParts = New-Object System.Collections.Generic.List[object]
    foreach ($ob in $cfg.outbounds) {
        $isServer = ($ob.protocol -in @('vless','hysteria','vmess','trojan')) -and ($ob.settings)
        if ($isServer) {
            $copy = $NewOutbound | ConvertTo-Json -Depth 30 | ConvertFrom-Json
            $copy | Add-Member -NotePropertyName tag -NotePropertyValue $ob.tag -Force
            $newParts.Add($copy)
        } else {
            $newParts.Add($ob)
        }
    }
    $cfg | Add-Member -NotePropertyName outbounds -NotePropertyValue $newParts.ToArray() -Force
    return $cfg
}

function Test-ProxyExit {
    param([int]$tries = 4, [int]$TimeoutSec = 10, [int]$RetryDelayMs = 2000)
    $maxTime = [Math]::Max(1, [int]$TimeoutSec)
    for ($i = 1; $i -le $tries; $i++) {
        try {
            $raw = & curl.exe -s --max-time $maxTime --socks5-hostname 127.0.0.1:10808 $Script:Cfg.WebCheckUrl 2>$null
            if ($LASTEXITCODE -eq 0) {
                $joined = ($raw -join '')
                $ip = $null
                try { $ip = ($joined | ConvertFrom-Json).ip } catch { }
                if (-not $ip) {
                    if ($joined -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $ip = $Matches[1] }
                }
                if ($ip) {
                    if (-not $Script:State) { Load-State }
                    $ts = Get-Date -Format 'HH:mm:ss'
                    $Script:State | Add-Member -NotePropertyName exitIp -NotePropertyValue ([string]$ip) -Force
                    $Script:State | Add-Member -NotePropertyName exitIpChecked -NotePropertyValue $ts -Force
                    Save-State
                    return ([string]$ip)
                }
            }
        } catch { }
        if ($i -lt $tries) { Start-Sleep -Milliseconds ([Math]::Max(0, [int]$RetryDelayMs)) }
    }
    return ''
}

# A burst client opens a FRESH pipe connection; frames written back-to-back are all
# processed by the daemon; later writes on the same connection are ignored.
# The returned client can be kept open - it OWNS the process spawned in this burst
# (the daemon kills records when their owning client disconnects).
function New-Burst {
    param([object[]]$messages, [string[]]$rids)
    $c = Open-DaemonSocket
    if (-not $c) { return $null }
    $recv = New-Object System.Collections.Generic.List[int]
    $helloId = 'hello-' + (Get-Random)
    $ridsOut = @{ $helloId = $true }
    $ok = Write-FrameTo $c (@{ action = 'client-hello'; version = '4.3.0'; 'request-id' = $helloId })
    for ($i = 0; $i -lt $messages.Count; $i++) {
        $m = $messages[$i]
        $rid = if ($rids -and $i -lt $rids.Count) { $rids[$i] } else { 'rq' + (Get-Random) }
        $m['request-id'] = $rid
        $ridsOut[$rid] = $true
        if (-not (Write-FrameTo $c $m)) { $ok = $false }
    }
    if (-not $ok) { try { $c.Dispose() } catch {}; return $null }
    return [pscustomobject]@{ Client = $c; Recv = $recv; Expected = $ridsOut }
}

function Reset-Socket {
    # drop the current socket; succeeding bursts open fresh connections
    try { if ($Script:Daemon.Client) { $Script:Daemon.Client.Dispose() } } catch {}
    $Script:Daemon.Client = $null
}

function Invoke-KillCore {
    # GUI-owned records cannot be stopped over the pipe; kill the process at OS level.
    # Requires elevation (xray runs as SYSTEM in session 0 as a daemon child).
    $p = Get-Process xray -ErrorAction SilentlyContinue
    if (-not $p) { return $true }
    try {
        $p | Where-Object { $_.Id -and $_.Id -gt 0 } | ForEach-Object {
            try { Stop-Process -Id $_.Id -Force -ErrorAction Stop; Log ("killed xray pid " + $_.Id) } catch {
                Log ("Stop-Process denied (" + $_.Exception.Message + ") - attempting elevated kill")
                $cmd = 'Stop-Process -Id ' + $_.Id + ' -Force'
                Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile', '-Command', $cmd
                Start-Sleep -Seconds 3
            }
        }
    } catch { Log ("kill failed: " + $_.Exception.Message); return $false }
    Start-Sleep -Milliseconds 500
    return ((Get-Process xray -ErrorAction SilentlyContinue) -eq $null)
}

function Start-CoreBurst {
    # one burst: hello + start + stdin(config) + close-stdin; connection stays open (owner)
    # returns the burst object (Client + Recv) so callers can drain process events
    param([string]$configJson, [switch]$Fast)
    $rids = @('start-switch', 'stdin-switch', 'clostdin-switch')
    $msgs = @(
        @{ action = 'start'; 'process-id' = $Script:Cfg.ProcessId; 'executable' = $Script:Cfg.XrayExe; 'arguments' = @(); 'working-dir' = $Script:Cfg.XrayWorkDir; 'auto-restart' = $true; 'max-restart-attempts' = 3; 'restart-delay-ms' = 1000 },
        @{ action = 'stdin'; 'process-id' = $Script:Cfg.ProcessId; data = $configJson },
        @{ action = 'close-stdin'; 'process-id' = $Script:Cfg.ProcessId }
    )
    $burst = New-Burst -messages $msgs -rids $rids
    if (-not $burst) { return $null }
    Start-Sleep -Milliseconds $(if ($Fast) { 650 } else { 1200 })
    $resp = Read-FramesFrom $burst.Client $burst.Recv -MaxMs $(if ($Fast) { 900 } else { 2500 })
    foreach ($f in $resp) {
        if ($f.status -and $f.'request-id' -eq 'start-switch') { Log ("start resp: status=" + $f.status + " " + $f.message) }
        if ($f.'request-id' -eq 'stdin-switch') { Log ("stdin resp: status=" + $f.status) }
        if ($f.event -eq 'stderr' -and $f.data -match 'fail|error') { Log ("core stderr: " + ($f.data -replace '\r?\n', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min(200, $_.Length)) })) }
    }
    return $burst
}

function Invoke-PipeSwitch {
    param([pscustomobject]$Target, [switch]$Fast)
    Load-Bans
    $targetKey = Get-ServerKey $Target
    if (Test-ServerBanned $targetKey) {
        Log ("refusing banned server {0}" -f $targetKey)
        return $false
    }
    $curSrv = Get-ActiveServer
    $template = Get-CurrentTemplate -Server $curSrv -Fast:$Fast
    if (-not $template) { return $false }
    $templateFallback = [bool]$Script:LastTemplateFallback
    $curBanned = $false
    if ($curSrv) { $curBanned = Test-ServerBanned (Get-ServerKey $curSrv) }
    $newOut = Get-CachedOutbound -srvHost $Target.host -srvPort $Target.port -ProfileKey $targetKey
    if (-not $newOut) {
        Log ("no cached outbound for {0}" -f $targetKey)
        Update-Reliability $targetKey $false
        return $false
    }

    $newCfg = Build-Config -Template $template -NewOutbound $newOut
    $newJson = ConvertTo-Json -InputObject $newCfg -Compress -Depth 30
    $oldJson = ConvertTo-Json -InputObject $template -Compress -Depth 30

    Log ("switching to {0}:{1} via daemon pipe (burst mode{2})..." -f $Target.host, $Target.port, $(if ($Fast) { ', fast' } else { '' }))
    $exitIpBefore = ''
    try { $exitIpBefore = [string]$Script:State.exitIp } catch { }
    if ($exitIpBefore) { Log ("last recorded exit IP before switch: " + $exitIpBefore) }

    # 1. release any core we own, stop/kill the running core
    if ($Script:OwnedClient) { try { $Script:OwnedClient.Dispose() } catch {}; $Script:OwnedClient = $null }
    try { $null = (Send-Daemon -obj @{ action = 'stop'; 'process-id' = $Script:Cfg.ProcessId } -WaitMs $(if ($Fast) { 800 } else { 2000 })) } catch { }
    Start-Sleep -Milliseconds $(if ($Fast) { 350 } else { 700 })
    $alive = Get-Process xray -ErrorAction SilentlyContinue
    if ($alive) {
        Log ('GUI-owned core still running - OS-level kill')
        if (-not (Invoke-KillCore)) {
            Log 'could not kill the running core'
            Update-Reliability (Get-ServerKey $Target) $false
            return $false
        }
    }
    # 2. start with the new config; keep the owner connection open
    $Script:OwnedBurst = Start-CoreBurst -configJson $newJson -Fast:$Fast
    $Script:OwnedClient = if ($Script:OwnedBurst) { $Script:OwnedBurst.Client } else { $null }
    if (-not $Script:OwnedBurst) { Log 'burst start failed'; return $false }
    # 2b. restore the system-wide TUN (kills nothing: own burst, kept alive)
    if ($Script:OwnedTun) { try { $Script:OwnedTun.Client.Dispose() } catch {} }
    $Script:OwnedTun = Start-TunBurst -configPath $Script:Cfg.TunConfigPath -Fast:$Fast
    Start-Sleep -Milliseconds $(if ($Fast) { 700 } else { 1500 })
    $tun = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'happ' }
    if ($tun) { Log ("TUN adapter up: {0} ({1})" -f $tun.Name, $tun.Status) } else { Log 'WARNING: TUN adapter did not come up' }
    # 3. verify (socks exit IP + the plain system-route IP)
    if ($Fast) {
        $exitIpAfter = Test-ProxyExit -tries ([int]$Script:Cfg.FastVerifyTries) -TimeoutSec ([int]$Script:Cfg.FastVerifyTimeoutSec) -RetryDelayMs 400
        $plainIp = '(fast verify: skipped)'
    } else {
        $exitIpAfter = Test-ProxyExit
        $plainIp = Get-PlainRouteIp
    }
    if ($exitIpAfter) {
        Log ("SWITCH OK -> {0}:{1} (core exit IP: {2}{3}; system route: {4})" -f $Target.host, $Target.port, $exitIpAfter, $(if ($exitIpBefore -and $exitIpBefore -ne $exitIpAfter) { ", was: $exitIpBefore" } else { '' }), $plainIp)
        $global:LastSwitchAt = Get-Date
        Update-Reliability (Get-ServerKey $Target) $true $exitIpAfter
        Set-ActiveServer $Target
        return $true
    }
    Update-Reliability (Get-ServerKey $Target) $false
    Log 'exit check failed on the new server - reverting to original config'
    if ($Script:OwnedBurst) { try { $Script:OwnedBurst.Client.Dispose() } catch {} }
    $Script:OwnedClient = $null; $Script:OwnedBurst = $null
    $null = Invoke-KillCore
    if ($curBanned -or $templateFallback) {
        # Never reconnect to a banned server, and never revert to a fallback
        # template whose server is not the real active server. In either case
        # the next failover attempt can start cleanly from another cached config.
        if ($curBanned) {
            Log 'original server is banned - refusing to revert; no proxy is active'
        } else {
            Log 'original server config was not cached - refusing to revert to a fallback template; no proxy is active'
        }
        return $false
    }
    $Script:OwnedBurst = Start-CoreBurst -configJson $oldJson -Fast:$Fast
    $Script:OwnedClient = if ($Script:OwnedBurst) { $Script:OwnedBurst.Client } else { $null }
    # TUN stays alive across the revert (it forwards into the fixed socks port)
    $revertOk = $false
    if ($Script:OwnedBurst) {
        if ($Fast) {
            $revertOk = [bool](Test-ProxyExit -tries 1 -TimeoutSec ([int]$Script:Cfg.FastVerifyTimeoutSec))
        } else {
            $revertOk = [bool](Test-ProxyExit)
        }
    }
    if ($revertOk) {
        if ($curSrv) { Set-ActiveServer $curSrv }
        Log 'reverted to original server'
    } else { Log 'REVERT FAILED - reconnect Happ manually!' }
    return $false
}

# ------------------------------------------------------------------- opencode helpers
function Invoke-OC {
    param([string]$api)
    Push-Location $Script:Cfg.ProjectDir
    try {
        $out = & opencode api get $api 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $raw = ($out -join "`n")
        try { return ($raw | ConvertFrom-Json) } catch { return $null }
    } finally { Pop-Location }
}

function Get-FailedSessions {
    param([int]$windowMinutes = 120, [int]$freshMinutes = 0, [string[]]$kinds = @('rate','endpoint','connreset','timeout'))
    $root = Invoke-OC '/api/session'
    if ($null -eq $root -or -not $root.data) { Log 'cannot list opencode sessions'; return @() }
    $cutoff = (Get-Date).AddMinutes(-1 * $windowMinutes)
    $result = @()
    foreach ($s in $root.data) {
        if ($Script:Cfg.TopLevelOnly -and $s.parentID) { continue }
        # Burned sessions are never prompted again; their fork carries the work.
        if (Test-SessionBurned $s.id) { continue }
        $updated = $null
        if ($s.time -and $s.time.updated) {
            try { $updated = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$s.time.updated).LocalDateTime } catch { }
        }
        if ($updated -and $updated -lt $cutoff) { continue }
        $msgsResp = Invoke-OC ("/api/session/{0}/message?order=desc&limit=25" -f $s.id)
        if (-not $msgsResp -or -not $msgsResp.data) { continue }
        # Walk newest -> oldest. Only a person-authored follow-up (non-empty text,
        # not our 'continue' and not opencode's restart note) means the session
        # moved on and we should leave it alone. Idle/system markers and error-less
        # assistant records are translucent: they must not mask an older failure.
        $errKind = $null; $errMsg = $null; $errCreated = $null; $errQuota = $false
        foreach ($m in $msgsResp.data) {
            if ($m.type -eq 'user') {
                $txt = ''
                try { $txt = ([string]$m.payload.text) } catch { $txt = '' }
                if ($txt -and $txt -notmatch '^(continue|The server restarted while you were working)') { break }
                continue
            }
            if ($m.type -eq 'system') { continue }
            if ($m.type -match 'assistant|idle') {
                $kind = $null
                $quotaHit = $false
                if ($m.error -and $m.error.message) {
                    if ($m.error.message -match $Script:Cfg.RateLimitPattern) {
                        $kind = 'rate'
                        $quotaHit = [bool]($m.error.message -match $Script:Cfg.QuotaBanPattern)
                    }
                    elseif ($m.error.message -match $Script:Cfg.EndpointPattern) { $kind = 'endpoint' }
                    elseif ($m.error.message -match $Script:Cfg.ConnResetPattern) { $kind = 'connreset' }
                    elseif ($m.error.message -match $Script:Cfg.TimeoutPattern) { $kind = 'timeout' }
                }
                if ($kind -and ($kinds -contains $kind) -and (-not $errKind)) {
                    $errKind = $kind
                    $errQuota = $quotaHit
                    $errMsg = $m.error.message.Substring(0, [Math]::Min(140, $m.error.message.Length))
                    try { $errCreated = [int64]$m.time.created } catch { $errCreated = $null }
                }
            }
        }
        if (-not $errKind) { continue }
        # A fork copies the transcript, including the failure that created it.
        # That copied error must not count as a fresh failure of the fork; only
        # messages created after the fork itself can trigger another burn.
        $forkRec = Get-SessionRec $s.id
        if ($forkRec -and $errCreated) {
            try {
                if ($forkRec.PSObject.Properties['createdAt'] -and $forkRec.createdAt) {
                    $forkMs = [DateTimeOffset]::Parse([string]$forkRec.createdAt).ToUnixTimeMilliseconds()
                    if ([int64]$errCreated -le $forkMs) { continue }
                }
            } catch { }
        }
        # Automatic post-switch resumes only revive fresh work. A session whose
        # failure is older than the cutoff is abandoned, or was merely re-opened:
        # opening refreshes time.updated without changing the error, so the error
        # timestamp is the deciding clock, not the session update time.
        if ($freshMinutes -gt 0 -and $errCreated) {
            $ageMin = ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - [int64]$errCreated) / 60000.0
            if ($ageMin -gt $freshMinutes) {
                Log ("not resuming {0} ({1}): failure is {2:N0} min old (fresh limit {3} min)" -f $s.id, $s.title, $ageMin, $freshMinutes)
                continue
            }
        }
        # prompted-set dedup applies to the switch path (rate/timeout classes):
        # skip only when this failure predates our last prompt for the session
        # (fresh failures pass). endpoint/connreset retries are allowed to hit
        # the same session repeatedly.
        if (($kinds -contains 'rate') -or ($kinds -contains 'timeout')) {
            $props = $Script:State.prompted.PSObject.Properties[$s.id]
            if ($props -and $errCreated) {
                $fresh = $false
                try { if ($errCreated -gt ([DateTimeOffset]::Parse($props.Value).ToUnixTimeMilliseconds())) { $fresh = $true } } catch { }
                if (-not $fresh) { continue }
            }
        }
        $result += [pscustomobject]@{
            id = $s.id; title = $s.title; when = $updated; kind = $errKind
            errCreated = $errCreated
            quota = $errQuota
            msg = $errMsg
        }
    }
    return $result
}

function Get-OpenCodeDesktopProcess {
    return @(Get-Process -Name $Script:Cfg.OpenCodeProcess -ErrorAction SilentlyContinue)
}

function Get-OpenCodeServiceProcess {
    # opencode desktop ships its own service binary; it can outlive the GUI when
    # the app is force-closed, so treat it as part of the app for restarts.
    $cliDir = Join-Path $env:APPDATA 'ai.opencode.desktop\cli'
    return @(Get-Process -Name 'opencode-cli' -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path -and $_.Path.StartsWith($cliDir, [System.StringComparison]::OrdinalIgnoreCase) } catch { $false }
    })
}

function Get-OpenCodeLeftover {
    return @(@(Get-OpenCodeDesktopProcess) + @(Get-OpenCodeServiceProcess))
}

function Stop-OpencodeDesktop {
    param([switch]$Fast)
    $app = @(Get-OpenCodeDesktopProcess)
    $svc = @(Get-OpenCodeServiceProcess)
    if (-not $app.Count -and -not $svc.Count) {
        Log 'opencode desktop is not running - nothing to stop'
        return $true
    }

    # remember the exe actually running (survives app updates / non-default installs)
    $runningExe = $null
    try { $runningExe = ($app | Where-Object { $_.Path } | Select-Object -First 1).Path } catch { }
    if ($runningExe) { $Script:Cfg.OpenCodeExe = $runningExe }

    Log ("stopping opencode desktop ({0} app + {1} service process(es))..." -f $app.Count, $svc.Count)
    # ask the Electron window to close first so drafts and window state are flushed
    $main = @($app | Where-Object { $_.MainWindowHandle -ne 0 })
    if ($main.Count) {
        foreach ($p in $main) {
            try { $null = $p.CloseMainWindow() } catch { }
        }
        $graceSec = [Math]::Max(2, [int]$Script:Cfg.OpenCodeStopSec)
        if ($Fast) { $graceSec = [Math]::Min(4, $graceSec) }
        $deadline = (Get-Date).AddSeconds($graceSec)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
            if (-not @(Get-OpenCodeLeftover).Count) {
                Log 'opencode desktop closed gracefully'
                return $true
            }
        }
    }

    Log 'opencode desktop is still running - forcing shutdown'
    # Electron can respawn renderer/utility processes while the main process is
    # still shutting down, so kill in passes until the tree stays gone.
    for ($pass = 0; $pass -lt 3; $pass++) {
        $remaining = @(Get-OpenCodeDesktopProcess)
        if (-not $remaining.Count) { break }
        foreach ($p in $remaining) {
            try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch {
                Log ("could not stop opencode pid " + $p.Id + ": " + $_.Exception.Message)
            }
        }
        Start-Sleep -Milliseconds 400
    }
    foreach ($p in @(Get-OpenCodeServiceProcess)) {
        try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch {
            Log ("could not stop opencode service pid " + $p.Id + ": " + $_.Exception.Message)
        }
    }
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Milliseconds 500
        if (-not @(Get-OpenCodeLeftover).Count) {
            Log 'opencode desktop stopped'
            return $true
        }
    }
    Log ('opencode desktop is still running (pids: ' + ((@(Get-OpenCodeLeftover) | ForEach-Object { $_.Id }) -join ', ') + ')')
    return $false
}

function Start-OpencodeDesktop {
    $exe = $Script:Cfg.OpenCodeExe
    if (-not (Test-Path $exe)) {
        Log ("opencode desktop exe not found at " + $exe + " - falling back to the background service")
        return (Restart-OpencodeService)
    }

    if (@(Get-OpenCodeDesktopProcess).Count) {
        Log 'opencode desktop is already running - waiting for its API'
    } else {
        $elevated = $false
        try {
            $pri = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            $elevated = $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { }
        try {
            if ($elevated) {
                # The watchdog is usually elevated for the core kill. Launch through
                # the interactive shell so the app does not inherit admin rights.
                Log 'starting opencode desktop via the interactive shell (unelevated)...'
                Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $exe) -ErrorAction Stop | Out-Null
            } else {
                Log 'starting opencode desktop...'
                Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe -Parent) -ErrorAction Stop | Out-Null
            }
        } catch {
            Log ("failed to start opencode desktop: " + $_.Exception.Message)
            return $false
        }
    }

    for ($i = 1; $i -le [int]$Script:Cfg.OpenCodeStartSec; $i++) {
        Start-Sleep -Seconds 1
        $info = Invoke-OC '/api/info'
        # /api/info returns the ServerInfo object directly (no data wrapper)
        if ($info -and ($info.data -or $info.version)) {
            if (-not @(Get-OpenCodeDesktopProcess).Count) {
                Log 'opencode API is up but the desktop app is not running'
                return $false
            }
            Log ("opencode desktop healthy after {0}s (pid {1})" -f $i, $(if ($info.data) { $info.data.pid } else { $info.pid }))
            return $true
        }
        if (($i % 15) -eq 0) {
            Log ("still waiting for opencode desktop ({0}s of {1}s)..." -f $i, $Script:Cfg.OpenCodeStartSec)
        }
    }
    Log 'opencode desktop failed to come back'
    return $false
}

function Restart-OpencodeService {
    Push-Location $Script:Cfg.ProjectDir
    try {
        Log 'restarting opencode background service...'
        & opencode service restart 2>$null | Out-Null
        for ($i = 1; $i -le 120; $i++) {
            Start-Sleep -Seconds 1
            $info = Invoke-OC '/api/info'
            if ($info -and ($info.data -or $info.version)) {
                Log ("opencode service healthy after " + $i + "s (pid " + $(if ($info.data) { $info.data.pid } else { $info.pid }) + ")")
                return $true
            }
            if (($i % 15) -eq 0) {
                Log ("still waiting for the opencode service (" + $i + "s of 120s)...")
            }
        }
        Log 'opencode service failed to come back'
        return $false
    } finally { Pop-Location }
}

function Send-ContinueToSession {
    param([string]$sessionID)
    Push-Location $Script:Cfg.ProjectDir
    try {
        # PS5.1 loses embedded quotes when the npm shim spawns the native exe;
        # pre-escape quotes so the payload arrives as valid JSON.
        $body = '{\"text\":\"' + $Script:Cfg.ContinueText + '\"}'
        $out = & opencode api post ("/api/session/{0}/prompt" -f $sessionID) --data $body 2>&1
        $txt = (($out -join ' ') -replace '\s+', ' ')
        if ($txt.Length -gt 160) { $txt = $txt.Substring(0, 160) }
        Log ("continue -> {0}: {1}" -f $sessionID, $txt)
        return ($LASTEXITCODE -eq 0)
    } finally { Pop-Location }
}

# ------------------------------------------------------- session burn / fork
# Provider quota flags follow a session, not just an exit IP: resuming the same
# session on a freshly switched server can flag the new IP with its first
# request. The watchdog therefore abandons a flagged session and resumes its
# fork, which carries the full projected transcript (fork is a local DB copy -
# it costs no provider request). The mapping lives in state.json.sessions.

function Get-SessionRec([string]$sessionID) {
    if (-not $sessionID) { return $null }
    if (-not $Script:State) { Load-State }
    try {
        $p = $Script:State.sessions.PSObject.Properties[$sessionID]
        if ($p) { return $p.Value }
    } catch { }
    return $null
}

function Test-SessionBurned([string]$sessionID) {
    $rec = Get-SessionRec $sessionID
    if (-not $rec) { return $false }
    try { return [bool]$rec.forkID } catch { return $false }
}

function Test-SessionExists([string]$sessionID) {
    if (-not $sessionID) { return $false }
    $r = Invoke-OC ("/api/session/{0}" -f $sessionID)
    return [bool]($r -and $r.data -and $r.data.id)
}

function Get-ForkCountSince([datetime]$since) {
    $n = 0
    try {
        foreach ($p in @($Script:State.sessions.PSObject.Properties)) {
            $v = $p.Value
            if (-not $v) { continue }
            $fid = $null
            try { $fid = [string]$v.forkID } catch { }
            if (-not $fid) { continue }
            try {
                if ([datetime]::Parse([string]$v.burnedAt) -ge $since) { $n++ }
            } catch { }
        }
    } catch { }
    return $n
}

function Set-SessionTitle {
    param([string]$sessionID, [string]$title)
    if (-not $sessionID -or -not $title) { return $false }
    $clean = (($title -replace '[\r\n]+', ' ') -replace '"', "'").Trim()
    if ($clean.Length -gt 120) { $clean = $clean.Substring(0, 120) }
    Push-Location $Script:Cfg.ProjectDir
    try {
        # PS5.1 + the npm shim split --data at literal spaces. JSON \u0020
        # escapes keep the payload one argv token and still decode to a space.
        $json = @{ title = $clean } | ConvertTo-Json -Compress
        $json = $json.Replace(' ', '\u0020')
        $body = $json.Replace('"', '\"')
        $out = & opencode api patch ("/api/session/{0}" -f $sessionID) --data $body 2>&1
        if ($LASTEXITCODE -ne 0) {
            $msg = (($out -join ' ') -replace '\s+', ' ')
            if ($msg.Length -gt 140) { $msg = $msg.Substring(0, 140) }
            Log ("session title update failed for {0}: {1}" -f $sessionID, $msg)
            return $false
        }
        return $true
    } catch {
        Log ("session title update failed for {0}: {1}" -f $sessionID, $_.Exception.Message)
        return $false
    } finally { Pop-Location }
}

function New-SessionFork {
    param(
        [string]$sessionID,
        [string]$reason = 'failover',
        [string]$kind = '',
        [string]$title = ''
    )
    if (-not $sessionID) { return $null }
    if (-not $Script:Cfg.SessionForkEnabled) { return $null }
    if (-not $Script:State) { Load-State }

    $rec = Get-SessionRec $sessionID
    $depth = 1
    $rootID = $sessionID
    if ($rec) {
        try { if ($rec.depth) { $depth = [int]$rec.depth + 1 } } catch { }
        try { if ($rec.rootID) { $rootID = [string]$rec.rootID } } catch { }
    }
    if ($depth -gt [int]$Script:Cfg.SessionForkMaxDepth) {
        Log ("session {0} reached the fork depth limit ({1}) - not forking again" -f $sessionID, $Script:Cfg.SessionForkMaxDepth)
        return $null
    }
    if ((Get-ForkCountSince (Get-Date).AddHours(-1)) -ge [int]$Script:Cfg.SessionForkMaxPerHour) {
        Log ("session fork rate limit reached ({0}/hour) - not forking {1}" -f $Script:Cfg.SessionForkMaxPerHour, $sessionID)
        return $null
    }

    Push-Location $Script:Cfg.ProjectDir
    try {
        $out = & opencode api post ("/api/session/{0}/fork" -f $sessionID) --data '{}' 2>&1
        if ($LASTEXITCODE -ne 0) {
            $msg = (($out -join ' ') -replace '\s+', ' ')
            if ($msg.Length -gt 160) { $msg = $msg.Substring(0, 160) }
            Log ("session fork failed for {0}: {1}" -f $sessionID, $msg)
            return $null
        }
        $resp = $null
        try { $resp = (($out -join "`n") | ConvertFrom-Json) } catch { }
        $forkID = $null
        $forkTitle = ''
        try { $forkID = [string]$resp.data.id } catch { }
        try { $forkTitle = [string]$resp.data.title } catch { }
        if (-not $forkID) {
            Log ("session fork returned no id for {0}" -f $sessionID)
            return $null
        }

        $now = Get-Date
        $entry = [pscustomobject]@{
            burnedAt  = $now.ToString('o')
            forkID    = $forkID
            forkTitle = $forkTitle
            reason    = $reason
            kind      = $kind
            depth     = $depth
            rootID    = $rootID
        }
        Add-Member -InputObject $Script:State.sessions -NotePropertyName $sessionID -NotePropertyValue $entry -Force
        $forkRec = [pscustomobject]@{
            createdAt  = $now.ToString('o')
            depth      = $depth
            rootID     = $rootID
            forkedFrom = $sessionID
        }
        Add-Member -InputObject $Script:State.sessions -NotePropertyName $forkID -NotePropertyValue $forkRec -Force
        Save-State

        if ($title -and $title -notmatch '^\[burned\]') {
            Set-SessionTitle $sessionID ('[burned] ' + $title) | Out-Null
        }
        Log ("session {0} burned by {1} errors - forked to {2} ({3}); the old session will not be prompted again" -f $sessionID, $kind, $forkID, $forkTitle)
        return $forkID
    } finally { Pop-Location }
}

function Resume-FailedSession {
    param(
        [pscustomobject]$Session,
        [string]$Reason = 'failover',
        [switch]$NoFork,
        [switch]$AllowRepeat
    )
    if (-not $Session -or -not $Session.id) { return $false }
    $id = [string]$Session.id
    $rec = Get-SessionRec $id
    $target = $id

    # A burned session is never prompted again. If it already has a fork, that
    # fork is the live continuation; if the fork was deleted, make a new one.
    if ($rec -and $rec.forkID) {
        $target = [string]$rec.forkID
        if (-not (Test-SessionExists $target)) {
            Log ("recorded fork {0} for burned session {1} no longer exists - forking again" -f $target, $id)
            try { $rec.PSObject.Properties.Remove('forkID') } catch { }
            $target = $id
        }
    }

    if ($target -eq $id -and -not $NoFork -and $Script:Cfg.SessionForkEnabled) {
        $forkID = New-SessionFork -sessionID $id -reason $Reason -kind ([string]$Session.kind) -title ([string]$Session.title)
        if (-not $forkID) {
            Log ("not continuing {0}: session fork failed and the flagged session was not reused" -f $id)
            return $false
        }
        $target = $forkID
    } elseif ($target -eq $id -and $NoFork -and (Test-SessionBurned $id)) {
        Log ("not prompting burned session {0} (no fork available)" -f $id)
        return $false
    }

    # Do not repeat a continue for the same failure event.
    if (-not $AllowRepeat -and $Session.errCreated) {
        $pr = $null
        try { $pr = $Script:State.prompted.PSObject.Properties[$target] } catch { }
        if ($pr) {
            $fresh = $true
            try { if ([int64]$Session.errCreated -le ([DateTimeOffset]::Parse([string]$pr.Value).ToUnixTimeMilliseconds())) { $fresh = $false } } catch { }
            if (-not $fresh) { return $false }
        }
    }

    # Stamp the prompt before sending: a provider error written while the CLI
    # call is still in flight must still count as a response to this continue.
    $now = (Get-Date).ToString('o')
    if (Send-ContinueToSession -sessionID $target) {
        Add-Member -InputObject $Script:State.prompted -NotePropertyName $target -NotePropertyValue $now -Force
        $tr = Get-SessionRec $target
        if (-not $tr) {
            $tr = New-Object PSObject
            Add-Member -InputObject $Script:State.sessions -NotePropertyName $target -NotePropertyValue $tr -Force
        }
        Add-Member -InputObject $tr -NotePropertyName lastPromptAt -NotePropertyValue $now -Force
        $n = 0
        try { $n = [int]$tr.prompts } catch { }
        Add-Member -InputObject $tr -NotePropertyName prompts -NotePropertyValue ($n + 1) -Force
        Save-State
        return $true
    }
    return $false
}

# ------------------------------------------------------------------- failover
function Mark-Used([pscustomobject]$srv) {
    if (-not $srv -or -not $srv.host) { return }
    $key = Get-ServerKey $srv
    if (-not $key) { return }
    Add-Member -InputObject $Script:State.used -NotePropertyName $key -NotePropertyValue (Get-Date -Format 'o') -Force
    Save-State
}

function Get-SwitchCooldownSec {
    # If another failure arrives soon after a switch, do not wait the full
    # two-minute cooldown; a consecutive timeout needs a fast next attempt.
    $normal = [int]$CooldownSec
    try {
        if ($global:LastFailover) {
            $age = ((Get-Date) - $global:LastFailover).TotalSeconds
            if ($age -ge 0 -and $age -lt [int]$Script:Cfg.ConsecutiveWindowSec) {
                return [int]$Script:Cfg.FastRetrySec
            }
        }
    } catch { }
    return $normal
}

function Invoke-Failover {
    param([string]$Reason = 'auto', [switch]$Fast)
    Load-State
    $global:LastFailover = Get-Date
    # A failover that aborts before its prompt phase must not leave the previous
    # phase's window in place for instant-timeout classification.
    $global:FailoverPromptStart = $null
    $global:FailoverPromptEnd = $null
    $cur = Get-ActiveServer
    if ($cur) {
        if ($Reason -eq 'quota') {
            Add-AutoBannedServer (Get-ServerKey $cur) 'free usage limit' | Out-Null
        } elseif ($Reason -eq 'timeout-instant') {
            Add-AutoBannedServer (Get-ServerKey $cur) 'instant timeout after continue' | Out-Null
        }
        Invoke-FailoverReason-Log $Reason $cur
        Mark-Used $cur
    } else {
        Log ('cannot read current Happ server - proceeding with failover (' + $Reason + ')')
    }
    if ($Fast) {
        # The pre-switch API scan can take seconds per session and is repeated
        # by the post-reload pass anyway.
        $affected = @()
        Log 'fast failover: deferring affected-session scan until after the switch'
    } else {
        $affected = Get-FailedSessions -windowMinutes $Script:Cfg.SessionResumeFreshMin -freshMinutes $Script:Cfg.SessionResumeFreshMin -kinds @('rate','endpoint','connreset','timeout')
        $affectedIds = (($affected | ForEach-Object { $_.id }) -join ', ')
        if (-not $affectedIds) { $affectedIds = 'none' }
        Log ("affected sessions (fresh {0} min): {1}" -f $Script:Cfg.SessionResumeFreshMin, $affectedIds)
    }

    # A live desktop app keeps HTTP/SSE connections pinned to the old core.
    # Stop it before the server changes and start it again once the switch is done.
    $desktopWasRunning = @(Get-OpenCodeDesktopProcess).Count -gt 0
    if ($Script:Cfg.RestartOpenCode -and $desktopWasRunning) {
        if (-not (Stop-OpencodeDesktop -Fast:$Fast)) {
            Log 'opencode desktop could not be stopped - aborting the switch'
            return
        }
    }

    $switched = $false
    $rotated = $false
    $appReady = $true
    $cacheFiles = @(Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json' -File -ErrorAction SilentlyContinue)
    if (-not $Fast -or $cacheFiles.Count -eq 0) {
        Update-ConfigCache | Out-Null
    }
    try {
        for ($attempt = 1; $attempt -le $Script:Cfg.MaxSwitchAttempts -and -not $switched; $attempt++) {
            $curKey = $null
            if ($cur) { $curKey = Get-ServerKey $cur }
            $cached = @(Get-CachedServerList)
            $cacheCount = $cached.Count
            $candidates = @()
            $unbannedCount = 0
            $usedUnbannedCount = 0
            foreach ($srv in $cached) {
                $stateKey = Get-ServerKey $srv
                if (-not $stateKey) { continue }
                if (Test-ServerBanned $stateKey) { continue }
                $unbannedCount++
                $isCurrent = ($curKey -eq $stateKey)
                $isUsed = [bool]$Script:State.used.PSObject.Properties[$stateKey]
                if ($isUsed) {
                    if (-not $isCurrent) { $usedUnbannedCount++ }
                    continue
                }
                if ($isCurrent) { continue }
                $candidates += $srv
            }
            $bannedCached = $cacheCount - $unbannedCount
            if ($bannedCached -gt 0) { Log ("skipping {0} banned cached server(s)" -f $bannedCached) }
            if (-not $candidates) {
                if ($cacheCount -eq 0) {
                    Log 'no cached server configs yet - rescanning happens on the next failover attempt'
                    break
                }
                if ($unbannedCount -eq 0) {
                    Log ("all {0} cached servers are banned - use -UnbanServer (or [L] to inspect)" -f $cacheCount)
                    break
                }
                if ($usedUnbannedCount -gt 0 -and -not $rotated) {
                    # every unbanned server was tried - reset used (never bans)
                    Log ("all {0} unbanned cached servers already used - starting rotation cycle 2 (random order; {1} banned)" -f $unbannedCount, @(Get-BannedEntries).Count)
                    foreach ($prop in @($Script:State.used.PSObject.Properties)) {
                        if ($curKey -and $prop.Name -eq $curKey) { continue }
                        $Script:State.used.PSObject.Properties.Remove($prop.Name) | Out-Null
                    }
                    $rotated = $true
                    Save-State
                    Add-RingEvent ("rotation reset: all {0} unbanned cached servers used - cycling again in random order" -f $unbannedCount)
                    continue
                }
                Log 'no alternative unbanned cached server available'
                break
            }
            $opt = Optimize-CandidateOrder -Candidates $candidates
            $candidates = @($opt.ordered)
            if ($candidates.Count -gt 1 -or $opt.recentFail -or $opt.staleExitIp -or $opt.bogusHost) {
                Log ("server choice: {0} preferred + {1} fallback (recent-fail: {2}, stale exit IP: {3}, bogus host: {4})" -f $opt.preferred, ($opt.recentFail + $opt.staleExitIp + $opt.bogusHost), $opt.recentFail, $opt.staleExitIp, $opt.bogusHost)
            }

            foreach ($cand in $candidates) {
                if (Invoke-PipeSwitch -Target $cand -Fast:$Fast) {
                    Mark-Used $cand
                    $switched = $true
                    break
                } else {
                    Mark-Used $cand
                }
            }
        }
    } finally {
        if ($Script:Cfg.RestartOpenCode) {
            try {
                if ($desktopWasRunning) {
                    $appReady = Start-OpencodeDesktop
                } else {
                    # no desktop process to relaunch (CLI-only usage) - keep the old behavior
                    $appReady = Restart-OpencodeService
                }
            } catch {
                Log ("opencode restart failed: " + $_.Exception.Message)
                $appReady = $false
            }
        }
    }
    if (-not $switched) { Log 'FAILED to switch to any previously unused server'; return }
    if (-not $appReady) {
        Log 'opencode did not come back - skipping continue prompts'
        return
    }

    $settleSec = [int]$Script:Cfg.ContinueDelaySec
    if ($Fast -and $settleSec -gt 1) { $settleSec = 1 }
    if ($settleSec -gt 0) {
        Log ("waiting {0}s for the provider to settle before continue prompts..." -f $settleSec)
        Start-Sleep -Seconds $settleSec
    }

    $postReload = Get-FailedSessions -windowMinutes $Script:Cfg.SessionResumeFreshMin -freshMinutes $Script:Cfg.SessionResumeFreshMin -kinds @('rate','endpoint','connreset','timeout')
    $postIds = (($postReload | ForEach-Object { $_.id }) -join ', ')
    if (-not $postIds) { $postIds = 'none' }
    Log ("post-reload failed sessions (fresh {0} min): {1}" -f $Script:Cfg.SessionResumeFreshMin, $postIds)
    # Only continues sent during this failover's prompt phase are "connect ->
    # continue" evidence against the freshly selected server. A later revive or
    # endpoint-retry continue on a long-running server must not ban it.
    $global:FailoverPromptStart = Get-Date
    $global:FailoverPromptEnd = $null
    try {
        $seen = @{}
        foreach ($s in (@($affected) + @($postReload))) {
            if ($seen.ContainsKey($s.id)) { continue }
            $seen[$s.id] = $true
            if ($s.kind -eq 'rate') {
                $props = $Script:State.prompted.PSObject.Properties[$s.id]
                if ($props) {
                    $fresh = $false
                    try { if ($s.errCreated -gt ([DateTimeOffset]::Parse($props.Value).ToUnixTimeMilliseconds())) { $fresh = $true } } catch { }
                    if (-not $fresh) { continue }
                }
            }
            Resume-FailedSession -Session $s -Reason $Reason | Out-Null
        }
    } finally {
        $global:FailoverPromptEnd = Get-Date
    }
    Log 'failover complete'
}

# ------------------------------------------------------------------- log tail
function Test-OpLogTail {
    if (-not (Test-Path $Script:Cfg.OpLogPath)) { return $null }
    $lines = Get-Content $Script:Cfg.OpLogPath -Tail 300 -ErrorAction SilentlyContinue
    $rateNewest = $null
    $quotaNewest = $null
    $endNewest = $null
    foreach ($l in $lines) {
        $ts = $null
        if ($l -match '^timestamp=([0-9T:\.\-]+)Z') {
            try { $ts = [DateTime]::Parse($Matches[1]).ToLocalTime() } catch { }
        }
        if (-not $ts) { continue }
        if ($l -match $Script:Cfg.RateLimitPattern) {
            if ($ts -gt $rateNewest) { $rateNewest = $ts }
            if ($l -match $Script:Cfg.QuotaBanPattern -and $ts -gt $quotaNewest) { $quotaNewest = $ts }
        } elseif ($l -match $Script:Cfg.EndpointPattern) {
            if ($ts -gt $endNewest) { $endNewest = $ts }
        }
    }
    return @{ rate = $rateNewest; quota = $quotaNewest; endpoint = $endNewest }
}

# ------- session-level failure scan (API-based) ------------------------------
# ECONNRESET and provider timeouts never reach opencode.log; the only persisted
# record is the session message error. One pass counts connection-loss failures
# inside the recent window and collects the newest timeout per top-level
# session. Failures at or before state.connResetUntil / state.timeoutUntil were
# already processed.
function Test-SessionFailureScan {
    $result = [pscustomobject]@{ connReset = 0; timeouts = @() }
    $root = Invoke-OC '/api/session'
    if ($null -eq $root -or -not $root.data) { return $result }
    $nowMs = [DateTimeOffset]::Now.ToUnixTimeMilliseconds()
    $winMs = $Script:Cfg.ConnResetWindowSec * 1000
    $floorMs = $nowMs - $winMs
    $processedMs = 0
    try { $processedMs = [int64][string]$Script:State.connResetUntil } catch { $processedMs = 0 }
    $toProcessedMs = 0
    try { $toProcessedMs = [int64][string]$Script:State.timeoutUntil } catch { $toProcessedMs = 0 }
    # sessions untouched for longer than this cannot contain a fresh failure
    $updFloorMs = $nowMs - ([Math]::Max([int]$Script:Cfg.ConnResetWindowSec, 600) * 1000)
    $count = 0
    $timeouts = @{}
    foreach ($s in $root.data) {
        if ($Script:Cfg.TopLevelOnly -and $s.parentID) { continue }
        $updMs = 0
        try { $updMs = [int64]$s.time.updated } catch { $updMs = 0 }
        if ($updMs -lt $updFloorMs) { continue }
        $msgsResp = Invoke-OC ("/api/session/{0}/message?order=desc&limit=8" -f $s.id)
        if (-not $msgsResp -or -not $msgsResp.data) { continue }
        foreach ($m in $msgsResp.data) {
            $cMs = 0
            try { $cMs = [int64]$m.time.created } catch { $cMs = 0 }
            if (-not $m.error -or -not $m.error.message) { continue }
            if ($m.error.message -match $Script:Cfg.ConnResetPattern) {
                if ($cMs -lt $floorMs) { continue }
                if ($processedMs -gt 0 -and $cMs -le $processedMs) { continue }
                $count++
            } elseif ($m.error.message -match $Script:Cfg.TimeoutPattern) {
                if ($toProcessedMs -gt 0 -and $cMs -le $toProcessedMs) { continue }
                $prev = $null
                if ($timeouts.ContainsKey([string]$s.id)) { $prev = $timeouts[[string]$s.id] }
                if (-not $prev -or $cMs -gt [int64]$prev.created) {
                    $msg = [string]$m.error.message
                    if ($msg.Length -gt 140) { $msg = $msg.Substring(0, 140) }
                    $timeouts[[string]$s.id] = [pscustomobject]@{ sessionID = [string]$s.id; created = [int64]$cMs; message = $msg }
                }
            }
        }
    }
    $result.connReset = $count
    $result.timeouts = @($timeouts.Values | Sort-Object created)
    return $result
}

# A timeout is "instant" when it arrives shortly after a continue prompt sent
# during the latest failover: connect -> continue -> timeout. That points at the
# freshly selected server, so it is worth banning. A timeout after the server
# had been running for a while is ordinary provider behaviour: mark the server
# used and switch, but keep the server for later rotation. The prompt must fall
# inside the latest failover's prompt phase; a revive/endpoint retry continue on
# a long-running server must never trigger a ban.
function Test-TimeoutWasInstant([object]$failure) {
    if (-not $failure) { return $false }
    if (-not $global:FailoverPromptStart -or -not $global:FailoverPromptEnd) { return $false }
    $pr = $null
    try { $pr = $Script:State.prompted.PSObject.Properties[[string]$failure.sessionID] } catch { }
    if (-not $pr) { return $false }
    $promptMs = 0
    $startMs = 0
    $endMs = 0
    try {
        $promptMs = [DateTimeOffset]::Parse([string]$pr.Value).ToUnixTimeMilliseconds()
        $startMs = ([DateTimeOffset]$global:FailoverPromptStart).ToUnixTimeMilliseconds()
        $endMs = ([DateTimeOffset]$global:FailoverPromptEnd).ToUnixTimeMilliseconds()
    } catch { return $false }
    if ($promptMs -lt $startMs -or $promptMs -gt $endMs) { return $false }
    $ageSec = ([double]$failure.created - [double]$promptMs) / 1000.0
    if ($ageSec -lt 0) { return $false }
    return ($ageSec -le [int]$Script:Cfg.TimeoutInstantSec)
}

# ------- system-route tunnel health ------------------------------------------
# The connreset counter needs sessions to persist failures - a dead tunnel with
# idle sessions is invisible to it. This probes the route apps actually use
# (plain system route, two independent URLs); an adapter that was seen alive
# and vanished is restored directly.
function Get-TunnelHealth {
    $r = @{ adapterAlive = $false; plainOk = $false }
    $tun = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'happ' }
    if ($tun) {
        foreach ($a in @($tun)) { if ($a.Status -eq 'Up') { $r.adapterAlive = $true; break } }
    }
    $ip1 = Get-PlainRouteIp
    if ($ip1) { $r.plainOk = $true; return $r }
    try {
        $raw = & curl.exe -s --max-time $Script:Cfg.ProbeTimeoutSec $Script:Cfg.ProbeUrl2 2>$null
        if ($raw -and (($raw -join '') -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')) { $r.plainOk = $true }
    } catch { }
    return $r
}

# ---------------- endpoint-unavailable soft-retry (tier 1: same server) --------------
function New-SoftState {
    return [pscustomobject]@{
        active = $false
        rounds = 0
        nextAt = [datetime]::MinValue
        lastSeen = [datetime]::MinValue
    }
}
$Script:Soft = New-SoftState
$Script:ConnResetLast = $null
$Script:TunnelLast = $null
$Script:DeadStreak = 0
$Script:AdapterStreak = 0
$Script:SawTunAlive = $false

function Invoke-FailoverReason-Log([string]$reason, [pscustomobject]$cur) {
    $label = Format-ServerLabel $cur
    switch ($reason) {
        'auto' { Log ("rate limit detected; current server {0}" -f $label) }
        'quota' { Log ("free usage limit reached; current server {0} auto-banned and marked used" -f $label) }
        'timeout-instant' { Log ("timeout immediately after continue; current server {0} auto-banned and marked used" -f $label) }
        'timeout' { Log ("timeout after normal use; current server {0} marked used (not banned)" -f $label) }
        'manual' { Log ("manual switch requested; current server {0} marked used" -f $label) }
        'manual-ban' { Log ("manual ban requested; leaving current server {0} and marking it used" -f $label) }
        'connreset-burst' { Log ("connection-loss burst (ECONNRESET); current server {0} marked used" -f $label) }
        'tunnel-dead' { Log ("network unreachable through the tunnel; current server {0} marked used" -f $label) }
        default { Log ("persistent upstream endpoint errors; switching server (current: {0})" -f $label) }
    }
}

function Handle-Endpoint {
    $now = Get-Date
    if (-not $Script:Soft.active) {
        $Script:Soft.active = $true
        $Script:Soft.rounds = 0
        $Script:Soft.nextAt = $now.AddSeconds(60)
        Log ('upstream endpoint-unavailable detected; same-server continue retry scheduled in ~60s')
        return
    }
    if ($now -lt $Script:Soft.nextAt) { return }
    $Script:Soft.rounds++
    Log ("endpoint-unavailable persists - sending same-server continue (try #{0})" -f $Script:Soft.rounds)
    $sess = Get-FailedSessions -kinds @('endpoint') -windowMinutes 120
    if ($sess) {
        foreach ($s in $sess) {
            # Same server, so a flagged session cannot poison a fresh exit IP;
            # burned sessions are still skipped by the helper.
            Resume-FailedSession -Session $s -Reason 'endpoint-retry' -NoFork -AllowRepeat | Out-Null
        }
    } else {
        Log 'no sessions currently stuck on endpoint errors'
    }
    if ($Script:Soft.rounds -ge 2) {
        Log ("endpoint errors persist after {0} same-server continue tries - fast switching server" -f $Script:Soft.rounds)
        $Script:Soft = New-SoftState
        Invoke-Failover -Reason 'endpoint-persist' -Fast
    } else {
        $Script:Soft.nextAt = $now.AddSeconds(60)
        Log 'next same-server continue retry scheduled in ~60s'
    }
}

# ------------------------------------------------------------------- test modes
if ($ForkSession -or $UnburnSession -or $ListBurned) {
    Load-State
    if ($ListBurned) {
        $burned = @($Script:State.sessions.PSObject.Properties | Where-Object {
            $_.Value -and $_.Value.PSObject.Properties['forkID'] -and $_.Value.forkID
        })
        if (-not $burned.Count) {
            Log 'burned sessions: (none)'
        } else {
            foreach ($e in $burned) {
                $v = $e.Value
                $kind = ''
                try { $kind = [string]$v.kind } catch { }
                Log ("burned session: {0} -> fork {1} ({2}) at {3}" -f $e.Name, $v.forkID, $kind, $v.burnedAt)
            }
        }
    }
    if ($UnburnSession) {
        $uKey = $UnburnSession.Trim()
        $up = $Script:State.sessions.PSObject.Properties[$uKey]
        if (-not $up) {
            Log ("no burn record for " + $uKey)
        } else {
            $uFork = ''
            try { $uFork = [string]$up.Value.forkID } catch { }
            $Script:State.sessions.PSObject.Properties.Remove($uKey) | Out-Null
            if ($uFork) { $Script:State.sessions.PSObject.Properties.Remove($uFork) | Out-Null }
            Save-State
            Log ("unburned session " + $uKey + " - it can be scanned and prompted again")
        }
    }
    if ($ForkSession) {
        $fKey = $ForkSession.Trim()
        $fResp = Invoke-OC ("/api/session/{0}" -f $fKey)
        if (-not $fResp -or -not $fResp.data -or -not $fResp.data.id) {
            Log ("session not found: " + $fKey)
        } else {
            $fTitle = ''
            try { $fTitle = [string]$fResp.data.title } catch { }
            $fNew = New-SessionFork -sessionID $fKey -reason 'manual' -kind 'manual' -title $fTitle
            if ($fNew) { Log ("manual fork: {0} -> {1}" -f $fKey, $fNew) }
        }
    }
    return
}
if ($ListBanned -or $BanServer -or $UnbanServer) {
    Load-State
    if ($ListBanned) {
        $bans = @(Get-BannedEntries)
        if (-not $bans.Count) {
            Log 'banned servers: (none)'
        } else {
            foreach ($p in $bans) {
                $bi = Get-BanInfo $p.Value
                $suffix = $(if ($bi.auto) { 'AUTO ' + $bi.reason } else { 'manual' })
                Log ("banned server: {0} (since {1}; {2})" -f $p.Name, $bi.at, $suffix)
            }
        }
    }
    if ($BanServer) {
        $key = Resolve-ServerKey $BanServer
        if (-not $key) { Log ("invalid server '" + $BanServer + "' - use host:port, host_port, or 'current'") }
        else { Add-BannedServer $key 'command line' | Out-Null }
    }
    if ($UnbanServer) {
        $key = Resolve-ServerKey $UnbanServer
        if (-not $key) { Log ("invalid server '" + $UnbanServer + "' - use host:port, host_port, or 'current'") }
        else { Remove-BannedServer $key | Out-Null }
    }
    return
}
if ($TestInit) {
    Load-State
    Log ("state: used=[$((($Script:State.used.PSObject.Properties | ForEach-Object { $_.Name })) -join ', ')]")
    Log ("banned: [$((@(Get-BannedEntries) | ForEach-Object { $_.Name }) -join ', ')]")
    $active = Get-ActiveServer
    $reg = Get-HappCurrentServer
    Log ("active: " + (Format-ServerLabel $active))
    Log ("registry: " + (Format-ServerLabel $reg))
    $p = Get-DaemonProcess
    Log ("core: " + ($p | ConvertTo-Json -Compress -Depth 4))
    Update-ConfigCache | Out-Null
    return
}
if ($TestSwitch) {
    Load-State
    Update-ConfigCache | Out-Null
    $cur = Get-ActiveServer
    Mark-Used $cur
    $curKey = $null
    if ($cur) { $curKey = Get-ServerKey $cur }
    $candidates = @()
    foreach ($srv in @(Get-CachedServerList)) {
        $stateKey = Get-ServerKey $srv
        if (-not $stateKey) { continue }
        if (Test-ServerBanned $stateKey) { continue }
        if ($curKey -eq $stateKey) { continue }
        if ($Script:State.used.PSObject.Properties[$stateKey]) { continue }
        $candidates += $srv
    }
    if (-not $candidates) { Log 'no unused, unbanned cached candidate for test switch'; return }
    $opt = Optimize-CandidateOrder -Candidates $candidates
    Log ("test candidates: {0} preferred (recent-fail {1}, stale exit IP {2}, bogus host {3})" -f $opt.preferred, $opt.recentFail, $opt.staleExitIp, $opt.bogusHost)
    $cand = @($opt.ordered)[0]
    Log ("test switch to (quality pick): " + ($cand | ConvertTo-Json -Compress))
    $res = Invoke-PipeSwitch -Target $cand
    Log ("test switch result: " + $res)
    # the candidate was consumed either way (success or failed attempt)
    Mark-Used $cand
    if ($res -and $Script:OwnedBurst) {
        Log 'holding the owned core alive for 5 minutes (tunnel on the new server)...'
        for ($i = 0; $i -lt 10 -and $Script:OwnedBurst.Client.IsConnected; $i++) {
            Start-Sleep -Seconds 30
            Log ("keep-alive " + $i + "; owned client connected=" + $Script:OwnedBurst.Client.IsConnected)
        }
        Log 'releasing owned core (tunnel will drop; reconnect via the Happ GUI)'
        try { $Script:OwnedBurst.Client.Dispose() } catch {}
    }
    return
}
if ($TestSessions) {
    Load-State
    $r = Get-FailedSessions -windowMinutes $Script:Cfg.AffectedWindowMin
    if (-not $r) { Log 'no failed sessions found' }
    else {
        $r | ForEach-Object {
            $age = '?'
            if ($_.errCreated) { $age = [math]::Round(([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - [int64]$_.errCreated) / 60000.0) }
            Log ("[rl] {0} (updated {1}, failure {2} min old) : {3}" -f $_.id, $_.when, $age, $_.msg)
        }
    }
    return
}
if ($TestProbe) {
    Load-State
    Push-Location $Script:Cfg.ProjectDir
    try {
        $new = (& opencode api post /api/session --data '{}' 2>&1) -join "`n"
        $sess = $null
        try { $sess = $new | ConvertFrom-Json } catch { }
        $sid = $null
        if ($sess -and $sess.data -and $sess.data.id) { $sid = $sess.data.id }
        elseif ($sess -and $sess.id) { $sid = $sess.id }
        Log ("probe session: " + $sid)
        if ($sid) { Send-ContinueToSession -sessionID $sid | Out-Null }
    } finally { Pop-Location }
    return
}
if ($SwitchProbe) {
    # verify the daemon accepts our 'start' (spawn only, no config, auto-restart off).
    # Expect a temporary second xray that dies immediately (port already bound by the GUI core).
    Load-State
    Log 'sending start burst (probe)...'
    $burst = New-Burst -messages @(
        @{ action = 'start'; 'process-id' = ($Script:Cfg.ProcessId + '-probe'); 'executable' = $Script:Cfg.XrayExe; 'arguments' = @(); 'working-dir' = $Script:Cfg.XrayWorkDir; 'auto-restart' = $false }
    ) -rids @('probe-start')
    Start-Sleep -Seconds 2
    $frames = Read-FramesFrom $burst.Client $burst.Recv -MaxMs 2500
    foreach ($f in $frames) { Log ("resp: " + ($f | ConvertTo-Json -Compress -Depth 4)) }
    try { $burst.Client.Dispose() } catch {}
    for ($i = 0; $i -lt 4; $i++) {
        Start-Sleep -Seconds 1
        $p = Get-DaemonProcess
        Log ("list: " + ($p | ConvertTo-Json -Compress -Depth 4))
    }
    return
}
# ------------------------------------------------------------------- watch
Add-Type -TypeDefinition @'
using System;
public class ConUtil {
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetStdHandle(int h);
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetConsoleScreenBufferInfo(IntPtr h, out CONSOLE_SCREEN_BUFFER_INFO info);
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct COORD { public short X; public short Y; }
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct SMALL_RECT { public short Left; public short Top; public short Right; public short Bottom; }
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct CONSOLE_SCREEN_BUFFER_INFO {
        public COORD dwSize;
        public COORD dwCursorPosition;
        public ushort wAttributes;
        public SMALL_RECT srWindow;
        public COORD dwMaximumWindowSize;
    }
}
'@

# pinned header + last-events view; the frame is redrawn in place from an
# in-memory ring, so window resizes and log volume can never scroll the
# header away and no full-screen clears are needed

function Sync-ConsoleSize {
    # Debounce window resizes: while the user drags the edge, Windows reports
    # changing dimensions and can reflow/scroll the buffer. Wait for a stable
    # size, then re-apply the pinned buffer and redraw from a clean top-left.
    try {
        $w = [int][Console]::WindowWidth
        $h = [int][Console]::WindowHeight
    } catch { return $false }
    if ($w -lt 20 -or $h -lt 5) { return $false }

    $first = ($Script:LastWinW -lt 0 -or $Script:LastWinH -lt 0)
    if ((-not $first) -and $w -eq $Script:LastWinW -and $h -eq $Script:LastWinH) {
        $Script:PendingWinW = -1
        $Script:PendingWinH = -1
        $Script:PendingWinAt = $null
        return $true
    }

    $now = Get-Date
    if ($w -ne $Script:PendingWinW -or $h -ne $Script:PendingWinH) {
        $Script:PendingWinW = $w
        $Script:PendingWinH = $h
        $Script:PendingWinAt = $now
        if (-not $first) { return $false }
    }
    if (-not $first -and $Script:PendingWinAt -and
        (($now - $Script:PendingWinAt).TotalMilliseconds -lt 180)) {
        return $false
    }

    try { [Console]::SetWindowPosition(0, 0) } catch { }
    try { [Console]::SetBufferSize($w, $h) } catch { }
    try { [Console]::SetWindowPosition(0, 0) } catch { }
    $Script:LastWinW = $w
    $Script:LastWinH = $h
    $Script:PendingWinW = -1
    $Script:PendingWinH = -1
    $Script:PendingWinAt = $null
    return $true
}

function Init-ConsoleLayout {
    if (-not $Interactive) { return }
    try {
        if ([Console]::WindowHeight -lt 14 -or [Console]::WindowWidth -lt 40) {
            $Script:LayoutReady = $false
            return
        }
        $Script:LastWinW = -1
        $Script:LastWinH = -1
        $Script:PendingWinW = -1
        $Script:PendingWinH = -1
        $Script:PendingWinAt = $null
        $Script:LayoutReady = $true
        $null = Sync-ConsoleSize
    } catch {
        $Script:LayoutReady = $false
    }
}

function Get-HeaderLines {
    $cur = Get-ActiveServer
    $cached = @(Get-CachedServerList)
    $cacheCount = $cached.Count
    $usedCount = 0
    try { $usedCount = ($Script:State.used.PSObject.Properties | Measure-Object).Count } catch { }
    $bannedCount = 0
    try { $bannedCount = @(Get-BannedEntries).Count } catch { }
    $burnedCount = 0
    try {
        $burnedCount = @($Script:State.sessions.PSObject.Properties | Where-Object {
            $_.Value -and $_.Value.PSObject.Properties['forkID'] -and $_.Value.forkID
        }).Count
    } catch { }
    $curKey = $null
    if ($cur) { $curKey = Get-ServerKey $cur }
    $freshCount = 0
    $unbannedCount = 0
    $usedUnbannedCount = 0
    $freshList = @()
    foreach ($srv in $cached) {
        $k = Get-ServerKey $srv
        if (-not $k) { continue }
        if (Test-ServerBanned $k) { continue }
        $unbannedCount++
        $isCurrent = ($curKey -eq $k)
        if ($Script:State.used.PSObject.Properties[$k]) {
            if (-not $isCurrent) { $usedUnbannedCount++ }
            continue
        }
        if ($isCurrent) { continue }
        $freshCount++
        $freshList += $srv
    }
    $nextLabel = ''
    try {
        $opt = $null
        if ($freshCount -gt 0) { $opt = Optimize-CandidateOrder -Candidates $freshList }
        if ($opt -and $opt.preferred -gt 0) {
            $nextLabel = ('quality ({0} pref + {1} fallback)' -f $opt.preferred, ($opt.recentFail + $opt.staleExitIp + $opt.bogusHost))
        } elseif ($opt) {
            # every unused candidate is demoted right now (recent fails / stale exit IPs)
            $nextLabel = 'random rotation'
        } elseif ($unbannedCount -eq 0) { $nextLabel = '(all banned)' }
        elseif ($usedUnbannedCount -gt 0) { $nextLabel = 'random rotation' }
        else { $nextLabel = '(none)' }
    } catch {
        if ($freshCount -gt 0) { $nextLabel = 'random (' + $freshCount + ' eligible)' } else { $nextLabel = 'random rotation' }
    }
    $curBanned = $false
    if ($curKey) { $curBanned = Test-ServerBanned $curKey }
    $guiProc = Get-Process Happ -ErrorAction SilentlyContinue | Select-Object -First 1
    $xrayProc = Get-Process xray -ErrorAction SilentlyContinue | Select-Object -First 1
    $owned = 'no'
    try {
        if ($Script:OwnedBurst -and $Script:OwnedBurst.Client -and $Script:OwnedBurst.Client.IsConnected) { $owned = 'yes (core kept alive)' }
    } catch { }
    $exitIp = '?'
    $exitWhen = ''
    try { $exitIp = [string]$Script:State.exitIp; $exitWhen = [string]$Script:State.exitIpChecked } catch { }
    if (-not $exitIp) { $exitIp = '?' }
    $pri = $null
    try { $pri = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent() } catch { }
    $elevated = $false
    try {
        if ($pri) { $elevated = $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    } catch { }
    $tunnel = $(if ($xrayProc) { 'UP' } else { 'DOWN - no xray core' })
    $uAction = 'update servers'
    $captureStatus = 'off - [U] continuous server update'
    if ($Script:Capture) {
        $uAction = 'stop capture'
        $elapsed = (Get-Date) - [datetime]$Script:Capture.started
        $captureStatus = ('ON {0} - {1} files - run Happ -> ... -> Ping all; [U] stop + import' -f $elapsed.ToString('mm\:ss'), (Get-CaptureFileCount))
    }
    return @(
        ('Happ Failover Watchdog        {0}                                elevated={1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $elevated),
        ('=============================================================='),
        ('Happ GUI : {0}    xray core: {1}    owned connection: {2}' -f ($(if ($guiProc) { 'running' } else { 'NOT RUNNING' })), ($(if ($xrayProc) { 'running pid ' + $xrayProc.Id } else { 'not running' })), $owned),
        ('Server   : {0}{1}' -f (Format-ServerLabel $cur), $(if ($curBanned) { '   [BANNED]' } else { '' })),
        ('Tunnel   : {0}' -f $tunnel),
        ('Capture  : {0}' -f $captureStatus),
        ('Exit IP  : {0}    (checked {1})' -f $exitIp, $exitWhen),
        ('Next     : {0}    cache: {1}    used: {2}    banned: {3}    burned: {4}    last failover: {5}' -f $nextLabel, $cacheCount, $usedCount, $bannedCount, $burnedCount, $global:LastFailover),
        ('[T] switch now    [B] ban current    [L] bans editor    [R] rescan+revive    [U] {0}    [C] clear used    [Q] quit' -f $uAction),
        ('----------------------------------------------------------------')
    )
}

# ------------------------------------------------------------------- bans editor
# The editor works on the union of cached servers, the active server, and any
# server still present in used/reliability/bans state. That way a ban can always
# be found and removed even if its cache config has disappeared.
function Get-ServerFromKey([string]$key) {
    if (-not $key) { return $null }
    $key = $key.Trim()
    if ($key -match '^(.+):([0-9]{1,5})#([0-9a-fA-F]+)$') {
        $port = [int]$Matches[2]
        if ($port -lt 1 -or $port -gt 65535) { return $null }
        $hostName = $Matches[1]
        $hash = $Matches[3].ToLowerInvariant()
        return [pscustomobject]@{
            host        = $hostName
            port        = $port
            key         = ('{0}:{1}#{2}' -f $hostName, $port, $hash)
            profileHash = $hash
        }
    }
    $i = $key.LastIndexOf(':')
    if ($i -lt 1) { return $null }
    $port = 0
    if (-not [int]::TryParse($key.Substring($i + 1), [ref]$port)) { return $null }
    if ($port -lt 1 -or $port -gt 65535) { return $null }
    $hostName = $key.Substring(0, $i)
    return [pscustomobject]@{
        host        = $hostName
        port        = $port
        key         = ('{0}:{1}' -f $hostName, $port)
        profileHash = ''
    }
}

function Get-AllKnownServers {
    if (-not $Script:State) { Load-State }
    $aliasMap = Get-CachedServerAliasMap
    $map = @{}
    $profileNames = @{}
    $ensure = {
        param([string]$hostName, [int]$port, [string]$key)
        if (-not $key) { $key = '{0}:{1}' -f $hostName, $port }
        if (-not $map.ContainsKey($key)) {
            $map[$key] = [pscustomobject]@{
                host      = [string]$hostName
                port      = [int]$port
                key       = [string]$key
                names     = (New-Object System.Collections.Generic.List[string])
                isProfile = $false
            }
        }
        return $map[$key]
    }

    foreach ($srv in @(Get-CachedServerList)) {
        $key = Get-ServerKey $srv
        if (-not $key) { continue }
        $rec = & $ensure ([string]$srv.host) ([int]$srv.port) $key
        if ($srv.PSObject.Properties['profileHash'] -and $srv.profileHash) {
            $rec.isProfile = $true
            $n = ([string](Get-CachedServerName ([string]$srv.host) ([int]$srv.port) $key)).Trim()
            if ($n -and -not $rec.names.Contains($n)) { $rec.names.Add($n) }
            if ($n) { $profileNames[('{0}:{1}|{2}' -f $srv.host, $srv.port, $n.ToLowerInvariant())] = $key }
        }
    }
    # names captured for this endpoint (primary file + aliases + recovered
    # malformed captures such as a corrupted "_443.json")
    foreach ($key in @($aliasMap.Keys)) {
        if (-not $map.ContainsKey($key)) { continue }
        $rec = $map[$key]
        foreach ($n in @($aliasMap[$key])) {
            if (-not $n) { continue }
            $profileLookup = ('{0}|{1}' -f $key, ([string]$n).ToLowerInvariant())
            if ($profileNames.ContainsKey($profileLookup)) { continue }
            if (-not $rec.names.Contains($n)) { $rec.names.Add($n) }
        }
    }
    foreach ($rec in @($map.Values)) {
        if ($rec.names.Count -eq 0) {
            $n = ([string](Get-CachedServerName ([string]$rec.host) ([int]$rec.port) ([string]$rec.key))).Trim()
            if ($n) { $rec.names.Add($n) }
        }
    }

    $active = Get-ActiveServer
    if ($active) {
        $aKey = Get-ServerKey $active
        if ($aKey) {
            $rec = & $ensure ([string]$active.host) ([int]$active.port) $aKey
            if ($aKey -match '#') { $rec.isProfile = $true }
            $aName = ([string]$active.name).Trim()
            if (-not $aName) { $aName = ([string](Get-CachedServerName ([string]$active.host) ([int]$active.port) $aKey)).Trim() }
            if ($aName -and -not $rec.names.Contains($aName)) { $rec.names.Add($aName) }
        }
    }

    $addKey = {
        param([string]$key)
        if (-not $key) { return }
        $srv = Get-ServerFromKey $key
        if (-not $srv) { return }
        $rec = & $ensure ([string]$srv.host) ([int]$srv.port) ([string]$srv.key)
        if ([string]$srv.key -match '#') { $rec.isProfile = $true }
        if ($rec.names.Count -eq 0) {
            $n = ([string](Get-CachedServerName ([string]$srv.host) ([int]$srv.port) ([string]$srv.key))).Trim()
            if ($n) { $rec.names.Add($n) }
        }
    }
    foreach ($ban in @(Get-BannedEntries)) { & $addKey ([string]$ban.Name) }
    try { foreach ($prop in @($Script:State.used.PSObject.Properties)) { & $addKey ([string]$prop.Name) } } catch { }
    try {
        $rel = $Script:State.reliability
        if ($rel) { foreach ($prop in @($rel.PSObject.Properties)) { & $addKey ([string]$prop.Name) } }
    } catch { }

    $curKey = $null
    if ($active) { $curKey = Get-ServerKey $active }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($rec in $map.Values) {
        $names = @($rec.names | Where-Object { $_ })
        if (-not $names.Count) { $names = @('') }
        $banInfo = Get-ServerBanInfo $rec.key
        $banned = [bool]$banInfo
        $used = $false
        try { $used = [bool]$Script:State.used.PSObject.Properties[$rec.key] } catch { }
        $current = ($rec.key -eq $curKey)
        $endpointKey = ('{0}:{1}' -f $rec.host, $rec.port)
        $endpointPrimary = ''
        if ($aliasMap.ContainsKey($endpointKey)) {
            $epNames = @($aliasMap[$endpointKey])
            if ($epNames.Count -gt 0) { $endpointPrimary = [string]$epNames[0] }
        }
        for ($i = 0; $i -lt $names.Count; $i++) {
            $nm = [string]$names[$i]
            $primary = [string]$names[0]
            $rowIsProfile = [bool]$rec.isProfile
            $aliasOf = ''
            if ($rowIsProfile) { $aliasOf = $endpointPrimary }
            elseif ($i -gt 0) { $aliasOf = $primary }
            $rows.Add([pscustomobject]@{
                host       = $rec.host
                port       = [int]$rec.port
                key        = $rec.key
                uid        = ($rec.key + '#' + $nm + '#' + $i)
                name       = $nm
                aliasOf    = $aliasOf
                isAlias    = ($i -gt 0 -or $rowIsProfile)
                isProfile  = $rowIsProfile
                banned     = $banned
                banAuto    = $(if ($banInfo) { [bool]$banInfo.auto } else { $false })
                banKind    = $(if ($banInfo) { [string]$banInfo.kind } else { '' })
                banReason  = $(if ($banInfo) { [string]$banInfo.reason } else { '' })
                banSince   = $(if ($banInfo) { [string]$banInfo.at } else { '' })
                banSource  = $(if ($banInfo) { [string]$banInfo.source } else { '' })
                banWildcard = $(if ($banInfo) { [bool]$banInfo.wildcard } else { $false })
                current    = $current
                used       = $used
                sortBanned = $(if ($banned) { 0 } else { 1 })
                sortName   = $(if ($nm) { $nm.ToLowerInvariant() } else { $rec.key.ToLowerInvariant() })
            })
        }
    }
    return @($rows | Sort-Object sortBanned, sortName, key, uid)
}

function Refresh-BansEditor {
    if (-not $Script:BansEditor) { return }
    $selectedKey = $null
    try {
        $old = @($Script:BansEditor.Items)
        if ($old.Count -gt 0 -and $Script:BansEditor.Index -ge 0 -and $Script:BansEditor.Index -lt $old.Count) {
            $selectedKey = [string]$old[$Script:BansEditor.Index].uid
            if (-not $selectedKey) { $selectedKey = [string]$old[$Script:BansEditor.Index].key }
        }
    } catch { }
    $oldSuppress = $Script:SuppressRender
    $Script:SuppressRender = $true
    try {
        $items = @(Get-AllKnownServers)
    } finally {
        $Script:SuppressRender = $oldSuppress
    }
    $idx = 0
    if ($selectedKey) {
        for ($i = 0; $i -lt $items.Count; $i++) {
            $iuid = [string]$items[$i].uid
            if (-not $iuid) { $iuid = [string]$items[$i].key }
            if ($iuid -eq $selectedKey) { $idx = $i; break }
        }
    }
    if ($items.Count -eq 0) { $idx = 0 }
    elseif ($idx -ge $items.Count) { $idx = $items.Count - 1 }
    $Script:BansEditor.Items = $items
    $Script:BansEditor.Index = $idx
    if ($Script:BansEditor.Offset -gt $idx) { $Script:BansEditor.Offset = $idx }
    if ($Script:BansEditor.Offset -lt 0) { $Script:BansEditor.Offset = 0 }
}

function Open-BansEditor {
    Load-Bans
    $Script:BansEditor = [pscustomobject]@{
        Active = $true
        Items  = @()
        Index  = 0
        Offset = 0
    }
    Refresh-BansEditor
}

function Close-BansEditor {
    $Script:BansEditor = $null
}

function Move-BansEditorSelection([int]$delta) {
    if (-not $Script:BansEditor -or -not $Script:BansEditor.Active) { return }
    $items = @($Script:BansEditor.Items)
    if (-not $items.Count) { return }
    $next = [int]$Script:BansEditor.Index + $delta
    if ($next -lt 0) { $next = 0 }
    if ($next -ge $items.Count) { $next = $items.Count - 1 }
    $Script:BansEditor.Index = $next
}

function Reorder-BansEditor {
    # Re-sort the in-memory list after a toggle. This avoids re-reading every
    # cached config (and the registry) on each Enter press.
    if (-not $Script:BansEditor -or -not $Script:BansEditor.Active) { return }
    $old = @($Script:BansEditor.Items)
    if (-not $old.Count) { return }
    $selectedKey = $null
    $idx = [int]$Script:BansEditor.Index
    if ($idx -ge 0 -and $idx -lt $old.Count) {
        $selectedKey = [string]$old[$idx].uid
        if (-not $selectedKey) { $selectedKey = [string]$old[$idx].key }
    }
    foreach ($item in $old) {
        $bi = Get-ServerBanInfo $item.key
        $item.banned = [bool]$bi
        $item.banAuto = $(if ($bi) { [bool]$bi.auto } else { $false })
        $item.banKind = $(if ($bi) { [string]$bi.kind } else { '' })
        $item.banReason = $(if ($bi) { [string]$bi.reason } else { '' })
        $item.banSince = $(if ($bi) { [string]$bi.at } else { '' })
        $item.banSource = $(if ($bi) { [string]$bi.source } else { '' })
        $item.banWildcard = $(if ($bi) { [bool]$bi.wildcard } else { $false })
        $item.sortBanned = $(if ($item.banned) { 0 } else { 1 })
    }
    $items = @($old | Sort-Object sortBanned, sortName, key, uid)
    $newIdx = 0
    if ($selectedKey) {
        for ($i = 0; $i -lt $items.Count; $i++) {
            $iuid = [string]$items[$i].uid
            if (-not $iuid) { $iuid = [string]$items[$i].key }
            if ($iuid -eq $selectedKey) { $newIdx = $i; break }
        }
    }
    $Script:BansEditor.Items = $items
    $Script:BansEditor.Index = $newIdx
    if ($Script:BansEditor.Offset -gt $newIdx) { $Script:BansEditor.Offset = $newIdx }
    if ($Script:BansEditor.Offset -lt 0) { $Script:BansEditor.Offset = 0 }
}

function Toggle-BansEditorSelection {
    if (-not $Script:BansEditor -or -not $Script:BansEditor.Active) { return }
    $items = @($Script:BansEditor.Items)
    if (-not $items.Count) { return }
    $idx = [Math]::Max(0, [Math]::Min([int]$Script:BansEditor.Index, $items.Count - 1))
    $item = $items[$idx]
    # ban/unban logs an event; suppress its render so the editor repaints once,
    # with the new state and order, instead of flashing the old list first
    $Script:SuppressRender = $true
    try {
        if ($item.banned) {
            $hadExact = [bool]$Script:Bans.PSObject.Properties[$item.key]
            Remove-BannedServer $item.key | Out-Null
            # A profile can also be covered by an old endpoint-wide ban. If the
            # row had no exact entry, Enter is meant to clear that wildcard. If
            # it did have an exact auto/manual entry, leave the endpoint's own
            # ban alone; the row will simply remain covered by it.
            $wildcardKey = ''
            if ([string]$item.key -match '^(.+:[0-9]{1,5})#[0-9a-fA-F]+$') { $wildcardKey = $Matches[1] }
            if (-not $hadExact -and $wildcardKey -and (Test-ServerBanned $item.key)) {
                Remove-BannedServer $wildcardKey | Out-Null
            }
        } else {
            Add-BannedServer $item.key 'bans editor' | Out-Null
        }
    } finally {
        $Script:SuppressRender = $false
    }
    Reorder-BansEditor
}

function Start-BansEditor {
    # Modal, fast input loop. While the editor is open the slower watchdog
    # polling is paused so keystrokes never wait behind API/tunnel checks.
    # A daemon heartbeat is still sent periodically.
    if (-not $Interactive) { return }
    try {
        Open-BansEditor
    } catch {
        Log ("bans editor open failed: " + $_.Exception.Message)
        Close-BansEditor
        return
    }
    if ($Script:LayoutReady) { Render-Frame }
    $beatAt = Get-Date
    try {
        while ($Script:BansEditor -and $Script:BansEditor.Active) {
            $redraw = $false
            if (-not $Script:LayoutReady) {
                Init-ConsoleLayout
                $redraw = $true
            }
            try {
                while ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    $redraw = $true
                    switch ($key.Key) {
                        'UpArrow'    { Move-BansEditorSelection -delta -1 }
                        'DownArrow'  { Move-BansEditorSelection -delta 1 }
                        'PageUp'     { Move-BansEditorSelection -delta -10 }
                        'PageDown'   { Move-BansEditorSelection -delta 10 }
                        'Home'       { Move-BansEditorSelection -delta -9999 }
                        'End'        { Move-BansEditorSelection -delta 9999 }
                        'Enter'      { Toggle-BansEditorSelection }
                        'R'          { Refresh-BansEditor }
                        'Escape'     { Close-BansEditor }
                        'L'          { Close-BansEditor }
                        'Q'          { Close-BansEditor }
                    }
                    if (-not $Script:BansEditor -or -not $Script:BansEditor.Active) { break }
                }
            } catch { }
            try {
                if ([Console]::WindowWidth -ne $Script:LastWinW -or
                    [Console]::WindowHeight -ne $Script:LastWinH) { $redraw = $true }
            } catch { }
            if ($redraw -and $Script:BansEditor -and $Script:BansEditor.Active -and $Script:LayoutReady) {
                Render-Frame
            }
            if (((Get-Date) - $beatAt).TotalSeconds -ge $Script:Cfg.HeartbeatSec) {
                try { $null = Send-Daemon -obj @{ action = 'heartbeat' } -WaitMs 300 } catch { }
                $Script:DaemonUtil.LastBeat = Get-Date
                $beatAt = Get-Date
            }
            Start-Sleep -Milliseconds 25
        }
    } finally {
        $Script:SuppressRender = $false
        if ($Script:BansEditor -and $Script:BansEditor.Active) { Close-BansEditor }
        if ($Script:LayoutReady) { Render-Frame }
    }
}

function Render-BansEditor {
    if (-not $Script:BansEditor -or -not $Script:BansEditor.Active) { return }
    if (-not $Script:LayoutReady) { return }
    try {
        if (-not (Sync-ConsoleSize)) { return }
        $w = [int]$Script:LastWinW
        $h = [int]$Script:LastWinH

        $items = @($Script:BansEditor.Items)
        $count = $items.Count
        $idx = [int]$Script:BansEditor.Index
        if ($count -eq 0) { $idx = 0 }
        elseif ($idx -lt 0) { $idx = 0 }
        elseif ($idx -ge $count) { $idx = $count - 1 }
        $Script:BansEditor.Index = $idx
        $bannedKeys = @{}
        $endpointKeys = @{}
        foreach ($it in $items) {
            $epKey = [string]$it.key
            if ($epKey -match '^(.+:[0-9]{1,5})#[0-9a-fA-F]+$') { $epKey = $Matches[1] }
            if ($epKey) { $endpointKeys[$epKey] = $true }
            if ($it.banned -and $it.key) { $bannedKeys[$it.key] = $true }
        }
        $bannedCount = $bannedKeys.Count
        $endpointCount = $endpointKeys.Count
        $autoBannedCount = @($items | Where-Object { $_.banned -and $_.banAuto } | ForEach-Object { $_.key } | Sort-Object -Unique).Count

        $hdrRows = 3
        $ftrRows = 1
        $view = [Math]::Max(1, $h - $hdrRows - $ftrRows)
        $offset = [int]$Script:BansEditor.Offset
        if ($idx -lt $offset) { $offset = $idx }
        if ($idx -ge ($offset + $view)) { $offset = $idx - $view + 1 }
        $maxOffset = [Math]::Max(0, $count - $view)
        if ($offset -gt $maxOffset) { $offset = $maxOffset }
        if ($offset -lt 0) { $offset = 0 }
        $Script:BansEditor.Offset = $offset
        $first = $(if ($count -gt 0) { $offset + 1 } else { 0 })
        $last = [Math]::Min($count, $offset + $view)

        $rows = New-Object System.Collections.Generic.List[object]
        $rows.Add([pscustomobject]@{
            Text = ('BANS/SERVERS   {0} rows / {1} endpoints   banned {2} ({5} auto)   {3}-{4}   red=manual  orange=quota   Up/Down move   Enter toggle   R rescan   Esc/L close' -f $count, $endpointCount, $bannedCount, $first, $last, $autoBannedCount)
            Fg   = [ConsoleColor]::Cyan
            Bg   = [ConsoleColor]::Black
        })
        $rows.Add([pscustomobject]@{
            Text = ('=' * [Math]::Max(1, $w))
            Fg   = [ConsoleColor]::DarkGray
            Bg   = [ConsoleColor]::Black
        })
        $rows.Add([pscustomobject]@{
            Text = '  STATE     CUR@ NAME                             HOST:PORT                 USED   (~ alias, @ profile)'
            Fg   = [ConsoleColor]::DarkGray
            Bg   = [ConsoleColor]::Black
        })

        for ($i = $offset; $i -lt $last; $i++) {
            $item = $items[$i]
            $selected = ($i -eq $idx)
            $status = $(if ($item.banned -and $item.banAuto) { '[AUTO]' } elseif ($item.banned) { '[BANNED]' } else { '[  ok  ]' })
            $selMark = $(if ($selected) { '>' } else { ' ' })
            $curMark = $(if ($item.current) { '*' } else { ' ' })
            $usedMark = $(if ($item.used) { 'used' } else { '    ' })
            $aliasMark = $(if ($item.isProfile) { '@' } elseif ($item.isAlias) { '~' } else { ' ' })
            $name = [string]$item.name
            if (-not $name) { $name = '(unnamed)' }
            $prefix = ('{0} {1} {2}{3} ' -f $selMark, $status, $curMark, $aliasMark)
            $suffix = ('  {0}  {1}' -f $item.key, $usedMark)
            $avail = [Math]::Max(8, $w - $prefix.Length - $suffix.Length)
            if ($name.Length -gt $avail) {
                if ($avail -le 3) { $name = $name.Substring(0, $avail) }
                else { $name = $name.Substring(0, $avail - 3) + '...' }
            }
            $text = $prefix + $name.PadRight($avail) + $suffix
            if ($selected -and $item.banned -and $item.banAuto) {
                $fg = [ConsoleColor]::Black; $bg = [ConsoleColor]::DarkYellow
            } elseif ($selected -and $item.banned) {
                $fg = [ConsoleColor]::White; $bg = [ConsoleColor]::DarkRed
            } elseif ($selected) {
                $fg = [ConsoleColor]::Black; $bg = [ConsoleColor]::Cyan
            } elseif ($item.banned -and $item.banAuto) {
                $fg = [ConsoleColor]::DarkYellow; $bg = [ConsoleColor]::Black
            } elseif ($item.banned) {
                $fg = [ConsoleColor]::Red; $bg = [ConsoleColor]::Black
            } elseif ($item.current) {
                $fg = [ConsoleColor]::Yellow; $bg = [ConsoleColor]::Black
            } else {
                $fg = [ConsoleColor]::Gray; $bg = [ConsoleColor]::Black
            }
            $rows.Add([pscustomobject]@{ Text = $text; Fg = $fg; Bg = $bg })
        }
        if ($count -eq 0) {
            $rows.Add([pscustomobject]@{
                Text = '  (no known servers - press R to rescan the cache)'
                Fg   = [ConsoleColor]::Yellow
                Bg   = [ConsoleColor]::Black
            })
        }
        while ($rows.Count -lt ($h - 1)) {
            $rows.Add([pscustomobject]@{ Text = ''; Fg = [ConsoleColor]::Gray; Bg = [ConsoleColor]::Black })
        }

        $footer = 'No server selected'
        if ($count -gt 0) {
            $sel = $items[$idx]
            $label = $(if ($sel.name) { $sel.name } else { '(unnamed)' })
            $action = $(if ($sel.banned) { 'ENTER unban' } else { 'ENTER ban' })
            $banNote = $(if ($sel.banned -and $sel.banAuto) { 'AUTO quota ban' } elseif ($sel.banned) { 'manual ban' } else { 'not banned' })
            if ($sel.isProfile) {
                $base = $(if ($sel.aliasOf) { $sel.aliasOf } else { '(endpoint)' })
                $footer = ('Profile: {0}  ({1}) = same host:port as {2}; {3}; {4}   |   Up/Down move   Enter toggle   R rescan   Esc/L close' -f $label, $sel.key, $base, $banNote, $action)
            } elseif ($sel.isAlias) {
                $base = $(if ($sel.aliasOf) { $sel.aliasOf } else { '(primary)' })
                $footer = ('Alias: {0}  ({1}) = same endpoint as {2}; {3}; {4} affects the shared endpoint   |   Up/Down move   Enter toggle   R rescan   Esc/L close' -f $label, $sel.key, $base, $banNote, $action)
            } else {
                $footer = ('Selected: {0}  ({1})   {2}; {3}   |   Up/Down move   Enter toggle   R rescan   Esc/L close' -f $label, $sel.key, $banNote, $action)
            }
        }
        $rows.Add([pscustomobject]@{ Text = $footer; Fg = [ConsoleColor]::Cyan; Bg = [ConsoleColor]::Black })

        $lastFg = $null
        $lastBg = $null
        for ($row = 0; $row -lt $h; $row++) {
            $r = $null
            if ($row -lt $rows.Count) { $r = $rows[$row] }
            if ($r) { $txt = [string]$r.Text; $fg = $r.Fg; $bg = $r.Bg }
            else { $txt = ''; $fg = [ConsoleColor]::Gray; $bg = [ConsoleColor]::Black }
            if ($txt.Length -gt $w) { $txt = $txt.Substring(0, $w) } else { $txt = $txt.PadRight($w) }
            [Console]::SetCursorPosition(0, $row)
            try {
                # only touch the console colors when they actually change; this
                # halves the API calls on long runs of same-colored rows
                if ($fg -ne $lastFg) { [Console]::ForegroundColor = $fg; $lastFg = $fg }
                if ($bg -ne $lastBg) { [Console]::BackgroundColor = $bg; $lastBg = $bg }
            } catch { }
            [Console]::Write($txt)
        }
        [Console]::ResetColor()
        [Console]::SetCursorPosition(0, [Math]::Max(0, $h - 1))
    } catch {
        try { [Console]::ResetColor() } catch { }
        try {
            $pos = ''
            try { if ($_.InvocationInfo) { $pos = ' at ' + (Split-Path -Leaf $_.InvocationInfo.ScriptName) + ':' + $_.InvocationInfo.ScriptLineNumber } } catch { }
            ('[bans-editor] ' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message + $pos) | Out-File $Script:Cfg.LogPath -Append -Encoding utf8
        } catch { }
        $Script:LayoutReady = $false
    }
}

function Render-Frame {
    if ($Script:BansEditor -and $Script:BansEditor.Active) {
        Render-BansEditor
        return
    }
    if (-not $Script:LayoutReady) { return }
    try {
        if (-not (Sync-ConsoleSize)) { return }
        $w = [int]$Script:LastWinW
        $h = [int]$Script:LastWinH
        $hdr = Get-HeaderLines
        $nHdr = [Math]::Min($hdr.Count, $h)
        $evRows = [Math]::Max(0, $h - $nHdr)
        # flatten the ring into row chunks of the current width
        $flat = New-Object System.Collections.Generic.List[string]
        foreach ($e in $Script:EventRing) {
            $e = [string]$e
            if ($e.Length -le $w) { $flat.Add($e); continue }
            for ($p = 0; $p -lt $e.Length; $p += $w) {
                $flat.Add($e.Substring($p, [Math]::Min($w, $e.Length - $p)))
            }
        }
        $skip = [Math]::Max(0, $flat.Count - $evRows)
        for ($row = 0; $row -lt $h; $row++) {
            $txt = ''
            if ($row -lt $nHdr) { $txt = [string]$hdr[$row] }
            else {
                $idx = $skip + ($row - $nHdr)
                if ($idx -lt $flat.Count) { $txt = $flat[$idx] }
            }
            if ($txt.Length -gt $w) { $txt = $txt.Substring(0, $w) } else { $txt = $txt.PadRight($w) }
            [Console]::SetCursorPosition(0, $row)
            [Console]::Write($txt)
        }
        [Console]::SetCursorPosition(0, [Math]::Max(0, $h - 1))
    } catch {
        try {
            $pos = ''
            try { if ($_.InvocationInfo) { $pos = ' at ' + (Split-Path -Leaf $_.InvocationInfo.ScriptName) + ':' + $_.InvocationInfo.ScriptLineNumber } } catch { }
            ('[render] ' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message + $pos) | Out-File $Script:Cfg.LogPath -Append -Encoding utf8
        } catch { }
        $Script:LayoutReady = $false
    }
}

function Write-ConsoleEvent([string]$msg) {
    try { $Script:EventRing.Add([string]$msg) } catch { }
    while ($Script:EventRing.Count -gt $Script:RingCap) {
        try { $Script:EventRing.RemoveAt(0) } catch { break }
    }
    if (-not $Script:SuppressRender) { Render-Frame }
}

if ($ListServers) {
    Load-State
    Show-CachedServers
    return
}

if ($CaptureAll) {
    Load-State
    if (-not (Start-CaptureMode -Seconds $CaptureSeconds)) { return }
    try {
        $deadline = (Get-Date).AddSeconds([Math]::Max(1, $CaptureSeconds))
        while ((Get-Date) -lt $deadline -and $Script:Capture -and $Script:Capture.proc -and -not $Script:Capture.proc.HasExited) {
            Update-CaptureMode
            Start-Sleep -Seconds 1
        }
    } finally {
        if ($Script:Capture) { Stop-CaptureMode | Out-Null }
    }
    Show-CachedServers
    return
}

if ($Watch) {
    Load-State
    $global:LastFailover = Get-Date
    $global:LastSwitchAt = $global:LastFailover
    $global:FailoverPromptStart = $null
    $global:FailoverPromptEnd = $null
    # Ignore timeout errors that predate this watchdog run: old sessions are
    # not evidence against the currently selected server.
    try {
        Add-Member -InputObject $Script:State -NotePropertyName timeoutUntil -NotePropertyValue ([string][DateTimeOffset]::Now.ToUnixTimeMilliseconds()) -Force
        Save-State
    } catch { }
    Log 'watchdog starting; tracking current server as used'
    $cur = Get-ActiveServer
    if ($cur) {
        Mark-Used $cur
        if (Test-ServerBanned (Get-ServerKey $cur)) {
            Log ('WARNING: current server ' + (Format-ServerLabel $cur) + ' is banned - the next switch will leave it')
        }
    }
    $startupBans = @(Get-BannedEntries).Count
    if ($startupBans -gt 0) { Log ("banned server list loaded: " + $startupBans) }
    $mutex = New-Object System.Threading.Mutex($false, 'happ-failover-watchdog')
    if (-not $mutex.WaitOne(50, $false)) { Log 'another instance running - exiting'; return }
    Log 'watchdog active'
    Init-ConsoleLayout
    $bootExit = Test-ProxyExit -tries 1
    if ($bootExit) {
        Log ("exit IP at startup: " + $bootExit)
    } else {
        Log 'exit IP check at startup: tunnel not ready'
        # A dead tunnel at boot most often means the previous instance Q'd while
        # it owned the core + TUN (the daemon kills owned records on client
        # disconnect). If TUN mode is known-good for this machine, recover on the
        # first health tick instead of waiting out the failover cooldown.
        $tun0 = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'happ' }
        if (-not $tun0) {
            $stateTunSeen = $false
            try { $stateTunSeen = [bool]$Script:State.tunSeen } catch { }
            if ($stateTunSeen) {
                Log 'tunnel was down at boot - scheduling immediate recovery on the first health tick'
                $Script:DeadStreak = 2
                $global:LastFailover = (Get-Date).AddSeconds(-1 * ($CooldownSec + 1))
            }
        }
    }
    if ($Interactive) {
        # The alias map is the only expensive part of opening the bans editor
        # (PowerShell JSON parsing of every captured config). Build it once now,
        # before keystrokes are accepted, so [L] opens instantly.
        try {
            $warm = [Diagnostics.Stopwatch]::StartNew()
            Get-CachedServerAliasMap | Out-Null
            $warm.Stop()
            Log ("server-name index warmed in {0} ms" -f [int]$warm.Elapsed.TotalMilliseconds)
        } catch { }
    }
    if ($Interactive -and $Script:LayoutReady) { Render-Frame }
    try { $host.UI.RawUI.WindowTitle = 'Happ Failover Watchdog' } catch { }
    while ($true) {
        try {
            Update-CaptureMode
            Load-Bans
            $fails = Test-OpLogTail
            $now = Get-Date
            # rate limits take priority: full server failover. Compare against the
            # failover start, not a fixed 15s margin; otherwise a quota error
            # arriving seconds after a switch could be ignored forever.
            if ($fails.rate -and $fails.rate -gt $global:LastFailover) {
                # A quota line is dominant even when a newer generic rate line
                # follows it: the free window is exhausted, so the orange ban
                # must not be skipped. Both timestamps are after LastFailover.
                $quotaError = ($fails.quota -and $fails.rate -and $fails.quota -gt $global:LastFailover)
                $switchCool = Get-SwitchCooldownSec
                if ($quotaError -or $now -gt $global:LastFailover.AddSeconds($switchCool)) {
                    if ($quotaError) {
                        Log 'free usage limit detected in opencode log - auto-banning current server and switching now'
                        Invoke-Failover -Reason 'quota' -Fast
                    } else {
                        Log 'rate limit detected in opencode log - fast failover starting'
                        Invoke-Failover -Reason 'auto' -Fast
                    }
                }
            }
            # endpoint-unavailable: soft path (continue retries on the same server first)
            if ($Script:Soft.active -and $Script:Soft.lastSeen -and ((Get-Date) - $Script:Soft.lastSeen).TotalMinutes -gt 15) {
                Log 'no new endpoint errors for 15+ minutes - soft-retry state reset'
                $Script:Soft = New-SoftState
            }
            if ($fails.endpoint -and ($fails.endpoint -gt $Script:Soft.lastSeen)) {
                $Script:Soft.lastSeen = $fails.endpoint
                Handle-Endpoint
            }
            # connection-loss bursts and provider timeouts (neither reaches
            # opencode.log - scan the session API on its own slower cadence)
            if ($null -eq $Script:ConnResetLast -or ((Get-Date) - $Script:ConnResetLast).TotalSeconds -ge $Script:Cfg.ConnResetScanSec) {
                $Script:ConnResetLast = Get-Date
                $scan = Test-SessionFailureScan
                # Only timeouts newer than the current server generation can be
                # evidence against it. The switch timestamp also excludes errors
                # from the previous server while it was shutting down. A later
                # failover attempt that never switched advances LastFailover and
                # therefore raises the floor as well.
                $epoch = $global:LastFailover
                if ($global:LastSwitchAt -and $global:LastSwitchAt -gt $epoch) { $epoch = $global:LastSwitchAt }
                $epochMs = ([DateTimeOffset]$epoch).ToUnixTimeMilliseconds()
                $newTimeouts = @($scan.timeouts | Where-Object { $_ -and [int64]$_.created -gt $epochMs })
                $instantTimeout = $null
                $newestTimeout = $null
                foreach ($to in $newTimeouts) {
                    if (-not $newestTimeout -or [int64]$to.created -gt [int64]$newestTimeout.created) { $newestTimeout = $to }
                    if (-not $instantTimeout -and (Test-TimeoutWasInstant $to)) { $instantTimeout = $to }
                }
                $timeoutHandled = $false
                if ($instantTimeout) {
                    Log ("timeout immediately after continue in {0} - auto-banning current server and fast switching" -f $instantTimeout.sessionID)
                    $until = [int64]$newestTimeout.created
                    Add-Member -InputObject $Script:State -NotePropertyName timeoutUntil -NotePropertyValue ([string]$until) -Force
                    Save-State
                    $timeoutHandled = $true
                    Invoke-Failover -Reason 'timeout-instant' -Fast
                } elseif ($newestTimeout) {
                    if ((Get-Date) -gt $global:LastFailover.AddSeconds((Get-SwitchCooldownSec))) {
                        Log ("timeout in {0} after the server had been in use - marking it used and switching (no ban)" -f $newestTimeout.sessionID)
                        $until = [int64]$newestTimeout.created
                        Add-Member -InputObject $Script:State -NotePropertyName timeoutUntil -NotePropertyValue ([string]$until) -Force
                        Save-State
                        $timeoutHandled = $true
                        Invoke-Failover -Reason 'timeout' -Fast
                    } else {
                        Log 'timeout detected but failover cooldown is active - waiting'
                    }
                }
                $crCount = [int]$scan.connReset
                if (-not $timeoutHandled -and $crCount -ge $Script:Cfg.ConnResetMinCount) {
                    if ((Get-Date) -gt $global:LastFailover.AddSeconds((Get-SwitchCooldownSec))) {
                        Log ("{0} connection-loss failures within {1}s - fast switching server" -f $crCount, $Script:Cfg.ConnResetWindowSec)
                        Add-Member -InputObject $Script:State -NotePropertyName connResetUntil -NotePropertyValue ([string][DateTimeOffset]::Now.ToUnixTimeMilliseconds()) -Force
                        Save-State
                        Invoke-Failover -Reason 'connreset-burst' -Fast
                    } else {
                        Log ("{0} connection-loss failures detected but cooldown active - waiting" -f $crCount)
                    }
                }
            }
            # system-route health: network gone with idle sessions never reaches the
            # session API, so probe it on its own cadence; a vanished TUN adapter
            # (seen alive before) is restored directly, a dead route trips a failover
            if ($null -eq $Script:TunnelLast -or ((Get-Date) - $Script:TunnelLast).TotalSeconds -ge $Script:Cfg.TunnelScanSec) {
                $Script:TunnelLast = Get-Date
                $th = Get-TunnelHealth
                $skipFailoverTick = $false
                if ($th.adapterAlive) {
                    $Script:SawTunAlive = $true
                    $Script:AdapterStreak = 0
                    # remember TUN mode is used on this machine - enables the instant
                    # boot-time recovery the next time the tunnel is down at startup
                    if (-not $Script:State.tunSeen) {
                        try {
                            Add-Member -InputObject $Script:State -NotePropertyName tunSeen -NotePropertyValue $true -Force
                            Save-State
                        } catch { }
                    }
                } elseif ($Script:SawTunAlive) {
                    $Script:AdapterStreak++
                }
                if ($th.plainOk) { $Script:DeadStreak = 0 } else { $Script:DeadStreak++ }
                if ($Script:SawTunAlive -and $Script:AdapterStreak -ge 2 -and (-not $th.adapterAlive)) {
                    Log 'TUN adapter missing on two consecutive checks - restoring the system tunnel'
                    $Script:AdapterStreak = 0
                    if ($Script:OwnedTun) { try { $Script:OwnedTun.Client.Dispose() } catch { } }
                    $Script:OwnedTun = Start-TunBurst -configPath $Script:Cfg.TunConfigPath
                    Start-Sleep -Seconds 4
                    $tun3 = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'happ' }
                    if ($tun3) { Log ('TUN restored: ' + (($tun3.Name) -join ', ')) } else { Log 'TUN restore failed' }
                    $skipFailoverTick = $true
                }
                if (-not $skipFailoverTick -and $Script:DeadStreak -ge 2) {
                    if ((Get-Date) -gt $global:LastFailover.AddSeconds((Get-SwitchCooldownSec))) {
                        Log ('network unreachable through the tunnel for ~' + ($Script:Cfg.TunnelScanSec * 2) + 's - fast switching server')
                        $Script:DeadStreak = 0
                        Invoke-Failover -Reason 'tunnel-dead' -Fast
                    } else {
                        Log 'network unreachable but failover cooldown active - waiting'
                    }
                }
            }
        } catch { Log ("watch loop error: " + $_.Exception.Message) }

        try {
            if ($null -eq $Script:DaemonUtil.LastBeat -or ((Get-Date) - $Script:DaemonUtil.LastBeat).TotalSeconds -gt $Script:Cfg.HeartbeatSec) {
                $null = Send-Daemon -obj @{ action = 'heartbeat' } -WaitMs 900
                $Script:DaemonUtil.LastBeat = Get-Date
            }
        } catch { Log ("heartbeat error: " + $_.Exception.Message) }

        if ($Interactive) {
            if (-not $Script:LayoutReady) { Init-ConsoleLayout }
            if ($Script:LayoutReady) { Render-Frame }
        }
        # keep a tight console input loop: keys and resizes are handled within
        # ~100ms, while the slower poll logic above still runs on its own cadence
        for ($t = 0; $t -lt ([Math]::Max(1, [int]($PollSeconds * 10))); $t++) {
            if ($Interactive) {
                # recover from a transient render error or a resize while idle
                if (-not $Script:LayoutReady) {
                    Init-ConsoleLayout
                    if ($Script:LayoutReady) { Render-Frame }
                } else {
                    try {
                        if ([Console]::WindowWidth -ne $Script:LastWinW -or
                            [Console]::WindowHeight -ne $Script:LastWinH) { Render-Frame }
                    } catch { }
                }
                $drain = $true
                while ($drain) {
                    $hit = $false
                    try { $hit = [Console]::KeyAvailable } catch { }
                    if ($hit) {
                        $key = [Console]::ReadKey($true)
                        switch ($key.Key) {
                            'T' { Log 'manual switch requested [T]'; Invoke-Failover -Reason 'manual' | Out-Null }
                            'B' {
                                $curB = Get-ActiveServer
                                if (-not $curB) {
                                    Log 'cannot determine the active server - use -BanServer host:port instead'
                                    break
                                }
                                $bKey = Get-ServerKey $curB
                                Add-BannedServer $bKey 'hotkey B' | Out-Null
                                Log ("switching away from banned server " + $bKey + "...")
                                Invoke-Failover -Reason 'manual-ban' | Out-Null
                            }
                            'L' {
                                Start-BansEditor
                            }
                            'R' {
                                Log 'config cache rescan requested [R]'
                                Update-ConfigCache | Out-Null
                                Log 'config cache rescan complete'
                                # revive pass: prompt sessions whose latest visible event
                                # is a failure - picks up sessions missed while they were
                                # temporarily masked (idle marker) or prompted earlier
                                $rev = Get-FailedSessions -windowMinutes $Script:Cfg.AffectedWindowMin -kinds @('rate','endpoint','connreset','timeout')
                                if ($rev) {
                                    foreach ($s in $rev) {
                                        Resume-FailedSession -Session $s -Reason 'revive' | Out-Null
                                    }
                                } else {
                                    Log 'revive pass: no failed sessions found'
                                }
                            }
                            'U' {
                                if ($Script:Capture) {
                                    Stop-CaptureMode
                                } else {
                                    Start-CaptureMode | Out-Null
                                }
                            }
                            'C' {
                                Log 'used-server list cleared [C] - all non-banned cached servers are candidates again (bans unchanged)'
                                $Script:State | Add-Member -NotePropertyName used -NotePropertyValue (New-Object PSObject) -Force
                                Save-State
                            }
                            'Q' {
                                Log 'quit requested [Q] - releasing owned core and TUN (the network drops if we own the tunnel; the next launch auto-recovers)'
                                if ($Script:Capture) { Stop-CaptureMode -NoImport | Out-Null }
                                if ($Script:OwnedBurst) { try { $Script:OwnedBurst.Client.Dispose() } catch {} }
                                try { if ($Script:OwnedClient) { $Script:OwnedClient.Dispose() } } catch { }
                                try { $mutex.ReleaseMutex() } catch { }
                                try { $mutex.Dispose() } catch { }
                                exit 0
                            }
                        }
                        if ($Script:LayoutReady) { Render-Frame }
                    } else {
                        $drain = $false
                    }
                }
            }
            Start-Sleep -Milliseconds 100
        }
    }
}

Write-Host "nothing to do; use -TestInit / -TestSwitch / -TestSessions / -TestProbe / -Watch / -CaptureAll [-CaptureSeconds N] / -ListServers / -ListBanned / -BanServer host:port / -UnbanServer host:port / -ForkSession ses_id / -ListBurned / -UnburnSession ses_id"

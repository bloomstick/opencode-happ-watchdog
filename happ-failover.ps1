#Requires -Version 5.1
<#
.SYNOPSIS
  opencode-happ-watchdog: on OpenCode provider errors (rate limits, dead
  connections, endpoint failures, a dead tunnel), rotate Happ to a previously
  unused server (via the happd named-pipe protocol), restart OpenCode, and send
  "continue" prompts to the affected top-level sessions.

.DESCRIPTION
  Reverse-engineered and verified in live use:
   - happd named pipe \\.\pipe\happd-<session>: 4-byte BIG-ENDIAN length + compact JSON
   - actions: client-hello, get-privilege, list, stop, kill, start, stdin, close-stdin, heartbeat, start-tun
   - xray.exe is spawned by the daemon with no args; config is delivered via a 'stdin' action
   - the system-wide TUN comes from a start-tun action that spawns sing-box.exe -c %LOCALAPPDATA%\Happ\config.json
   - the GUI process (Happ.exe) keeps generated xray configs in memory -> templates & server params
   - HKCU\Software\Happ\OrganizationDefaults\Preferences holds lastServer* (current server)

  Usage:
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -TestInit
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -TestSwitch
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -TestSessions
    powershell -ExecutionPolicy Bypass -File happ-failover.ps1 -TestProbe
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
    [int]$PollSeconds = 5,
    [int]$CooldownSec = 120,
    [string]$ProjectDir = ''
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Script:Cfg = @{
    ToolDir           = $PSScriptRoot
    StatePath         = (Join-Path $PSScriptRoot 'state.json')
    LogPath           = (Join-Path $PSScriptRoot 'failover.log')
    ConfigCacheDir    = (Join-Path $PSScriptRoot 'configs')
    OpLogPath         = "$env:USERPROFILE\.local\share\opencode\log\opencode.log"
    # directory context for `opencode api` (sessions of the project to be healed);
    # defaults to the directory the script was launched from, can be set with -ProjectDir
    ProjectDir        = ''
    HappRegPath       = 'HKCU:\Software\Happ\OrganizationDefaults\Preferences'
    XrayExe           = 'C:\Program Files\FlyFrogLLC\Happ\core\xray.exe'
    XrayWorkDir       = 'C:\Program Files\FlyFrogLLC\Happ\core'
    ProcessId         = 'xray-core'
    ContinueText      = 'continue'
    RateLimitPattern  = '(Rate limit exceeded|Too many requests)'
    EndpointPattern   = 'Endpoint is unavailable'
    ContinueDelaySec  = 5     # wait after service (re)connect before continue prompts
    RestartOpenCode   = $true
    TopLevelOnly      = $true
    MaxSwitchAttempts = 6
    TunExe             = 'C:\Program Files\FlyFrogLLC\Happ\tun\sing-box.exe'
    TunConfigPath      = (Join-Path $env:LOCALAPPDATA 'Happ\config.json')
    TunIface           = 'happ-tun'
    TunAddress         = '172.18.0.1/30'
    TunAddressV6       = 'fd6e:a81b:704f:1211::2'
    TunDns             = '1.1.1.1'
    HeartbeatSec      = 15
    WebCheckUrl       = 'https://api.ipify.org/?format=json'
    AffectedWindowMin = 120
    ConnResetPattern   = 'ECONNRESET|Connection lost while reading the response'
    ConnResetWindowSec = 180    # count connection-loss failures within this window
    ConnResetMinCount  = 3      # threshold within the window -> full server failover
    ConnResetScanSec   = 20     # API-level scan cadence (ECONNRESET never reaches opencode.log)
    TunnelScanSec      = 30     # system-route health probe cadence
    ProbeUrl2          = 'https://checkip.amazonaws.com'
    ProbeTimeoutSec    = 8
}

foreach ($p in @($Script:Cfg.ToolDir, $Script:Cfg.ConfigCacheDir)) {
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
}

# console renderer state - declared before any Log call can run
$Script:LayoutReady = $false
$Script:EventRing = New-Object System.Collections.Generic.List[string]
$Script:RingCap = 400
$Script:LastWinW = -1
$Script:LastWinH = -1

# public: resolve the OpenCode project context (defaults to the launch directory)
if (-not $ProjectDir) { $ProjectDir = (Get-Location).Path }
$Script:Cfg.ProjectDir = $ProjectDir

function Log([string]$msg) {
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    if ($Script:LayoutReady) {
        try { Write-ConsoleEvent $line } catch { try { Write-Host $line } catch { } }
    } else {
        try { Write-Host $line } catch { }
    }
    try { $line | Out-File $Script:Cfg.LogPath -Append -Encoding utf8 } catch { }
}

# ------------------------------------------------------------------- state
function Load-State {
    if (Test-Path $Script:Cfg.StatePath) {
        try { $Script:State = Get-Content $Script:Cfg.StatePath -Raw | ConvertFrom-Json } catch { $Script:State = $null }
    }
    if ($null -eq $Script:State) {
        $Script:State = New-Object PSObject
        Add-Member -InputObject $Script:State -NotePropertyName used -NotePropertyValue (New-Object PSObject) -Force
        Add-Member -InputObject $Script:State -NotePropertyName prompted -NotePropertyValue (New-Object PSObject) -Force
        Save-State
    }
}
function Save-State {
    try { $Script:State | ConvertTo-Json -Depth 8 | Set-Content $Script:Cfg.StatePath -Encoding utf8 } catch { Log "state save failed: $_" }
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
    param([string]$configPath)
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
    Start-Sleep -Milliseconds 1200
    $resp = Read-FramesFrom $burst.Client $burst.Recv -MaxMs 2500
    foreach ($f in $resp) {
        if ($f.'request-id' -eq 'tun-start') { Log ("start-tun resp: status=" + $f.status + $(if ($f.message) { ' ' + $f.message } else { '' })) }
    }
    return $burst
}

function Get-PlainRouteIp {
    try {
        $raw = & curl.exe -s --max-time 10 $Script:Cfg.WebCheckUrl 2>$null
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
    $total = (Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json' -ErrorAction SilentlyContinue).Count
    foreach ($hit in $hits) {
        $text = [Text.Encoding]::UTF8.GetString($hit.Data)
        foreach ($o in (Get-JsonConfigFromText $text)) {
            foreach ($ob in $o.outbounds) {
                if ($ob.protocol -in @('vless','hysteria','vmess','trojan') -and $ob.settings -and $ob.settings.vnext -and $ob.settings.vnext[0]) {
                    $key = ('{0}_{1}' -f $ob.settings.vnext[0].address, $ob.settings.vnext[0].port)
                    $file = Join-Path $Script:Cfg.ConfigCacheDir ($key + '.json')
                    if (-not (Test-Path $file)) {
                        try {
                            $o | ConvertTo-Json -Depth 30 | Set-Content $file -Encoding utf8
                            $saved++; $total++
                            Log ("cached config: " + $key)
                        } catch { Log ("cache save failed " + $key + ": " + $_.Exception.Message) }
                    }
                }
            }
        }
    }
    Log ("config cache scan done: new=$saved total=$total")
    return $saved
}

function Get-ServerFromCacheKey([string]$key) {
    $li = $key.LastIndexOf('_')
    if ($li -lt 1) { return $null }
    return [pscustomobject]@{ host = $key.Substring(0, $li); port = [int]$key.Substring($li + 1) }
}

function Get-CachedOutbound {
    param([string]$srvHost, [int]$srvPort)
    $file = Join-Path $Script:Cfg.ConfigCacheDir ("{0}_{1}.json" -f $srvHost, $srvPort)
    if (-not (Test-Path $file)) { return $null }
    try {
        $tpl = Get-Content $file -Raw | ConvertFrom-Json
        foreach ($ob in $tpl.outbounds) {
            if ($ob.protocol -in @('vless','hysteria','vmess','trojan') -and $ob.settings -and $ob.settings.vnext) {
                $v = $ob.settings.vnext[0]
                if ($v.address -eq $srvHost -and $v.port -eq $srvPort) { return $ob }
            }
        }
    } catch { }
    return $null
}

function Get-CurrentTemplate {
    $cur = Get-HappCurrentServer
    if (-not $cur) { Log 'cannot read current Happ server from registry'; return $null }
    $file = Join-Path $Script:Cfg.ConfigCacheDir ("{0}_{1}.json" -f $cur.host, $cur.port)
    if (Test-Path $file) {
        try { return (Get-Content $file -Raw | ConvertFrom-Json) } catch { Log ("template parse failed: " + $_.Exception.Message) }
    }
    Log ("current server {0}_{1} not in cache; scanning GUI memory..." -f $cur.host, $cur.port)
    Update-ConfigCache | Out-Null
    if (Test-Path $file) {
        try { return (Get-Content $file -Raw | ConvertFrom-Json) } catch { }
    }
    Log "current server template unavailable"
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
    param([int]$tries = 4)
    for ($i = 1; $i -le $tries; $i++) {
        try {
            $raw = & curl.exe -s --max-time 10 --socks5-hostname 127.0.0.1:10808 $Script:Cfg.WebCheckUrl 2>$null
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
        Start-Sleep -Seconds 2
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
    param([string]$configJson)
    $rids = @('start-switch', 'stdin-switch', 'clostdin-switch')
    $msgs = @(
        @{ action = 'start'; 'process-id' = $Script:Cfg.ProcessId; 'executable' = $Script:Cfg.XrayExe; 'arguments' = @(); 'working-dir' = $Script:Cfg.XrayWorkDir; 'auto-restart' = $true; 'max-restart-attempts' = 3; 'restart-delay-ms' = 1000 },
        @{ action = 'stdin'; 'process-id' = $Script:Cfg.ProcessId; data = $configJson },
        @{ action = 'close-stdin'; 'process-id' = $Script:Cfg.ProcessId }
    )
    $burst = New-Burst -messages $msgs -rids $rids
    if (-not $burst) { return $null }
    Start-Sleep -Milliseconds 1200
    $resp = Read-FramesFrom $burst.Client $burst.Recv -MaxMs 2500
    foreach ($f in $resp) {
        if ($f.status -and $f.'request-id' -eq 'start-switch') { Log ("start resp: status=" + $f.status + " " + $f.message) }
        if ($f.'request-id' -eq 'stdin-switch') { Log ("stdin resp: status=" + $f.status) }
        if ($f.event -eq 'stderr' -and $f.data -match 'fail|error') { Log ("core stderr: " + ($f.data -replace '\r?\n', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min(200, $_.Length)) })) }
    }
    return $burst
}

function Invoke-PipeSwitch {
    param([pscustomobject]$Target)
    $template = Get-CurrentTemplate
    if (-not $template) { return $false }
    $newOut = Get-CachedOutbound -srvHost $Target.host -srvPort $Target.port
    if (-not $newOut) { Log ("no cached outbound for {0}:{1}" -f $Target.host, $Target.port); return $false }

    $newCfg = Build-Config -Template $template -NewOutbound $newOut
    $newJson = ConvertTo-Json -InputObject $newCfg -Compress -Depth 30
    $oldJson = ConvertTo-Json -InputObject $template -Compress -Depth 30

    Log ("switching to {0}:{1} via daemon pipe (burst mode)..." -f $Target.host, $Target.port)
    $exitIpBefore = Test-ProxyExit -tries 1
    if ($exitIpBefore) { Log ("current exit IP before switch: " + $exitIpBefore) }

    # 1. release any core we own, stop/kill the running core
    if ($Script:OwnedClient) { try { $Script:OwnedClient.Dispose() } catch {}; $Script:OwnedClient = $null }
    try { $null = (Send-Daemon -obj @{ action = 'stop'; 'process-id' = $Script:Cfg.ProcessId } -WaitMs 2000) } catch { }
    Start-Sleep -Milliseconds 700
    $alive = Get-Process xray -ErrorAction SilentlyContinue
    if ($alive) {
        Log ('GUI-owned core still running - OS-level kill')
        if (-not (Invoke-KillCore)) { Log 'could not kill the running core'; return $false }
    }
    # 2. start with the new config; keep the owner connection open
    $Script:OwnedBurst = Start-CoreBurst -configJson $newJson
    $Script:OwnedClient = if ($Script:OwnedBurst) { $Script:OwnedBurst.Client } else { $null }
    if (-not $Script:OwnedBurst) { Log 'burst start failed'; return $false }
    # 2b. restore the system-wide TUN (kills nothing: own burst, kept alive)
    if ($Script:OwnedTun) { try { $Script:OwnedTun.Client.Dispose() } catch {} }
    $Script:OwnedTun = Start-TunBurst -configPath $Script:Cfg.TunConfigPath
    Start-Sleep -Milliseconds 1500
    $tun = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'happ' }
    if ($tun) { Log ("TUN adapter up: {0} ({1})" -f $tun.Name, $tun.Status) } else { Log 'WARNING: TUN adapter did not come up' }
    # 3. verify (socks exit IP + the plain system-route IP)
    $exitIpAfter = Test-ProxyExit
    $plainIp = Get-PlainRouteIp
    if ($exitIpAfter) {
        Log ("SWITCH OK -> {0}:{1} (core exit IP: {2}{3}; system route: {4})" -f $Target.host, $Target.port, $exitIpAfter, $(if ($exitIpBefore -and $exitIpBefore -ne $exitIpAfter) { ", was: $exitIpBefore" } else { '' }), $plainIp)
        return $true
    }
    Log 'exit check failed on the new server - reverting to original config'
    if ($Script:OwnedBurst) { try { $Script:OwnedBurst.Client.Dispose() } catch {} }
    $Script:OwnedClient = $null; $Script:OwnedBurst = $null
    $null = Invoke-KillCore
    $Script:OwnedBurst = Start-CoreBurst -configJson $oldJson
    $Script:OwnedClient = if ($Script:OwnedBurst) { $Script:OwnedBurst.Client } else { $null }
    # TUN stays alive across the revert (it forwards into the fixed socks port)
    if ($Script:OwnedBurst -and (Test-ProxyExit)) { Log 'reverted to original server' } else { Log 'REVERT FAILED - reconnect Happ manually!' }
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
    param([int]$windowMinutes = 120, [string[]]$kinds = @('rate','endpoint','connreset'))
    $root = Invoke-OC '/api/session'
    if ($null -eq $root -or -not $root.data) { Log 'cannot list opencode sessions'; return @() }
    $cutoff = (Get-Date).AddMinutes(-1 * $windowMinutes)
    $result = @()
    foreach ($s in $root.data) {
        if ($Script:Cfg.TopLevelOnly -and $s.parentID) { continue }
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
        $errKind = $null; $errMsg = $null; $errCreated = $null
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
                if ($m.error -and $m.error.message) {
                    if ($m.error.message -match $Script:Cfg.RateLimitPattern) { $kind = 'rate' }
                    elseif ($m.error.message -match $Script:Cfg.EndpointPattern) { $kind = 'endpoint' }
                    elseif ($m.error.message -match $Script:Cfg.ConnResetPattern) { $kind = 'connreset' }
                }
                if ($kind -and ($kinds -contains $kind) -and (-not $errKind)) {
                    $errKind = $kind
                    $errMsg = $m.error.message.Substring(0, [Math]::Min(140, $m.error.message.Length))
                    try { $errCreated = [int64]$m.time.created } catch { $errCreated = $null }
                }
            }
        }
        if (-not $errKind) { continue }
        # prompted-set dedup applies to the switch path (rate class): skip only when
        # this failure predates our last prompt for the session (fresh failures pass).
        # endpoint/connreset retries are allowed to hit the same session repeatedly
        if ($kinds -contains 'rate') {
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
            msg = $errMsg
        }
    }
    return $result
}

function Restart-Opencode {
    Push-Location $Script:Cfg.ProjectDir
    try {
        Log 'restarting opencode service...'
        & opencode service restart 2>$null | Out-Null
        for ($i = 0; $i -lt 120; $i++) {
            Start-Sleep -Seconds 1
            $info = Invoke-OC '/api/info'
            # /api/info returns the ServerInfo object directly (no data wrapper)
            if ($info -and ($info.data -or $info.version)) {
                Log ("opencode service healthy after " + ($i + 1) + "s (pid " + $(if ($info.data) { $info.data.pid } else { $info.pid }) + ")")
                return $true
            }
            if ($i -gt 0 -and ($i % 15) -eq 0) {
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

# ------------------------------------------------------------------- failover
function Mark-Used([pscustomobject]$srv) {
    if (-not $srv -or -not $srv.host) { return }
    $key = ('{0}:{1}' -f $srv.host, $srv.port)
    Add-Member -InputObject $Script:State.used -NotePropertyName $key -NotePropertyValue (Get-Date -Format 'o') -Force
    Save-State
}

function Invoke-Failover {
    param([string]$Reason = 'auto')
    Load-State
    $global:LastFailover = Get-Date
    $cur = Get-HappCurrentServer
    if ($cur) {
        Invoke-FailoverReason-Log $Reason $cur
        Mark-Used $cur
    } else {
        Log ('cannot read current Happ server - proceeding with failover (' + $Reason + ')')
    }
    $affected = Get-FailedSessions -windowMinutes $Script:Cfg.AffectedWindowMin -kinds @('rate','endpoint','connreset')
    Log ("affected sessions: " + (($affected | ForEach-Object { $_.id }) -join ', '))

    $switched = $false
    $rotated = $false
    for ($attempt = 1; $attempt -le $Script:Cfg.MaxSwitchAttempts -and -not $switched; $attempt++) {
        Update-ConfigCache | Out-Null
        $curKey = $null
        if ($cur) { $curKey = ('{0}:{1}' -f $cur.host, $cur.port) }
        $candidates = @()
        foreach ($f in (Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json' -ErrorAction SilentlyContinue)) {
            $srv = Get-ServerFromCacheKey $f.BaseName
            if (-not $srv) { continue }
            $stateKey = ('{0}:{1}' -f $srv.host, $srv.port)
            if ($Script:State.used.PSObject.Properties[$stateKey]) { continue }
            if ($curKey -eq $stateKey) { continue }
            $candidates += $srv
        }
        if (-not $candidates) {
            $cacheCount = (Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json' -ErrorAction SilentlyContinue).Count
            $usedCount = ($Script:State.used.PSObject.Properties | Measure-Object).Count
            if ($cacheCount -gt 0 -and $usedCount -ge $cacheCount -and -not $rotated) {
                # every cached server was tried - start a new rotation cycle,
                # keeping only the currently active server marked; remember LRU order
                $Script:LruOrder = @($Script:State.used.PSObject.Properties | Sort-Object { $_.Value } | ForEach-Object { $_.Name })
                Log ("all {0} cached servers already used - starting rotation cycle 2 (least-recently-used first)" -f $cacheCount)
                $curKey2 = $null
                if ($cur) { $curKey2 = ('{0}:{1}' -f $cur.host, $cur.port) }
                foreach ($prop in @($Script:State.used.PSObject.Properties)) {
                    if ($curKey2 -and $prop.Name -eq $curKey2) { continue }
                    $Script:State.used.PSObject.Properties.Remove($prop.Name) | Out-Null
                }
                $rotated = $true
                Save-State
                Add-RingEvent ("rotation reset: all {0} cached servers used - cycling again LRU-first" -f $cacheCount)
                continue
            }
            if ($cacheCount -eq 0) { Log 'no cached server configs yet - rescanning happens on the next failover attempt' }
            break
        }
        if ($rotated -and $Script:LruOrder) {
            $candidates = @($candidates | Sort-Object {
                $k = ('{0}:{1}' -f $_.host, $_.port)
                $idx = [array]::IndexOf($Script:LruOrder, $k)
                if ($idx -lt 0) { $idx = [int]::MaxValue }
                $idx
            })
        }

        foreach ($cand in $candidates) {
            if (Invoke-PipeSwitch -Target $cand) {
                Mark-Used $cand
                $switched = $true
                break
            } else {
                Mark-Used $cand
            }
        }
    }
    if (-not $switched) { Log 'FAILED to switch to any previously unused server'; return }

    if ($Script:Cfg.RestartOpenCode) { Restart-Opencode | Out-Null }

    if ($Script:Cfg.ContinueDelaySec -gt 0) {
        Log ("waiting {0}s for the provider to settle before continue prompts..." -f $Script:Cfg.ContinueDelaySec)
        Start-Sleep -Seconds $Script:Cfg.ContinueDelaySec
    }

    $postReload = Get-FailedSessions -windowMinutes $Script:Cfg.AffectedWindowMin -kinds @('rate','endpoint','connreset')
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
        if (Send-ContinueToSession -sessionID $s.id) {
            Add-Member -InputObject $Script:State.prompted -NotePropertyName $s.id -NotePropertyValue (Get-Date -Format 'o') -Force
            Save-State
        }
    }
    Log 'failover complete'
}

# ------------------------------------------------------------------- log tail
function Test-OpLogTail {
    if (-not (Test-Path $Script:Cfg.OpLogPath)) { return $null }
    $lines = Get-Content $Script:Cfg.OpLogPath -Tail 300 -ErrorAction SilentlyContinue
    $windowStart = $global:LastFailover.AddSeconds(15)
    $rateNewest = $null
    $endNewest = $null
    foreach ($l in $lines) {
        $ts = $null
        if ($l -match '^timestamp=([0-9T:\.\-]+)Z') {
            try { $ts = [DateTime]::Parse($Matches[1]).ToLocalTime() } catch { }
        }
        if (-not $ts) { continue }
        if ($l -match $Script:Cfg.RateLimitPattern) {
            if ($ts -gt $rateNewest) { $rateNewest = $ts }
        } elseif ($l -match $Script:Cfg.EndpointPattern) {
            if ($ts -gt $endNewest) { $endNewest = $ts }
        }
    }
    return @{ rate = $rateNewest; endpoint = $endNewest }
}

# ------- connection-loss burst detection (API-based) ------------------------
# ECONNRESET never reaches opencode.log; the only persisted record is the
# session message error. Counts distinct connection-loss failures across
# top-level sessions created inside the recent window; failures older than
# state.connResetUntil were already processed.
function Test-ConnResetBurst {
    $root = Invoke-OC '/api/session'
    if ($null -eq $root -or -not $root.data) { return 0 }
    $nowMs = [DateTimeOffset]::Now.ToUnixTimeMilliseconds()
    $winMs = $Script:Cfg.ConnResetWindowSec * 1000
    $floorMs = $nowMs - $winMs
    $processedMs = 0
    try { $processedMs = [int64][string]$Script:State.connResetUntil } catch { $processedMs = 0 }
    $count = 0
    foreach ($s in $root.data) {
        if ($Script:Cfg.TopLevelOnly -and $s.parentID) { continue }
        $updMs = 0
        try { $updMs = [int64]$s.time.updated } catch { $updMs = 0 }
        if ($updMs -lt ($floorMs - 60000)) { continue }   # untouched since before the window
        if ($processedMs -gt 0 -and $updMs -le $processedMs) { continue }
        $msgsResp = Invoke-OC ("/api/session/{0}/message?order=desc&limit=8" -f $s.id)
        if (-not $msgsResp -or -not $msgsResp.data) { continue }
        foreach ($m in $msgsResp.data) {
            $cMs = 0
            try { $cMs = [int64]$m.time.created } catch { $cMs = 0 }
            if ($cMs -lt $floorMs) { continue }
            if ($processedMs -gt 0 -and $cMs -le $processedMs) { continue }
            if ($m.error -and $m.error.message -and ($m.error.message -match $Script:Cfg.ConnResetPattern)) { $count++ }
        }
    }
    return $count
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
    switch ($reason) {
        'auto' { Log ("rate limit detected; current server {0} ({1}:{2})" -f $cur.name, $cur.host, $cur.port) }
        'manual' { Log ("manual switch requested; current server {0} ({1}:{2}) marked used" -f $cur.name, $cur.host, $cur.port) }
        'connreset-burst' { Log ("connection-loss burst (ECONNRESET); current server {0} ({1}:{2}) marked used" -f $cur.name, $cur.host, $cur.port) }
        'tunnel-dead' { Log ("network unreachable through the tunnel; current server {0} ({1}:{2}) marked used" -f $cur.name, $cur.host, $cur.port) }
        default { Log ("persistent upstream endpoint errors; switching server (current: {0}:{1})" -f $cur.host, $cur.port) }
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
            if (Send-ContinueToSession -sessionID $s.id) {
                # soft path allows repeats, so do not mark the prompted set
                Log ("continue sent to stuck session {0}" -f $s.id)
            }
        }
    } else {
        Log 'no sessions currently stuck on endpoint errors'
    }
    if ($Script:Soft.rounds -ge 2) {
        Log ("endpoint errors persist after {0} same-server continue tries - switching server" -f $Script:Soft.rounds)
        $Script:Soft = New-SoftState
        Invoke-Failover -Reason 'endpoint-persist'
    } else {
        $Script:Soft.nextAt = $now.AddSeconds(60)
        Log 'next same-server continue retry scheduled in ~60s'
    }
}

# ------------------------------------------------------------------- test modes
if ($TestInit) {
    Load-State
    Log ("state: used=[$((($Script:State.used.PSObject.Properties | ForEach-Object { $_.Name })) -join ', ')]")
    $cur = Get-HappCurrentServer
    Log ("current: " + ($cur | ConvertTo-Json -Compress -Depth 3))
    $p = Get-DaemonProcess
    Log ("core: " + ($p | ConvertTo-Json -Compress -Depth 4))
    Update-ConfigCache | Out-Null
    return
}
if ($TestSwitch) {
    Load-State
    Update-ConfigCache | Out-Null
    $cur = Get-HappCurrentServer
    Mark-Used $cur
    $cand = $null
    foreach ($f in (Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json')) {
        $srv = Get-ServerFromCacheKey $f.BaseName
        if ($cur -and $srv.host -eq $cur.host -and $srv.port -eq $cur.port) { continue }
        $stateKey = ('{0}:{1}' -f $srv.host, $srv.port)
        if ($Script:State.used.PSObject.Properties[$stateKey]) { continue }
        $cand = $srv; break
    }
    if (-not $cand) { Log 'no unused cached candidate for test switch'; return }
    Log ("test switch to: " + ($cand | ConvertTo-Json -Compress))
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
    if (-not $r) { Log 'no rate-limited sessions found' }
    else { $r | ForEach-Object { Log ("[rl] {0} (updated {1}) : {2}" -f $_.id, $_.when, $_.msg) } }
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

function Init-ConsoleLayout {
    if (-not $Interactive) { return }
    try {
        if ([Console]::WindowHeight -lt 14 -or [Console]::WindowWidth -lt 40) { return }
        $Script:LayoutReady = $true
        $Script:LastWinW = [Console]::WindowWidth
        $Script:LastWinH = [Console]::WindowHeight
        try { [Console]::SetBufferSize($Script:LastWinW, $Script:LastWinH) } catch { }
    } catch { }
}

function Get-HeaderLines {
    $cur = Get-HappCurrentServer
    $cacheCount = (Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json' -ErrorAction SilentlyContinue).Count
    $usedCount = 0
    try { $usedCount = ($Script:State.used.PSObject.Properties | Measure-Object).Count } catch { }
    $nextCandidate = ''
    foreach ($f in (Get-ChildItem $Script:Cfg.ConfigCacheDir -Filter '*.json' -ErrorAction SilentlyContinue)) {
        $k = $f.BaseName
        if ($k -and $Script:State -and $Script:State.used -and $Script:State.used.PSObject.Properties[$k]) { continue }
        if ($cur -and $k -eq ('{0}:{1}' -f $cur.host, $cur.port)) { continue }
        $nextCandidate = $k; break
    }
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
    return @(
        ('OpenCode Happ Watchdog       {0}                                elevated={1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $elevated),
        ('=============================================================='),
        ('Happ GUI : {0}    xray core: {1}    owned connection: {2}' -f ($(if ($guiProc) { 'running' } else { 'NOT RUNNING' })), ($(if ($xrayProc) { 'running pid ' + $xrayProc.Id } else { 'not running' })), $owned),
        ('Server   : {0} ({1})' -f $cur.host, $cur.name),
        ('Tunnel   : {0}' -f $tunnel),
        ('Exit IP  : {0}    (checked {1})' -f $exitIp, $exitWhen),
        ('Next     : {0}    cache: {1}    used: {2}    last failover: {3}' -f $(if ($nextCandidate) { $nextCandidate } else { '(none)' }), $cacheCount, $usedCount, $global:LastFailover),
        ('[T] switch now    [R] rescan+revive    [C] clear used    [Q] quit'),
        ('----------------------------------------------------------------')
    )
}

function Render-Frame {
    if (-not $Script:LayoutReady) { return }
    try {
        $w = [Console]::WindowWidth
        $h = [Console]::WindowHeight
        if ($w -ne $Script:LastWinW -or $h -ne $Script:LastWinH) {
            # window resized: re-sync the buffer so the view can never scroll away
            try { [Console]::SetBufferSize($w, $h) } catch { }
            $Script:LastWinW = $w
            $Script:LastWinH = $h
        }
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
    Render-Frame
}

if ($Watch) {
    Load-State
    $global:LastFailover = Get-Date
    Log 'watchdog starting; tracking current server as used'
    $cur = Get-HappCurrentServer
    if ($cur) { Mark-Used $cur }
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
    if ($Interactive -and $Script:LayoutReady) { Render-Frame }
    try { $host.UI.RawUI.WindowTitle = 'OpenCode Happ Watchdog' } catch { }
    while ($true) {
        try {
            $fails = Test-OpLogTail
            $now = Get-Date
            # rate limits take priority: full server failover
            if ($fails.rate -and $fails.rate -gt $global:LastFailover.AddSeconds(15)) {
                if ($now -gt $global:LastFailover.AddSeconds($CooldownSec)) {
                    Log 'rate limit detected in opencode log - failover starting'
                    Invoke-Failover
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
            # connection-loss bursts (ECONNRESET never reach opencode.log - scan the
            # session API on its own slower cadence)
            if ($null -eq $Script:ConnResetLast -or ((Get-Date) - $Script:ConnResetLast).TotalSeconds -ge $Script:Cfg.ConnResetScanSec) {
                $Script:ConnResetLast = Get-Date
                $crCount = Test-ConnResetBurst
                if ($crCount -ge $Script:Cfg.ConnResetMinCount) {
                    if ((Get-Date) -gt $global:LastFailover.AddSeconds($CooldownSec)) {
                        Log ("{0} connection-loss failures within {1}s - switching server" -f $crCount, $Script:Cfg.ConnResetWindowSec)
                        Add-Member -InputObject $Script:State -NotePropertyName connResetUntil -NotePropertyValue ([string][DateTimeOffset]::Now.ToUnixTimeMilliseconds()) -Force
                        Save-State
                        Invoke-Failover -Reason 'connreset-burst'
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
                    if ((Get-Date) -gt $global:LastFailover.AddSeconds($CooldownSec)) {
                        Log ('network unreachable through the tunnel for ~' + ($Script:Cfg.TunnelScanSec * 2) + 's - switching server')
                        $Script:DeadStreak = 0
                        Invoke-Failover -Reason 'tunnel-dead'
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
            if ($Script:LayoutReady) { Render-Frame }
        }
        # keep a tight console input loop: keys are handled within ~250ms,
        # while the slower poll logic above still runs on its own cadence
        for ($t = 0; $t -lt ([Math]::Max(1, [int]($PollSeconds * 4))); $t++) {
            if ($Interactive) {
                $drain = $true
                while ($drain) {
                    $hit = $false
                    try { $hit = [Console]::KeyAvailable } catch { }
                    if ($hit) {
                        $key = [Console]::ReadKey($true)
                        switch ($key.Key) {
                            'T' { Log 'manual switch requested [T]'; Invoke-Failover -Reason 'manual' | Out-Null }
                            'R' {
                                Log 'config cache rescan requested [R]'
                                Update-ConfigCache | Out-Null
                                Log 'config cache rescan complete'
                                # revive pass: prompt sessions whose latest visible event
                                # is a failure - picks up sessions missed while they were
                                # temporarily masked (idle marker) or prompted earlier
                                $rev = Get-FailedSessions -windowMinutes $Script:Cfg.AffectedWindowMin -kinds @('rate','endpoint','connreset')
                                if ($rev) {
                                    foreach ($s in $rev) {
                                        if (Send-ContinueToSession -sessionID $s.id) {
                                            Add-Member -InputObject $Script:State.prompted -NotePropertyName $s.id -NotePropertyValue (Get-Date -Format 'o') -Force
                                            Save-State
                                        }
                                    }
                                } else {
                                    Log 'revive pass: no failed sessions found'
                                }
                            }
                            'C' {
                                Log 'used-server list cleared [C] - all cached servers are candidates again'
                                $Script:State | Add-Member -NotePropertyName used -NotePropertyValue (New-Object PSObject) -Force
                                Save-State
                            }
                            'Q' {
                                Log 'quit requested [Q] - releasing owned core and TUN (the network drops if we own the tunnel; the next launch auto-recovers)'
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
            Start-Sleep -Milliseconds 250
        }
    }
}

Write-Host "nothing to do; use -TestInit / -TestSwitch / -TestSessions / -TestProbe / -Watch"

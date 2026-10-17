# Launcher for the OpenCode Happ Watchdog.
# Double-clickable via the desktop shortcut; self-elevates once (UAC) because
# switching servers requires OS-level control of the daemon-owned xray core.
$ErrorActionPreference = 'Continue'

$pri = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$tool = Join-Path $PSScriptRoot 'happ-failover.ps1'
if (-not (Test-Path $tool)) {
    Write-Host ("cannot find " + $tool)
    Read-Host 'press ENTER to exit'
    exit 1
}

if (-not $elevated) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath), '-Direct'
    )
    exit 0
}

try { $host.UI.RawUI.WindowTitle = 'OpenCode Happ Watchdog (elevated)' } catch { }

Write-Host 'starting watchdog in interactive mode...'
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tool -Watch -Interactive
    if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) {
        # clean exit (e.g. user pressed Q) - close the console immediately
        exit 0
    }
    Write-Host ("watchdog exited with code " + $LASTEXITCODE)
    Read-Host 'press ENTER to close'
} catch {
    Write-Host ("watch error: " + $_.Exception.Message)
    Read-Host 'watchdog crashed - press ENTER to close'
}

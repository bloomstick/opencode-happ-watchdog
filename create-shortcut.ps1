# Creates a desktop shortcut for the OpenCode Happ Watchdog.
$ErrorActionPreference = 'Stop'
$desktop = [Environment]::GetFolderPath('Desktop')
$lnkPath = Join-Path $desktop 'OpenCode Happ Watchdog.lnk'

$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut($lnkPath)
$lnk.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$lnk.Arguments = ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $PSScriptRoot 'start-happ-failover.ps1'))
$lnk.WorkingDirectory = $PSScriptRoot
$lnk.WindowStyle = 1
$lnk.Description = 'OpenCode Happ Watchdog: rotates the Happ server on OpenCode provider errors, restores the tunnel, restarts OpenCode, continues affected sessions'
$lnk.IconLocation = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe,0"
$lnk.Save()
Write-Host ("shortcut created: " + $lnkPath)

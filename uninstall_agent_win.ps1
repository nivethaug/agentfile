<#
.SYNOPSIS
  Uninstall script for AlgoAgent installed by setup_win_clean.ps1
.DESCRIPTION
  Stops and removes the Windows service (created with NSSM or sc), deletes virtualenv, agent files, logs, and optional NSSM installation directory.
.PARAMETER Force
  If specified, skip confirmation prompts.
.EXAMPLE
  .\uninstall_algoagent.ps1 -Force
#>

param(
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Config (mirrors installer defaults) ----
$ServiceName = 'AlgoAgentService'
$HomeDir    = $env:USERPROFILE
$VenvBaseDir= Join-Path $HomeDir 'venvalgobn'
$ExtractDir = Join-Path $HomeDir 'agent'
$LogDir     = 'C:\agents\logs'
$NssmDir    = 'C:\nssm'

function Log {
  param([string]$msg)
  Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  -  $msg"
}

function Ensure-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
  if (-not $isAdmin) {
    Write-Warning "This script needs to run as Administrator. Attempting to re-launch with elevation..."
    Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $(if ($Force) { '-Force' })" -Verb RunAs
    Exit 0
  }
}

Ensure-Admin

# Show plan
Log "Planned actions:"
Log " - Stop and remove service: $ServiceName"
Log " - Delete virtualenv directory: $VenvBaseDir"
Log " - Delete agent files directory: $ExtractDir"
Log " - Delete logs directory: $LogDir"
Log " - (Optional) Delete NSSM dir: $NssmDir"

if (-not $Force) {
  $ok = Read-Host "Proceed with uninstall? Type 'yes' to continue"
  if ($ok -ne 'yes') {
    Log "Aborted by user."
    Exit 1
  }
}

# 1) Stop service if exists
try {
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($svc) {
    if ($svc.Status -ne 'Stopped') {
      Log "Stopping service $ServiceName..."
      Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 2
    }
    # Try removing with sc.exe
    Log "Removing service $ServiceName via sc.exe..."
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
    # If NSSM is present, use it to remove the service cleanly
    $nssmPath = $null
    if (Test-Path $NssmDir) {
      $found = Get-ChildItem -Path $NssmDir -Recurse -Filter 'nssm.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($found) { $nssmPath = $found.FullName }
    } else {
      # Try to locate nssm in PATH
      $which = Get-Command nssm.exe -ErrorAction SilentlyContinue
      if ($which) { $nssmPath = $which.Path }
    }
    if ($nssmPath) {
      try {
        Log "Removing service via NSSM ($nssmPath) as well (if present)..."
        & $nssmPath remove $ServiceName confirm
      } catch {
        Log "NSSM remove reported: $($_.Exception.Message)"
      }
    }
    Log "Service removal attempted. It may take a moment for the service to fully disappear."
  } else {
    Log "Service $ServiceName not found — skipping service stop/remove."
  }
} catch {
  Log "Error while stopping/removing service: $($_.Exception.Message)"
}

# 2) Remove scheduled task (if any)
try {
  $taskName = $ServiceName
  $ts = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  if ($ts) {
    Log "Removing scheduled task $taskName..."
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  }
} catch {
  Log "No scheduled task removed or error: $($_.Exception.Message)"
}

# 3) Remove Windows firewall rule (if installer added any) - best-effort (no-op if none)
try {
  $fwName = "AlgoAgent-$ServiceName"
  $fw = Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue
  if ($fw) {
    Log "Removing firewall rule $fwName..."
    Remove-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue
  }
} catch { }

# 4) Delete directories (virtualenv, agent code, logs)
function SafeRemoveDir([string]$path) {
  if (-not $path) { return }
  if (Test-Path $path) {
    try {
      Log "Deleting: $path"
      # Use -Recurse and -Force; retry on access errors
      Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
      Log "Deleted: $path"
    } catch {
      Log "Failed to delete $path: $($_.Exception.Message)"
    }
  } else {
    Log "Path not found: $path"
  }
}

SafeRemoveDir $VenvBaseDir
SafeRemoveDir $ExtractDir
SafeRemoveDir $LogDir

# 5) Optionally remove NSSM installation directory
if (Test-Path $NssmDir) {
  if ($Force) {
    SafeRemoveDir $NssmDir
  } else {
    $choice = Read-Host "Delete NSSM directory at $NssmDir? (yes/no)"
    if ($choice -eq 'yes') { SafeRemoveDir $NssmDir }
  }
}

# 6) Remove leftover files in C:\agents (if empty, remove parent)
try {
  $parent = Split-Path -Parent $LogDir
  if (Test-Path $parent) {
    $children = Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue
    if (-not $children) {
      Log "Removing empty parent directory: $parent"
      Remove-Item -LiteralPath $parent -Force -ErrorAction SilentlyContinue
    }
  }
} catch { }

Log "Uninstall completed. If the service still appears in the Services MMC, please restart the machine or run 'sc queryex' to inspect."

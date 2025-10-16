## ================================================================
# AlgoAgent Windows Installer (Final Header Fixed)
# ================================================================

param(
  [string]$AgentId = $env:AGENT_ID,
  [string]$AgentUrl = 'https://github.com/nivethaug/agentfile/releases/download/v1.0.9/agent_windows.py'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------
# Paths and constants
# -----------------------------
$HomeDir     = $env:USERPROFILE
$ExtractDir  = Join-Path $HomeDir 'agent'
$VenvBaseDir = Join-Path $HomeDir 'venvalgobn'
$AgentPath   = Join-Path $ExtractDir 'agent_windows.py'
$Requirements= Join-Path $VenvBaseDir 'requirements.txt'
$ServiceName = 'AlgoAgentService'
$NssmDir     = 'C:\nssm'
$NssmExe     = Join-Path $NssmDir 'nssm.exe'

# -----------------------------
# Log file setup (robust)
# -----------------------------
$Global:LogFile = Join-Path $HomeDir 'agent_setup.log'

function Log([string]$msg) {
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  Write-Host "[$ts] $msg"
  if (Test-Path $Global:LogFile) {
    try {
      "[$ts] $msg" | Out-File -FilePath $Global:LogFile -Append -Encoding utf8 -ErrorAction Stop
    } catch {
      Write-Host "[$ts] Warning: could not write to $Global:LogFile" -ForegroundColor Yellow
    }
  } else {
    try {
      "[$ts] $msg" | Out-File -FilePath $Global:LogFile -Encoding utf8 -ErrorAction Stop
    } catch {
      Write-Host "[$ts] Warning: could not create $Global:LogFile" -ForegroundColor Yellow
    }
  }
}




if (-not $AgentId) {
  Write-Host 'ERROR: No AGENT_ID supplied.' -ForegroundColor Red
  Write-Host "Use: `$env:AGENT_ID='agent-xxxx'; .\setup_win_clean.ps1"
  exit 1
}
Log "Using AGENT_ID=$AgentId"

# Find python
function Get-PythonPath {
  try { (Get-Command python -ErrorAction Stop).Path } catch { $null }
}

$Python = Get-PythonPath
if (-not $Python) {
  Log 'Python not found. Attempting to install via winget...'
  try {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      & winget install -e --id Python.Python.3 -h | Out-Null 2>$null
      Start-Sleep -Seconds 10
      $Python = Get-PythonPath
    } else {
      throw 'winget-not-available'
    }
  } catch {
    Log 'Winget not available or install failed. Please install Python 3.10+ manually and re-run.'
    throw
  }
}
Log "Using Python at: $Python"

# Prepare dirs
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null
New-Item -ItemType Directory -Force -Path $VenvBaseDir | Out-Null

# Create venv if missing
if (-not (Test-Path (Join-Path $VenvBaseDir 'Scripts\python.exe'))) {
  Log "Creating virtual environment at $VenvBaseDir"
  & $Python -m venv $VenvBaseDir
} else {
  Log 'Virtual environment already exists.'
}

$Pip   = Join-Path $VenvBaseDir 'Scripts\pip.exe'
$VenvPy= Join-Path $VenvBaseDir 'Scripts\python.exe'

# Dependencies (safe list)
$req = @(
  'python-socketio[client]'
  'aiofiles'
  'psutil'
  'python-dotenv'
  'aiohttp'
  'pipreqs'
  'apscheduler'
  'sqlalchemy'
)
$req -join "`r`n" | Set-Content -Path $Requirements -Encoding utf8

Log 'Installing Python dependencies...'
& $Pip install --upgrade pip
& $Pip install -r $Requirements

# Download agent
Log "Downloading latest agent from: $AgentUrl"
try {
  Invoke-WebRequest -Uri $AgentUrl -OutFile $AgentPath -UseBasicParsing -ErrorAction Stop
  Log "Agent downloaded to $AgentPath"
} catch {
  Log ("Failed to download agent: " + $_.Exception.Message)
  throw
}

# NSSM and service
$LogDir  = 'C:\agents\logs'
$StdOut  = Join-Path $LogDir 'service_stdout.log'
$StdErr  = Join-Path $LogDir 'service_stderr.log'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

if (-not (Test-Path $NssmExe)) {
  Log 'NSSM not found — installing...'
  New-Item -ItemType Directory -Force -Path $NssmDir | Out-Null
  $zipUrl = 'https://nssm.cc/release/nssm-2.24.zip'
  $zipFile = Join-Path $NssmDir 'nssm.zip'
  try {
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $NssmDir)
    Remove-Item $zipFile -Force
    $found = Get-ChildItem -Path $NssmDir -Recurse -Filter 'nssm.exe' | Where-Object { $_.FullName -match 'win64' } | Select-Object -First 1
    if ($found) {
      $NssmExe = $found.FullName
    } else {
      $found2 = Get-ChildItem -Path $NssmDir -Recurse -Filter 'nssm.exe' | Select-Object -First 1
      if ($found2) { $NssmExe = $found2.FullName } else { throw 'NSSM exe not found after extraction.' }
    }
    Log ("NSSM installed at " + $NssmExe)
  } catch {
    Log ("Failed to install NSSM: " + $_.Exception.Message)
    throw
  }
} else {
  Log ("NSSM found at " + $NssmExe)
}

# Remove existing service if present
try {
  & $NssmExe stop $ServiceName 2>$null
  & $NssmExe remove $ServiceName confirm
  Start-Sleep -Seconds 1
} catch {}

# Install service
Log ("Installing NSSM Windows service " + $ServiceName)
& $NssmExe install $ServiceName $VenvPy $AgentPath
& $NssmExe set $ServiceName AppDirectory $ExtractDir
& $NssmExe set $ServiceName AppStdout $StdOut
& $NssmExe set $ServiceName AppStderr $StdErr
& $NssmExe set $ServiceName AppRotateFiles 1
& $NssmExe set $ServiceName Start SERVICE_AUTO_START

sc.exe failure $ServiceName reset= 0 actions= restart/10000/restart/10000/restart/10000 | Out-Null

# Start service
& $NssmExe start $ServiceName
Log ("Service " + $ServiceName + " started successfully.")

# Finish - safe output
Write-Host ''
Write-Host '=============================================' -ForegroundColor Green
Write-Host '✅ Setup Complete: AlgoAgent Installed' -ForegroundColor Green
Write-Host ('Service Name : ' + $ServiceName) -ForegroundColor Cyan
Write-Host ('Executable   : ' + $VenvPy) -ForegroundColor Cyan
Write-Host ('Agent File   : ' + $AgentPath) -ForegroundColor Cyan
Write-Host ('Logs         : ' + $StdOut + ' , ' + $StdErr) -ForegroundColor Cyan
Write-Host '=============================================' -ForegroundColor Green
Write-Host ''
Write-Host 'View live logs with (copy/paste):' -ForegroundColor Yellow
# print command pieces separately
Write-Host 'Get-Content' -NoNewline -ForegroundColor White
Write-Host ' ' -NoNewline -ForegroundColor White
Write-Host $StdOut -NoNewline -ForegroundColor White
Write-Host ' -Tail 30 -Wait' -ForegroundColor White

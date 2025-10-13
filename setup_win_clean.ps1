#requires -version 5.1
param(
  [string]$AgentId = $env:AGENT_ID,
  [string]$AgentUrl = "https://github.com/nivethaug/agentfile/releases/download/v1.9.0/agent_windows.py"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Log([string]$msg) {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[$ts] $msg"
  if ($Global:LogFile) {
    "[$ts] $msg" | Out-File -FilePath $Global:LogFile -Append -Encoding utf8
  }
}

# --------------------
# Paths / Constants
# --------------------
$HomeDir     = $env:USERPROFILE
$ExtractDir  = Join-Path $HomeDir "agent"
$VenvBaseDir = Join-Path $HomeDir "venvalgobn"
$AgentPath   = Join-Path $ExtractDir "agent_windows.py"
$Requirements= Join-Path $VenvBaseDir "requirements.txt"
$LogFile     = Join-Path $HomeDir "agent_setup.log"
$TaskName    = "agent-client"

# --------------------
# Validate input
# --------------------
if ([string]::IsNullOrWhiteSpace($AgentId)) {
  Write-Host "ERROR: No AGENT_ID supplied. Use: `$env:AGENT_ID=agent-xxxx; .\setup_win_clean.ps1  OR pass -AgentId" -ForegroundColor Red
  exit 1
}
Log "Using AGENT_ID=$AgentId"

# --------------------
# Ensure Python
# --------------------
function Get-PythonPath {
  try {
    (Get-Command python -ErrorAction Stop).Path
  } catch {
    try {
      $py = Get-Command py -ErrorAction Stop
      $ver = & $py -3 -c "import sys; print(sys.executable)" 2>$null
      if ($LASTEXITCODE -eq 0 -and $ver) { return $ver.Trim() }
      $null
    } catch {
      $null
    }
  }
}

$Python = Get-PythonPath
if (-not $Python) {
  Log "Python not found. Attempting install via winget..."
  try {
    $winget = (Get-Command winget -ErrorAction Stop).Path
    & $winget install -e --id Python.Python.3 -h | Out-Null 2>$null
    Start-Sleep -Seconds 6
    $Python = Get-PythonPath
  } catch {
    Log "winget not available or install failed. Please install Python 3.10+ and rerun."
    throw
  }
}
Log "Using Python at: $Python"

# --------------------
# Create working dirs
# --------------------
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null
New-Item -ItemType Directory -Force -Path $VenvBaseDir | Out-Null

# --------------------
# Create venv
# --------------------
if (-not (Test-Path (Join-Path $VenvBaseDir "Scripts\python.exe"))) {
  Log "Creating virtual environment at $VenvBaseDir"
  & $Python -m venv $VenvBaseDir
} else {
  Log "Virtual environment already exists"
}

$Pip   = Join-Path $VenvBaseDir "Scripts\pip.exe"
$VenvPy= Join-Path $VenvBaseDir "Scripts\python.exe"

# --------------------
# Requirements
# --------------------
@"
python-socketio[client]
aiofiles
psutil
python-dotenv
aiohttp
pipreqs
"@ | Set-Content -Path $Requirements -Encoding utf8
Log "requirements.txt saved at $Requirements"

# --------------------
# Install packages
# --------------------
Log "Installing Python packages..."
& $Pip install --upgrade pip
& $Pip install -r $Requirements

# --------------------
# Download agent file
# --------------------
Log "Downloading agent to $AgentPath"
try {
  if (-not (Test-Path $ExtractDir)) {
    New-Item -ItemType Directory -Path $ExtractDir -Force | Out-Null
  }
  Invoke-WebRequest -Uri $AgentUrl -OutFile $AgentPath -UseBasicParsing
  Log "✅ Agent downloaded successfully"
} catch {
  Log "❌ Failed to download agent from $AgentUrl"
  throw
}

# --------------------
# Try Scheduled Task (admin mode)
# --------------------
$TaskRegistered = $false
try {
  $action    = New-ScheduledTaskAction -Execute $VenvPy -Argument "`"$AgentPath`""
  $trigger   = New-ScheduledTaskTrigger -AtLogOn
  $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
  $task      = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal

  schtasks /Delete /TN $TaskName /F | Out-Null 2>$null
  Register-ScheduledTask -TaskName $TaskName -InputObject $task | Out-Null
  Log "✅ Scheduled Task '$TaskName' created"
  $TaskRegistered = $true
} catch {
  Log "⚠️  Could not register scheduled task automatically. (Try running PowerShell as Administrator.)"
}

# --------------------
# Fallback: Startup Shortcut (non-admin)
# --------------------
if (-not $TaskRegistered) {
  try {
    $StartupDir = [Environment]::GetFolderPath("Startup")
    $Shortcut   = Join-Path $StartupDir "Agent.lnk"
    $WshShell   = New-Object -ComObject WScript.Shell
    $Lnk        = $WshShell.CreateShortcut($Shortcut)
    $Lnk.TargetPath       = $VenvPy
    $Lnk.Arguments        = "`"$AgentPath`""
    $Lnk.WorkingDirectory = $ExtractDir
    $Lnk.WindowStyle      = 7
    $Lnk.IconLocation     = "$env:SystemRoot\System32\shell32.dll, 2"
    $Lnk.Save()
    Log "✅ Startup shortcut created in $StartupDir"
  } catch {
    Log "⚠️  Failed to create startup shortcut: $($_.Exception.Message)"
  }
}

# --------------------
# Start agent now
# --------------------
try {
  Start-Process -FilePath $VenvPy -ArgumentList "`"$AgentPath`"" -WindowStyle Hidden -WorkingDirectory $ExtractDir
  Log "✅ Agent started in background"
  Write-Host "Setup complete. The agent will auto-start on logon." -ForegroundColor Green
} catch {
  Log ("❌ Failed to start agent immediately: " + $_.Exception.Message)
  throw
}

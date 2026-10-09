#requires -Version 5.1
<#
.SYNOPSIS
  Start the SentinelAI backend on Windows (native PowerShell).
.DESCRIPTION
  Reads HOST/PORT from .env when present (defaults 127.0.0.1:8000),
  activates .venv (creating it with dependencies on first run), and starts
  uvicorn with --reload. Equivalent of run.sh for bash.
.EXAMPLE
  .\run.ps1
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BackendDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $BackendDir

$Host_Ip = "127.0.0.1"
$Port = "8000"
$EnvFile = Join-Path $BackendDir ".env"
if (Test-Path -LiteralPath $EnvFile) {
    foreach ($line in (Get-Content -LiteralPath $EnvFile)) {
        $t = $line.Trim()
        if ($t -eq "" -or $t.StartsWith("#") -or -not $t.Contains("=")) { continue }
        $k, $v = $t.Split("=", 2)
        $k = $k.Trim(); $v = $v.Trim().Trim('"').Trim("'")
        if ($k -eq "HOST" -and $v -ne "") { $Host_Ip = $v }
        if ($k -eq "PORT" -and $v -ne "") { $Port = $v }
    }
}

$VenvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $VenvPython)) {
    Write-Host "Creating .venv and installing dependencies (first run only)…"
    python -m venv .venv
    & $VenvPython -m pip install -r requirements.txt -r requirements-dev.txt
}

# Activation-equivalent: venv console scripts (bandit, …) resolve even when
# the venv was never formally activated.
$env:PATH = "$(Join-Path $BackendDir '.venv\Scripts');$env:PATH"

Write-Host "Backend: http://${Host_Ip}:${Port}  docs: http://${Host_Ip}:${Port}/docs"
& $VenvPython -m uvicorn main:app --host $Host_Ip --port $Port --reload

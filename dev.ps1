#requires -Version 5.1
<#
.SYNOPSIS
  Start backend + frontend in two new PowerShell windows (Windows dev).
.EXAMPLE
  .\dev.ps1
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

Start-Process powershell -ArgumentList "-NoExit", "-Command", `
    "& { Set-Location -LiteralPath '$Root\backend'; .\run.ps1 }"
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
    "& { Set-Location -LiteralPath '$Root\frontend'; npm run dev }"

Write-Host "Backend window + frontend window starting…"
Write-Host "Open http://localhost:3000 once both are up."

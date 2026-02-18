# Airlock-MCP Demo - Live Security Audit Log
# Run this in the LEFT window before starting the attack

if (-not (Test-Path "demo\airlock.log")) {
    New-Item -Path "demo\airlock.log" -ItemType File -Force | Out-Null
}

Write-Host ""
Write-Host "  Airlock Security Audit Log - waiting for events..." -ForegroundColor Cyan
Write-Host ""

Get-Content -Path "demo\airlock.log" -Wait -Tail 30

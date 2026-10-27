$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$pidFile = Join-Path $PSScriptRoot 'data\server.pid'
$python = (Resolve-Path '.venv\Scripts\python.exe').Path
$serverPid = 0
if (Test-Path -LiteralPath $pidFile) {
    if (-not [int]::TryParse((Get-Content -LiteralPath $pidFile -Raw).Trim(), [ref]$serverPid)) {
        throw 'The server PID file is invalid. Remove data/server.pid only after checking that the demo server is stopped.'
    }
} else {
    $listener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    $candidate = if ($listener) { Get-CimInstance Win32_Process -Filter "ProcessId = $($listener.OwningProcess)" }
    if ($candidate -and $candidate.CommandLine.IndexOf($python,[StringComparison]::OrdinalIgnoreCase) -ge 0 -and $candidate.CommandLine -match 'uvicorn\s+(agentshield\.)?app:app' -and $candidate.CommandLine -match '--host\s+127\.0\.0\.1' -and $candidate.CommandLine -match '--port\s+8000') {
        $serverPid = $candidate.ProcessId
        Write-Host 'Found the AgentShield server launched from this project; stopping it.'
    } else {
        Write-Host 'No launcher-managed AgentShield server was found.'
        Write-Host 'If you started Uvicorn in a terminal, stop it with Ctrl+C in that terminal.'
        exit 0
    }
}

$process = Get-CimInstance Win32_Process -Filter "ProcessId = $serverPid"
if (-not $process) {
    Remove-Item -LiteralPath $pidFile -Force
    Write-Host 'The server process has already stopped; removed its stale PID file.'
    exit 0
}

$expected = $process.CommandLine.IndexOf($python,[StringComparison]::OrdinalIgnoreCase) -ge 0 -and $process.CommandLine -match 'uvicorn\s+(agentshield\.)?app:app' -and $process.CommandLine -match '--host\s+127\.0\.0\.1' -and $process.CommandLine -match '--port\s+8000'
if (-not $expected) {
    throw 'The PID file does not point to this project AgentShield Uvicorn process. It was left running.'
}

Stop-Process -Id $serverPid -Force
try { Wait-Process -Id $serverPid -Timeout 10 -ErrorAction SilentlyContinue } catch {}
Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
Write-Host 'AgentShield server stopped.'

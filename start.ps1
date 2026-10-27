$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

if (-not (Test-Path -LiteralPath '.env')) {
    Copy-Item -LiteralPath '.env.example' -Destination '.env'
    Write-Host 'Created .env from .env.example. Add GEMINI_API_KEY before running agent tasks.'
}
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    py -m venv .venv
}
$python = (Resolve-Path '.venv\Scripts\python.exe').Path
& $python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }

$port = 8000
$baseUrl = "http://127.0.0.1:$port"
$pidFile = Join-Path $PSScriptRoot 'data\server.pid'
$existingHealth = $null
try {
    $existingHealth = Invoke-RestMethod -Uri "$baseUrl/health" -TimeoutSec 2
} catch {}
if ($existingHealth.status -eq 'ok') {
    if (Test-Path -LiteralPath $pidFile) {
        Write-Host 'Restarting the AgentShield server managed by start.ps1 so code changes take effect.'
        & (Join-Path $PSScriptRoot 'stop.ps1')
        $stillRunning = $true
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            Start-Sleep -Milliseconds 250
            try { Invoke-RestMethod -Uri "$baseUrl/health" -TimeoutSec 1 | Out-Null } catch { $stillRunning = $false; break }
        }
        if ($stillRunning) { throw 'The previous AgentShield process did not release port 8000. Run .\stop.ps1 and try again.' }
    } else {
        $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        $existingProcess = if ($listener) { Get-CimInstance Win32_Process -Filter "ProcessId = $($listener.OwningProcess)" }
        if ($existingProcess -and $existingProcess.CommandLine.IndexOf($python,[StringComparison]::OrdinalIgnoreCase) -ge 0 -and $existingProcess.CommandLine -match 'uvicorn\s+(agentshield\.)?app:app' -and $existingProcess.CommandLine -match '--host\s+127\.0\.0\.1' -and $existingProcess.CommandLine -match '--port\s+8000') {
            Set-Content -LiteralPath $pidFile -Value $existingProcess.ProcessId -NoNewline
            Write-Host 'Found the AgentShield server previously launched from this project; restarting it to load code changes.'
            & (Join-Path $PSScriptRoot 'stop.ps1')
            $stillRunning = $true
            for ($attempt = 0; $attempt -lt 20; $attempt++) {
                Start-Sleep -Milliseconds 250
                try { Invoke-RestMethod -Uri "$baseUrl/health" -TimeoutSec 1 | Out-Null } catch { $stillRunning = $false; break }
            }
            if ($stillRunning) { throw 'The previous AgentShield process did not release port 8000. Run .\stop.ps1 and try again.' }
        } else {
            Start-Process $baseUrl
            Write-Host "AgentShield is already running at $baseUrl, but it was not started by this project launcher."
            Write-Host 'Stop the terminal process that started it, then run .\start.ps1 again.'
            exit 0
        }
    }
}

New-Item -ItemType Directory -Path 'data' -Force | Out-Null
$stdout = Join-Path $PSScriptRoot 'data\server.stdout.log'
$stderr = Join-Path $PSScriptRoot 'data\server.stderr.log'
$server = Start-Process -FilePath $python -ArgumentList @('-m','uvicorn','agentshield.app:app','--host','127.0.0.1','--port',"$port") -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
Set-Content -LiteralPath $pidFile -Value $server.Id -NoNewline

$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Start-Sleep -Milliseconds 500
    try {
        $health = Invoke-RestMethod -Uri "$baseUrl/health" -TimeoutSec 2
        if ($health.status -eq 'ok') { $ready = $true; break }
    } catch {}
    if ($server.HasExited) { break }
}
if (-not $ready) {
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    $diagnostics = if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Tail 20 } else { @() }
    throw "AgentShield failed to start. Check data/server.stderr.log. $($diagnostics -join ' ')"
}
Start-Process $baseUrl
Write-Host "AgentShield is ready at $baseUrl"
Write-Host 'The browser is connected automatically. Run a preset task from the dashboard.'
Write-Host 'Run .\stop.ps1 to stop the server. Running .\start.ps1 again restarts this managed server.'

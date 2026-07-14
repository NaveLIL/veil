$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $env:LOCALAPPDATA "Veil"
$logPath = Join-Path $logDir "server-autostart.log"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

function Write-Log([string]$message) {
    "$(Get-Date -Format o) $message" | Out-File -FilePath $logPath -Append -Encoding utf8
}

try {
    Write-Log "Starting Docker Desktop engine"
    docker desktop start | Out-Null

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            docker info --format '{{.ServerVersion}}' | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $ready = $true
                break
            }
        } catch {
            # Docker is still booting; retry without surfacing a console.
        }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) {
        throw "Docker engine did not become ready within 120 seconds"
    }

    Write-Log "Starting Veil gateway and push services"
    docker compose --project-directory $repo up -d gateway ntfy | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE"
    }
    Write-Log "Veil server stack started"
} catch {
    Write-Log "Autostart failed: $($_.Exception.Message)"
    exit 1
}

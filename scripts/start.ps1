$HealthTimeoutSeconds = if ($env:HEALTH_TIMEOUT_SECONDS) { [int]$env:HEALTH_TIMEOUT_SECONDS } else { 120 }
$UrlTimeoutSeconds = if ($env:URL_TIMEOUT_SECONDS) { [int]$env:URL_TIMEOUT_SECONDS } else { 90 }

function Read-EnvValue([string]$Key) {
    $value = [Environment]::GetEnvironmentVariable($Key, "Process")
    if ($value) { return $value }
    if (Test-Path ".env") {
        $line = Get-Content ".env" | Where-Object { $_ -match "^$Key=" } | Select-Object -Last 1
        if ($line) {
            $raw = $line -replace "^$Key=", ""
            $raw = $raw -replace '^"(.*)"$', '$1'
            $raw = $raw -replace "^'(.*)'$", '$1'
            return $raw
        }
    }
    return $null
}

function Set-EnvValue([string]$Key, [string]$Value) {
    if (-not (Test-Path ".env")) { New-Item -ItemType File -Path ".env" | Out-Null }
    $lines = Get-Content ".env"
    $out = New-Object System.Collections.Generic.List[string]
    $written = $false
    foreach ($line in $lines) {
        if ($line -match "^$Key=") {
            $out.Add("$Key=$Value")
            $written = $true
        } else {
            $out.Add($line)
        }
    }
    if (-not $written) { $out.Add("$Key=$Value") }
    Set-Content -Path ".env" -Value $out -Encoding UTF8
}

if (-not (Read-EnvValue "NGROK_AUTHTOKEN")) {
    Write-Host "NGROK_AUTHTOKEN is required."
    Write-Host "PowerShell: `$env:NGROK_AUTHTOKEN='your-ngrok-token'; powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1"
    Write-Host "Alternative: put NGROK_AUTHTOKEN=your-ngrok-token into .env"
    exit 1
}

New-Item -ItemType Directory -Force -Path "auth" | Out-Null
New-Item -ItemType Directory -Force -Path "workspace" | Out-Null
if (-not (Test-Path "auth/users.json")) {
    Set-Content -Path "auth/users.json" -Value "{`n  `"users`": []`n}`n" -Encoding UTF8
}

if (-not (Read-EnvValue "AUTH_JWT_SECRET")) {
    $bytes = New-Object byte[] 48
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $secret = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    Set-EnvValue "AUTH_JWT_SECRET" $secret
}

try {
    $usersJson = Get-Content "auth/users.json" -Raw | ConvertFrom-Json
    $userCount = @($usersJson.users).Count
} catch {
    $userCount = 0
}

if ($userCount -eq 0) {
    Write-Host "No users found in auth/users.json. Create one before connecting ChatGPT:"
    Write-Host "PowerShell: python .\scripts\create_user.py --username darius"
}

docker compose up --build -d mcp-app ngrok

Write-Host "Waiting for ngrok public HTTPS URL..."

$deadline = (Get-Date).AddSeconds($UrlTimeoutSeconds)
$url = $null
$UrlRegex = 'https://[-a-zA-Z0-9.]+\.ngrok(-free)?\.app'

while ((Get-Date) -lt $deadline) {
    try {
        $tunnels = Invoke-RestMethod -Uri "http://localhost:4040/api/tunnels" -TimeoutSec 3
        $httpsTunnel = $tunnels.tunnels | Where-Object { $_.public_url -like "https://*" } | Select-Object -First 1
        if ($httpsTunnel) {
            $url = $httpsTunnel.public_url
            break
        }
    } catch {}

    $logs = docker compose logs ngrok 2>&1 | Out-String
    $matches = [regex]::Matches($logs, $UrlRegex)
    if ($matches.Count -gt 0) {
        $url = $matches[$matches.Count - 1].Value
        break
    }

    Start-Sleep -Seconds 1
}

if (-not $url) {
    Write-Host "ngrok public URL was not found. Current ngrok logs:"
    docker compose logs ngrok
    exit 1
}

Write-Host "Public URL candidate: $url"
Write-Host "Writing OAuth public URL into .env and recreating mcp-app..."
Set-EnvValue "PUBLIC_BASE_URL" $url
Set-EnvValue "AUTH_ISSUER" $url
Set-EnvValue "AUTH_AUDIENCE" $url

docker compose up --build -d --force-recreate mcp-app

Write-Host "Checking public health endpoint before printing ChatGPT Connector URL..."

for ($i = 0; $i -lt $HealthTimeoutSeconds; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "$url/health" -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
            Write-Host "Public URL: $url"
            Write-Host "ChatGPT Connector URL: $url/mcp"
            Write-Host "OAuth Protected Resource Metadata: $url/.well-known/oauth-protected-resource"
            Write-Host "OAuth Authorization Server Metadata: $url/.well-known/oauth-authorization-server"
            Write-Host "Health URL: $url/health"
            Write-Host "Logs: docker compose logs -f mcp-app ngrok"
            exit 0
        }
    } catch {}
    Start-Sleep -Seconds 1
}

Write-Host "The ngrok URL appeared, but $url/health did not become reachable."
Write-Host "MCP app local health check:"
try { Invoke-RestMethod http://localhost:8000/health } catch { Write-Host $_ }
Write-Host "ngrok API tunnels:"
try { Invoke-RestMethod http://localhost:4040/api/tunnels } catch { Write-Host $_ }
Write-Host "mcp-app logs:"
docker compose logs mcp-app
Write-Host "ngrok logs:"
docker compose logs ngrok
exit 1

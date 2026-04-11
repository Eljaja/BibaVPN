# BibaVPN local stack + Python SOCKS e2e (TCP, UDP, idle, WebSocket).
# Usage (from repo root biba-vpn/):
#   .\scripts\run_e2e.ps1
# Remote client already running on SOCKS 127.0.0.1:1080:
#   $env:BIBAVPN_SKIP_STACK = "1"; $env:BIBAVPN_SOCKS_PORT = "1080"; .\scripts\run_e2e.ps1

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$useDebug = if ($env:BIBAVPN_RELEASE -eq "1") { $false } else { $true }
$profile = if ($useDebug) { "debug" } else { "release" }

$serverExe = $null
$clientExe = $null
if ($env:BIBAVPN_SERVER_EXE -and $env:BIBAVPN_CLIENT_EXE) {
    Write-Host ('[e2e] using BIBAVPN_SERVER_EXE / BIBAVPN_CLIENT_EXE (skip cargo)')
    $serverExe = $env:BIBAVPN_SERVER_EXE
    $clientExe = $env:BIBAVPN_CLIENT_EXE
} else {
    Write-Host ('[e2e] cargo build -p bibavpn --bins (' + ($(if ($useDebug) { 'debug' } else { 'release' })) + ')')
    if ($useDebug) {
        & cargo build -p bibavpn --bins
    } else {
        & cargo build -p bibavpn --bins --release
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[e2e] cargo build failed. Install Visual Studio Build Tools (C++) or MinGW, or set:'
        Write-Host ' `$env:BIBAVPN_SERVER_EXE` and `$env:BIBAVPN_CLIENT_EXE` to built binaries.'
        exit $LASTEXITCODE
    }
    $serverExe = Join-Path $RepoRoot "target\$profile\bibavpn-server.exe"
    $clientExe = Join-Path $RepoRoot "target\$profile\bibavpn-client.exe"
    if (-not (Test-Path $serverExe)) {
        $serverExe = Join-Path $RepoRoot "target\$profile\bibavpn-server"
        $clientExe = Join-Path $RepoRoot "target\$profile\bibavpn-client"
    }
}

$vpnPort = if ($env:BIBAVPN_LOCAL_PORT) { [int]$env:BIBAVPN_LOCAL_PORT } else {38443 + (Get-Random -Maximum 2000) }
$socksPort = if ($env:BIBAVPN_SOCKS_PORT) { [int]$env:BIBAVPN_SOCKS_PORT } else { 11080 + (Get-Random -Maximum 2000) }
$token = if ($env:BIBAVPN_TOKEN) { $env:BIBAVPN_TOKEN } else { "e2e-local-token" }

$serverProc = $null
$clientProc = $null
$code = 1

function Wait-SocksReady([string]$SockHost, [int]$Port, [int]$MaxSec = 45) {
    $deadline = (Get-Date).AddSeconds($MaxSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $iar = $c.BeginConnect($SockHost, $Port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(300, $false)) {
                $c.EndConnect($iar)
                $c.Close()
                return
            }
            $c.Close()
        } catch { }
        Start-Sleep -Milliseconds 200
    }
    throw "SOCKS ${SockHost}:$Port not reachable within ${MaxSec}s"
}

try {
    if ($env:BIBAVPN_SKIP_STACK -ne "1") {
        Write-Host ('[e2e] starting bibavpn-server on 127.0.0.1:' + $vpnPort)
        $serverArgs = @(
            "--listen", "127.0.0.1:$vpnPort",
            "--self-signed-san", "localhost",
            "--token", $token,
            "--ws-path", "/ws",
            "--ws-ping-secs", "10"
        )
        $serverProc = Start-Process -FilePath $serverExe -ArgumentList $serverArgs -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 1

        Write-Host ('[e2e] starting bibavpn-client SOCKS 127.0.0.1:' + $socksPort)
        $clientArgs = @(
            "--server", "127.0.0.1:$vpnPort",
            "--sni", "localhost",
            "--token", $token,
            "--insecure",
            "--socks5", "127.0.0.1:$socksPort",
            "--ws-ping-secs", "10"
        )
        $clientProc = Start-Process -FilePath $clientExe -ArgumentList $clientArgs -PassThru -WindowStyle Hidden

        Wait-SocksReady "127.0.0.1" $socksPort
    } else {
        Write-Host ('[e2e] BIBAVPN_SKIP_STACK=1 - using existing SOCKS 127.0.0.1:' + $socksPort)
        Wait-SocksReady "127.0.0.1" $socksPort
    }

    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
    if (-not $py) { throw "python not found in PATH" }

    $e2e = Join-Path $PSScriptRoot "bibavpn_e2e.py"
    & $py.Source $e2e --socks-host "127.0.0.1" --socks-port $socksPort @args
    if ($null -ne $LASTEXITCODE) { $code = $LASTEXITCODE } else { $code = 0 }
} catch {
    Write-Host ('[e2e] ERROR: ' + $_.Exception.Message)
    $code = 1
} finally {
    if ($clientProc -and -not $clientProc.HasExited) {
        Stop-Process -Id $clientProc.Id -Force -ErrorAction SilentlyContinue
    }
    if ($serverProc -and -not $serverProc.HasExited) {
        Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    }
}

exit $code

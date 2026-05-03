# Сборка bibavpn-desktop.exe без MSVC: Rust GNU + портабельный MinGW (winlibs).
# МинGW ставится в %LOCALAPPDATA%\bibavpn-mingw (не нужны права администратора).
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$mingwRoot = Join-Path $env:LOCALAPPDATA "bibavpn-mingw"
$mingwBin = Join-Path $mingwRoot "mingw64\bin"
$zipPath = Join-Path $mingwRoot "winlibs.zip"
$zipUrl = "https://github.com/brechtsanders/winlibs_mingw/releases/download/16.1.0posix-14.0.0-ucrt-r1/winlibs-x86_64-posix-seh-gcc-16.1.0-mingw-w64ucrt-14.0.0-r1.zip"

if (-not (Test-Path (Join-Path $mingwBin "dlltool.exe"))) {
    New-Item -ItemType Directory -Force -Path $mingwRoot | Out-Null
    Write-Host "Downloading MinGW (winlibs)..."
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath $mingwRoot -Force
}

if (-not (Test-Path (Join-Path $mingwBin "dlltool.exe"))) {
    Write-Error "MinGW bin not found under $mingwBin"
}

$env:PATH = "$mingwBin;$env:PATH"
Set-Location $repoRoot

Write-Host "Building UI..."
Push-Location (Join-Path $repoRoot "apps/bibavpn-desktop/ui")
try {
    npm install --no-audit --no-fund
    npm run build
} finally {
    Pop-Location
}

Write-Host "cargo build (x86_64-pc-windows-gnu)..."
cargo +stable-x86_64-pc-windows-gnu build -p bibavpn-desktop --release

$exe = Join-Path $repoRoot "target/release/bibavpn-desktop.exe"
Write-Host "Done: $exe"
Get-Item $exe | Format-List FullName, Length, LastWriteTime

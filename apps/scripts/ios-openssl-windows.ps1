#Requires -Version 5.1
<#
.SYNOPSIS
  OpenSSL на Windows для iOS-сертификата без Mac: CSR для developer.apple.com и сборка .p12 для CI (GitHub IOS_CERTIFICATE).

.INSTALL OPENSSL (выбери один вариант)

  1) winget (рекомендуется):
       winget install -e --id ShiningLight.OpenSSL.Light --accept-package-agreements

  2) Уже есть Git for Windows — openssl обычно здесь:
       "C:\Program Files\Git\usr\bin\openssl.exe"

  После установки перезапусти терминал и проверь:
       .\ios-openssl-windows.ps1 check

.USAGE

  Шаг A — CSR для Apple (Certificates → создать → загрузить CSR):
       $env:APPLE_CSR_EMAIL = 'you@domain.com'
       $env:APPLE_CSR_CN    = 'Your Name'
       .\ios-openssl-windows.ps1 csr

     В каталоге OutDir появятся ios_signing_private.key и ios_signing.csr — загрузи CSR на сайт Apple.

  Шаг B — после скачивания .cer с Apple (положи файл как ios_distribution.cer в тот же каталог):
       .\ios-openssl-windows.ps1 p12 -CerPath .\ios_distribution.cer

     Запросит пароль экспорта — это IOS_CERTIFICATE_PASSWORD для GitHub.

  Шаг C — base64 для секрета IOS_CERTIFICATE:
       .\ios-openssl-windows.ps1 print-base64 -P12Path .\ios_certificate.p12

.NOTES
  Храни ios_signing_private.key в секрете; без него нельзя собрать .p12 из выданного Apple .cer.
  Для provisioning profile секрет IOS_MOBILE_PROVISION — отдельно: base64 файла .mobileprovision в браузере.
#>

param(
    [Parameter(Position = 0)]
    [ValidateSet('check', 'csr', 'p12', 'print-base64')]
    [string]$Action = 'check',

    [string]$OutDir = (Join-Path $PSScriptRoot 'ios-signing-out'),

    [string]$CerPath = (Join-Path $PSScriptRoot 'ios-signing-out\ios_distribution.cer'),

    [string]$P12Path = (Join-Path $PSScriptRoot 'ios-signing-out\ios_certificate.p12'),

    [string]$KeyPath = (Join-Path $PSScriptRoot 'ios-signing-out\ios_signing_private.key'),

    [string]$CsrPath = (Join-Path $PSScriptRoot 'ios-signing-out\ios_signing.csr')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-OpenSslExe {
    $cmd = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    $x86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $candidates = [System.Collections.Generic.List[string]]::new()
    $candidates.Add((Join-Path ${env:ProgramFiles} 'Git\usr\bin\openssl.exe'))
    $candidates.Add((Join-Path ${env:ProgramFiles} 'OpenSSL-Win64\bin\openssl.exe'))
    if (-not [string]::IsNullOrEmpty($x86)) {
        $candidates.Add((Join-Path $x86 'Git\usr\bin\openssl.exe'))
        $candidates.Add((Join-Path $x86 'OpenSSL-Win32\bin\openssl.exe'))
    }
    foreach ($p in $candidates) {
        if (Test-Path -LiteralPath $p) {
            return $p
        }
    }
    return $null
}

function Invoke-OpenSsl {
    param([string]$Exe, [string[]]$Args)
    & $Exe @Args
    if ($LASTEXITCODE -ne 0) {
        throw "openssl exited with code $LASTEXITCODE"
    }
}

$openssl = Resolve-OpenSslExe
if (-not $openssl) {
    Write-Error @'
OpenSSL not found in PATH or standard Git/OpenSSL install paths.

Install:
  winget install -e --id ShiningLight.OpenSSL.Light --accept-package-agreements

Or install Git for Windows and ensure this directory is on PATH:
  C:\Program Files\Git\usr\bin
'@
}

switch ($Action) {
    'check' {
        Write-Host "OK: openssl -> $openssl"
        Invoke-OpenSsl -Exe $openssl -Args @('version')
        exit 0
    }

    'csr' {
        $email = $env:APPLE_CSR_EMAIL
        $cn = $env:APPLE_CSR_CN
        if ([string]::IsNullOrWhiteSpace($email) -or [string]::IsNullOrWhiteSpace($cn)) {
            Write-Error 'Set environment variables APPLE_CSR_EMAIL and APPLE_CSR_CN.'
        }

        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
        $keyOut = Join-Path $OutDir 'ios_signing_private.key'
        $csrOut = Join-Path $OutDir 'ios_signing.csr'

        Invoke-OpenSsl -Exe $openssl -Args @(
            'genrsa',
            '-out', $keyOut,
            '2048'
        )

        # CSR fields for Apple; change country/org if needed (ISO country code).
        $subj = "/emailAddress=$email/CN=$cn/C=RU/O=BibaVPN"
        Invoke-OpenSsl -Exe $openssl -Args @(
            'req', '-new',
            '-key', $keyOut,
            '-out', $csrOut,
            '-subj', $subj
        )

        Write-Host 'Done:'
        Write-Host ('  Private key (keep secret): ' + $keyOut)
        Write-Host ('  CSR upload this file at developer.apple.com: ' + $csrOut)
        exit 0
    }

    'p12' {
        if (-not (Test-Path -LiteralPath $CerPath)) {
            Write-Error ("Missing Apple .cer file: $CerPath. Download certificate and pass -CerPath.")
        }
        $dir = Split-Path -Parent $CerPath
        $pem = Join-Path $dir 'ios_cert_from_apple.pem'
        $key = Join-Path $dir 'ios_signing_private.key'
        $outP12 = Join-Path $dir 'ios_certificate.p12'

        if (-not (Test-Path -LiteralPath $key)) {
            Write-Error ("Missing private key: $key. Run 'csr' in this folder first.")
        }

        # Apple .cer is usually DER; sometimes PEM.
        & $openssl x509 -inform DER -in $CerPath -out $pem 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'DER failed, trying PEM...'
            Invoke-OpenSsl -Exe $openssl -Args @(
                'x509',
                '-inform', 'PEM',
                '-in', $CerPath,
                '-out', $pem
            )
        }

        Write-Host 'Enter PKCS12 export password when openssl prompts (twice). Use the same string as GitHub secret IOS_CERTIFICATE_PASSWORD.'
        Invoke-OpenSsl -Exe $openssl -Args @(
            'pkcs12',
            '-export',
            '-out', $outP12,
            '-inkey', $key,
            '-in', $pem
        )

        Write-Host ('Done: ' + $outP12)
        Write-Host ('Next: .\ios-openssl-windows.ps1 print-base64 -P12Path "' + $outP12 + '"')
        exit 0
    }

    'print-base64' {
        if (-not (Test-Path -LiteralPath $P12Path)) {
            Write-Error "Missing file: $P12Path"
        }
        $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $P12Path))
        $b64 = [Convert]::ToBase64String($bytes)
        Write-Host ('Base64 length: ' + $b64.Length + ' characters.')
        try {
            Set-Clipboard -Value $b64
            Write-Host 'Base64 copied to clipboard. Paste into GitHub secret IOS_CERTIFICATE as one line.'
        }
        catch {
            $sidecar = [System.IO.Path]::ChangeExtension($P12Path, '.p12.b64.txt')
            [System.IO.File]::WriteAllText($sidecar, $b64)
            Write-Host ('Clipboard unavailable; wrote file: ' + $sidecar)
        }
        exit 0
    }
}

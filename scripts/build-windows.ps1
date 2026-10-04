<#
.SYNOPSIS
Builds all Windows binaries and prepares Explorer integration for testing.

.DESCRIPTION
Runs the release workspace build, copies ShellIcon.ico beside the executables,
and creates the sparse MSIX package. With no signing arguments it creates an
unsigned development package. Run withcrypt-setup.exe register afterward.

.EXAMPLE
.\scripts\build-windows.ps1
.\target\release\withcrypt-setup.exe register

.EXAMPLE
.\scripts\build-windows.ps1 -Publisher "CN=WithCrypt" -CertificatePath .\withcrypt.pfx
#>
param(
    [string]$Publisher,
    [string]$CertificatePath,
    [SecureString]$CertificatePassword,
    [string]$Version = "0.1.0.0"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$release = Join-Path $root "target\release"
$shellIcon = Join-Path $root "resources\ShellIcon.ico"

if (-not (Test-Path $shellIcon)) {
    throw "resources\ShellIcon.ico not found."
}

Push-Location $root
try {
    cargo build --release --locked --workspace
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}

Copy-Item $shellIcon (Join-Path $release "ShellIcon.ico") -Force
# Avoid accidentally launching binaries left by versions before the rename.
foreach ($oldName in "withcrypt-desktop.exe", "withcrypt-shell-setup.exe") {
    $oldPath = Join-Path $release $oldName
    if (Test-Path $oldPath) { Remove-Item $oldPath -Force }
}

$packageArguments = @{
    InstallDir = $release
    Version = $Version
}
if ($Publisher -and $CertificatePath) {
    $packageArguments["Publisher"] = $Publisher
    $packageArguments["CertificatePath"] = $CertificatePath
    if ($CertificatePassword) {
        $packageArguments["CertificatePassword"] = $CertificatePassword
    }
} elseif ($Publisher -or $CertificatePath) {
    throw "Signed builds require both -Publisher and -CertificatePath."
} else {
    $packageArguments["Unsigned"] = $true
}

& (Join-Path $PSScriptRoot "package-windows-shell.ps1") @packageArguments
if ($LASTEXITCODE -ne 0) { throw "Shell package build failed ($LASTEXITCODE)" }

Write-Host "Windows build is ready in $release"
Write-Host "Register: .\target\release\withcrypt-setup.exe register"

<#
.SYNOPSIS
Builds the Windows binaries for x64, x86 and/or ARM64 and prepares Explorer
integration. See docs/build-windows.md.

.DESCRIPTION
For each architecture: runs the release workspace build for its Rust target,
copies ShellIcon.ico beside the executables and, for x64 and ARM64, creates
the sparse MSIX package for the Windows 11 menu. x86 (32-bit) builds use the
classic menu only, so no package is made for them.

Output: target\<rust-target>\release, e.g. target\aarch64-pc-windows-msvc\release.
With no signing arguments the package is unsigned (development only).

.EXAMPLE
.\scripts\build-windows.ps1 -Architecture x64

.EXAMPLE
.\scripts\build-windows.ps1 -Architecture x64,x86,arm64

.EXAMPLE
.\scripts\build-windows.ps1 -Architecture arm64 -Publisher "CN=WithCrypt Dev" -CertificateThumbprint <thumbprint>
#>
param(
    [ValidateSet("x64", "x86", "arm64")]
    [string[]]$Architecture = @("x64"),
    [string]$Publisher,
    [string]$CertificatePath,
    [string]$CertificateThumbprint,
    [SecureString]$CertificatePassword,
    [string]$Version = "0.1.0.0"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$shellIcon = Join-Path $root "resources\ShellIcon.ico"
$triples = @{
    x64 = "x86_64-pc-windows-msvc"
    x86 = "i686-pc-windows-msvc"
    arm64 = "aarch64-pc-windows-msvc"
}
# MSVC folder name per architecture, used to detect missing VS components.
$msvcArch = @{ x64 = "x64"; x86 = "x86"; arm64 = "arm64" }
$msvcHost = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "HostARM64" } else { "Hostx64" }

if (-not (Test-Path $shellIcon)) {
    throw "resources\ShellIcon.ico not found."
}
if (($Publisher -or $CertificatePath -or $CertificateThumbprint) -and
    -not ($Publisher -and ($CertificatePath -or $CertificateThumbprint))) {
    throw "Signed builds require -Publisher with -CertificatePath or -CertificateThumbprint."
}

# Fail early with a clear message instead of an obscure linker error.
$installedTargets = rustup target list --installed
$msvcRoots = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*" -Directory -ErrorAction SilentlyContinue
foreach ($arch in $Architecture) {
    $triple = $triples[$arch]
    if ($installedTargets -notcontains $triple) {
        throw "Rust target $triple is not installed. Run: rustup target add $triple"
    }
    # Both the target libraries and the host-to-target linker must come from
    # the same MSVC toolset; a VS install can have one without the other.
    $toolset = $msvcRoots | Where-Object {
        (Test-Path (Join-Path $_.FullName "lib\$($msvcArch[$arch])")) -and
        (Test-Path (Join-Path $_.FullName "bin\$msvcHost\$($msvcArch[$arch])\link.exe"))
    }
    if (-not $toolset) {
        $component = if ($arch -eq "arm64") { "C++ ARM64/ARM64EC build tools" } else { "C++ x64/x86 build tools" }
        throw "MSVC tools for $arch are missing. Install the MSVC '$component' component with the Visual Studio Installer."
    }
}

foreach ($arch in $Architecture) {
    $triple = $triples[$arch]
    $release = Join-Path $root "target\$triple\release"
    Write-Host "=== $arch ($triple)"

    Push-Location $root
    try {
        cargo build --release --locked --workspace --target $triple
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed for $triple ($LASTEXITCODE)" }
    } finally {
        Pop-Location
    }

    Copy-Item $shellIcon (Join-Path $release "ShellIcon.ico") -Force
    # Avoid accidentally launching binaries left by versions before the rename.
    foreach ($oldName in "withcrypt-desktop.exe", "withcrypt-shell-setup.exe") {
        $oldPath = Join-Path $release $oldName
        if (Test-Path $oldPath) { Remove-Item $oldPath -Force }
    }

    if ($arch -eq "x86") {
        # A 32-bit shell DLL cannot load into the 64-bit Explorer of Windows 11.
        Remove-Item (Join-Path $release "WithCrypt.Shell.msix") -ErrorAction SilentlyContinue
        Write-Host "x86: classic Explorer menu only (no Windows 11 package)."
    } else {
        $packageArguments = @{
            Architecture = $arch
            InstallDir = $release
            Version = $Version
        }
        if ($Publisher) {
            $packageArguments["Publisher"] = $Publisher
            if ($CertificateThumbprint) {
                $packageArguments["CertificateThumbprint"] = $CertificateThumbprint
            } else {
                $packageArguments["CertificatePath"] = $CertificatePath
                if ($CertificatePassword) { $packageArguments["CertificatePassword"] = $CertificatePassword }
            }
        } else {
            $packageArguments["Unsigned"] = $true
        }
        & (Join-Path $PSScriptRoot "package-windows-shell.ps1") @packageArguments
    }
    Write-Host "Ready: $release"
}

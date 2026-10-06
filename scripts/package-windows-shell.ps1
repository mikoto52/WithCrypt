<#
.SYNOPSIS
Builds the sparse package for the Windows 11 top-level Explorer menu.

.DESCRIPTION
The package holds only the manifest and logos. withcrypt-gui.exe and
withcrypt_shell.dll stay in -InstallDir (the external location), and the
finished WithCrypt.Shell.msix is copied there too so withcrypt-setup.exe
can register it.

-Architecture must match the binaries: x64 or arm64. Explorer only loads a
shell DLL of its own architecture, and every Windows 11 is 64-bit, so there is
no x86 package; 32-bit builds use the classic menu instead.

-Unsigned (Windows 11 only) uses Microsoft's test publisher OID and skips
signing; withcrypt-setup installs it with Add-AppxPackage -AllowUnsigned.
Windows ignores the all-files menu entry of an unsigned package, so use a
signed build (a trusted self-signed test certificate is enough) to test the
menu. Signed builds need -Publisher equal to the certificate subject.

.EXAMPLE
.\scripts\package-windows-shell.ps1 -Architecture x64 -Unsigned

.EXAMPLE
.\scripts\package-windows-shell.ps1 -Architecture arm64 -Publisher "CN=WithCrypt" -CertificatePath .\withcrypt.pfx

.EXAMPLE
# Certificate from the current user's store, e.g. a self-signed test certificate.
.\scripts\package-windows-shell.ps1 -Architecture x64 -Publisher "CN=WithCrypt Dev" -CertificateThumbprint <thumbprint>
#>
param(
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64",
    [switch]$Unsigned,
    [string]$Publisher,
    [string]$CertificatePath,
    [string]$CertificateThumbprint,
    [SecureString]$CertificatePassword,
    [string]$InstallDir,
    [string]$OutDir,
    [string]$Version = "0.1.0.0"
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$triple = @{ x64 = "x86_64-pc-windows-msvc"; arm64 = "aarch64-pc-windows-msvc" }[$Architecture]
if (-not $InstallDir) { $InstallDir = Join-Path $root "target\$triple\release" }
if (-not $OutDir) { $OutDir = Join-Path $root "target\msix\$Architecture" }

# Required in the publisher of every unsigned package; see
# https://learn.microsoft.com/windows/msix/package/unsigned-package
$unsignedOid = "OID.2.25.311729368913984317654407730594956997722=1"
if ($Unsigned) {
    if (-not $Publisher) { $Publisher = "CN=WithCrypt Dev" }
    if ($Publisher -notmatch [regex]::Escape($unsignedOid)) { $Publisher = "$Publisher, $unsignedOid" }
} elseif (-not $Publisher -or -not ($CertificatePath -or $CertificateThumbprint)) {
    throw "Pass -Publisher with -CertificatePath or -CertificateThumbprint, or -Unsigned until code signing is set up."
}
if (-not (Test-Path $InstallDir)) {
    throw "$InstallDir not found. Run: .\scripts\build-windows.ps1 -Architecture $Architecture"
}
$InstallDir = (Resolve-Path $InstallDir).Path
foreach ($file in "withcrypt-gui.exe", "withcrypt_shell.dll") {
    if (-not (Test-Path (Join-Path $InstallDir $file))) {
        throw "$file not found in $InstallDir. Run: .\scripts\build-windows.ps1 -Architecture $Architecture"
    }
}
$shellIcon = Join-Path $root "resources\ShellIcon.ico"
if (-not (Test-Path $shellIcon)) { throw "resources\ShellIcon.ico not found." }
Copy-Item $shellIcon (Join-Path $InstallDir "ShellIcon.ico") -Force

# The SDK tools run on the build machine, so pick the host's tool folder.
$hostTools = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
$kit = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.*\$hostTools\makeappx.exe" |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $kit) { throw "Windows SDK (makeappx.exe) not found." }
$makeappx = $kit.FullName
$signtool = Join-Path $kit.DirectoryName "signtool.exe"

$stage = Join-Path $OutDir "stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force (Join-Path $stage "Assets") | Out-Null
$manifest = (Get-Content (Join-Path $PSScriptRoot "windows-shell\AppxManifest.xml") -Raw -Encoding UTF8).
    Replace("__PUBLISHER__", [Security.SecurityElement]::Escape($Publisher)).
    Replace("__VERSION__", $Version).
    Replace("__ARCH__", $Architecture)
[IO.File]::WriteAllText((Join-Path $stage "AppxManifest.xml"), $manifest, (New-Object Text.UTF8Encoding $false))

Add-Type -AssemblyName System.Drawing
$icon = [Drawing.Image]::FromFile((Join-Path $root "resources\ShellIcon.png"))
try {
    foreach ($asset in @(@("Square44x44Logo.png", 44), @("Square150x150Logo.png", 150), @("StoreLogo.png", 50))) {
        $size = $asset[1]
        $bitmap = New-Object Drawing.Bitmap $size, $size
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.DrawImage($icon, 0, 0, $size, $size)
        $graphics.Dispose()
        $bitmap.Save((Join-Path $stage "Assets\$($asset[0])"), [Drawing.Imaging.ImageFormat]::Png)
        $bitmap.Dispose()
    }
} finally {
    $icon.Dispose()
}

$msix = Join-Path $OutDir "WithCrypt.Shell.msix"
# /nv: a sparse package intentionally omits the executables it references.
& $makeappx pack /d $stage /p $msix /nv /o | Out-Null
if ($LASTEXITCODE -ne 0) { throw "makeappx failed ($LASTEXITCODE)" }
if (-not $Unsigned) {
    if ($CertificateThumbprint) {
        # Signs with a certificate from the current user's personal store.
        $signArgs = @("sign", "/fd", "SHA256", "/s", "My", "/sha1", $CertificateThumbprint)
    } else {
        $signArgs = @("sign", "/fd", "SHA256", "/f", (Resolve-Path $CertificatePath).Path)
        if ($CertificatePassword) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertificatePassword)
            try { $signArgs += @("/p", [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
    }
    & $signtool @signArgs $msix | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
}
Copy-Item $msix (Join-Path $InstallDir "WithCrypt.Shell.msix") -Force
Write-Host "Package ($Architecture, $(if ($Unsigned) { 'unsigned' } else { 'signed' })): $msix"
Write-Host "Copied to $InstallDir"

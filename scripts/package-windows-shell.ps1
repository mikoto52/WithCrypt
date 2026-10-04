<#
.SYNOPSIS
Builds the sparse package for the Windows 11 top-level Explorer menu.

.DESCRIPTION
The package holds only the manifest and logos. withcrypt-gui.exe and
withcrypt_shell.dll stay in -InstallDir (the external location), and the
finished WithCrypt.Shell.msix is copied there too so withcrypt-setup.exe
can register it.

-Unsigned (Windows 11 only) uses Microsoft's test publisher OID and skips
signing; withcrypt-setup installs it with Add-AppxPackage -AllowUnsigned.
Use it until code signing is set up, not for wide distribution. Signed builds
need -Publisher equal to the certificate subject and a trusted certificate.

.EXAMPLE
cargo build --release --locked -p withcrypt-gui -p withcrypt-shell -p withcrypt-setup
.\scripts\package-windows-shell.ps1 -Unsigned
.\target\release\withcrypt-setup.exe register

.EXAMPLE
.\scripts\package-windows-shell.ps1 -Publisher "CN=WithCrypt" -CertificatePath .\withcrypt.pfx
#>
param(
    [switch]$Unsigned,
    [string]$Publisher,
    [string]$CertificatePath,
    [SecureString]$CertificatePassword,
    [string]$InstallDir = (Join-Path $PSScriptRoot "..\target\release"),
    [string]$OutDir = (Join-Path $PSScriptRoot "..\target\msix"),
    [string]$Version = "0.1.0.0"
)
$ErrorActionPreference = "Stop"
# Required in the publisher of every unsigned package; see
# https://learn.microsoft.com/windows/msix/package/unsigned-package
$unsignedOid = "OID.2.25.311729368913984317654407730594956997722=1"
if ($Unsigned) {
    if (-not $Publisher) { $Publisher = "CN=WithCrypt Dev" }
    if ($Publisher -notmatch [regex]::Escape($unsignedOid)) { $Publisher = "$Publisher, $unsignedOid" }
} elseif (-not $Publisher -or -not $CertificatePath) {
    throw "Pass -Publisher and -CertificatePath, or -Unsigned until code signing is set up."
}
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$InstallDir = (Resolve-Path $InstallDir).Path
foreach ($file in "withcrypt-gui.exe", "withcrypt_shell.dll") {
    if (-not (Test-Path (Join-Path $InstallDir $file))) {
        throw "$file not found in $InstallDir. Run: cargo build --release --locked -p withcrypt-gui -p withcrypt-shell -p withcrypt-setup"
    }
}
$shellIcon = Join-Path $root "resources\ShellIcon.ico"
if (-not (Test-Path $shellIcon)) { throw "resources\ShellIcon.ico not found." }
Copy-Item $shellIcon (Join-Path $InstallDir "ShellIcon.ico") -Force
$kit = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.*\x64\makeappx.exe" |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $kit) { throw "Windows SDK (makeappx.exe) not found." }
$makeappx = $kit.FullName
$signtool = Join-Path $kit.DirectoryName "signtool.exe"

$stage = Join-Path $OutDir "stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force (Join-Path $stage "Assets") | Out-Null
$manifest = (Get-Content (Join-Path $PSScriptRoot "windows-shell\AppxManifest.xml") -Raw -Encoding UTF8).
    Replace("__PUBLISHER__", [Security.SecurityElement]::Escape($Publisher)).
    Replace("__VERSION__", $Version)
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
    $signArgs = @("sign", "/fd", "SHA256", "/f", (Resolve-Path $CertificatePath).Path)
    if ($CertificatePassword) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertificatePassword)
        try { $signArgs += @("/p", [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    & $signtool @signArgs $msix
    if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
}
Copy-Item $msix (Join-Path $InstallDir "WithCrypt.Shell.msix") -Force
Write-Host "Package: $msix ($(if ($Unsigned) { 'unsigned' } else { 'signed' }))"
Write-Host "Copied to $InstallDir. Register: withcrypt-setup.exe register"

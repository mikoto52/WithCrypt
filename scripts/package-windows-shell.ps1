<#
.SYNOPSIS
Builds and signs the sparse package for the Windows 11 top-level Explorer menu.

.DESCRIPTION
The package holds only the manifest and logos. withcrypt-desktop.exe and
withcrypt_shell.dll stay in -InstallDir (the external location). Windows only
installs signed packages, so -Publisher must equal the certificate subject and
the certificate must be trusted on the machine. The classic menu
(withcrypt-desktop.exe --register-shell) needs none of this.

.EXAMPLE
cargo build --release --locked -p withcrypt-desktop -p withcrypt-shell
.\scripts\package-windows-shell.ps1 -Publisher "CN=WithCrypt" -CertificatePath .\withcrypt.pfx -Install
#>
param(
    [Parameter(Mandatory = $true)][string]$Publisher,
    [Parameter(Mandatory = $true)][string]$CertificatePath,
    [SecureString]$CertificatePassword,
    [string]$InstallDir = (Join-Path $PSScriptRoot "..\target\release"),
    [string]$OutDir = (Join-Path $PSScriptRoot "..\target\msix"),
    [string]$Version = "0.1.0.0",
    [switch]$Install
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$InstallDir = (Resolve-Path $InstallDir).Path
foreach ($file in "withcrypt-desktop.exe", "withcrypt_shell.dll") {
    if (-not (Test-Path (Join-Path $InstallDir $file))) {
        throw "$file not found in $InstallDir. Run: cargo build --release --locked -p withcrypt-desktop -p withcrypt-shell"
    }
}
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
& $makeappx pack /d $stage /p $msix /nv /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed ($LASTEXITCODE)" }
$signArgs = @("sign", "/fd", "SHA256", "/f", (Resolve-Path $CertificatePath).Path)
if ($CertificatePassword) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertificatePassword)
    try { $signArgs += @("/p", [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
& $signtool @signArgs $msix
if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }

if ($Install) {
    Add-AppxPackage -Path $msix -ExternalLocation $InstallDir
    Write-Host "Installed. Restart Explorer if the menu does not appear yet."
} else {
    Write-Host "Package: $msix"
    Write-Host "Install: Add-AppxPackage -Path `"$msix`" -ExternalLocation `"$InstallDir`""
}
Write-Host "Remove:  Get-AppxPackage WithCrypt.ShellExtension | Remove-AppxPackage"

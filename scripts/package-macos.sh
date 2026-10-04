#!/bin/sh
set -eu
cargo build --release --locked --workspace
bundle=dist/macos/WithCrypt.app/Contents
mkdir -p "$bundle/MacOS" "$bundle/Resources"
cp LICENSE "$bundle/Resources/LICENSE"
cp LICENSE dist/macos/LICENSE
cp resources/AppIcon.icns "$bundle/Resources/WithCrypt.icns"
cp target/release/withcrypt-gui "$bundle/MacOS/WithCrypt"
cp target/release/withcrypt dist/macos/withcrypt
cat > "$bundle/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key>
<string>WithCrypt</string>
<key>CFBundleIconFile</key>
<string>WithCrypt.icns</string>
<key>CFBundleDisplayName</key>
<string>WithCrypt</string>
<key>CFBundleExecutable</key>
<string>WithCrypt</string>
<key>CFBundleIdentifier</key>
<string>local.withcrypt.gui</string>
<key>CFBundleVersion</key>
<string>0.1.0</string>
<key>CFBundleShortVersionString</key>
<string>0.1.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST

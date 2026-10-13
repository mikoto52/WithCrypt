# Windows 빌드 매뉴얼

WithCrypt를 Windows용 **x64, x86(32비트), ARM64**로 빌드하고, 탐색기 메뉴 패키지와 설치 프로그램을 만드는 방법이다. 명령은 모두 저장소 루트의 PowerShell에서 실행한다.

## 1. 아키텍처별 결과물

| 아키텍처 | Rust 타깃 | 빌드 폴더 | 탐색기 메뉴 | GUI 렌더러 | 설치 파일 |
|---|---|---|---|---|---|
| x64 | `x86_64-pc-windows-msvc` | `target\x86_64-pc-windows-msvc\release` | Windows 11 새 메뉴 + 클래식 | OpenGL | `WithCrypt-setup-x64.exe` |
| x86 | `i686-pc-windows-msvc` | `target\i686-pc-windows-msvc\release` | 클래식만 | OpenGL | `WithCrypt-setup-x86.exe` |
| ARM64 | `aarch64-pc-windows-msvc` | `target\aarch64-pc-windows-msvc\release` | Windows 11 새 메뉴 + 클래식 | Direct3D 12 (wgpu) | `WithCrypt-setup-arm64.exe` |

- **x86에 새 메뉴가 없는 이유:** 탐색기는 자기와 같은 아키텍처의 DLL만 불러온다. Windows 11은 64비트뿐이라 32비트 셸 DLL을 쓸 수 없다. x86 빌드는 클래식 메뉴("더 많은 옵션 표시")만 등록하며, 64비트 Windows에 설치해도 동작한다.
- **ARM64가 Direct3D 12를 쓰는 이유:** ARM PC는 OpenGL 드라이버가 보장되지 않는다.
- **AES-256-GCM:** 세 아키텍처 모두 지원한다. x86·x64는 AES-NI를 자동으로 쓰고, ARM64는 상수 시간 소프트웨어 구현을 쓴다(x64보다 느릴 수 있다).

## 2. 준비물

1. **Rust (rustup).** 저장소의 `rust-toolchain.toml`이 1.99.0을 자동으로 고른다. 추가로 빌드할 타깃을 설치한다.
   ```powershell
   rustup target add i686-pc-windows-msvc aarch64-pc-windows-msvc --toolchain 1.99.0
   ```
2. **Visual Studio 2022 (또는 Build Tools).** "C++를 사용한 데스크톱 개발" 워크로드에 아래 개별 구성 요소가 필요하다.
   - MSVC v143 - VS 2022 C++ x64/x86 빌드 도구 (x64·x86)
   - MSVC v143 - VS 2022 C++ ARM64/ARM64EC 빌드 도구 (ARM64)
   - Windows 11 SDK (`rc.exe`, `makeappx.exe`, `signtool.exe`)

   ARM64는 같은 MSVC 버전 안에 ARM64 **라이브러리와 링커가 모두** 있어야 한다. 라이브러리만 있고 링커(`bin\Hostx64\arm64\link.exe`)가 없는 설치도 있으니, 빌드 스크립트가 `MSVC tools for arm64 are missing`이라고 멈추면 위 ARM64 구성 요소를 설치한다.
3. **NSIS 3** (설치 프로그램을 만들 때만). `makensis.exe`가 `C:\Program Files (x86)\NSIS`에 있으면 된다.

## 3. 빠른 시작

```powershell
.\scripts\build-windows.ps1 -Architecture x64,x86,arm64
```

아키텍처마다 다음을 한다.
1. `cargo build --release --locked --workspace --target <타깃>`으로 빌드한다.
2. `ShellIcon.ico`를 빌드 폴더에 복사한다.
3. x64·ARM64는 Windows 11 메뉴 패키지 `WithCrypt.Shell.msix`를 만든다.

빌드 전에 Rust 타깃과 MSVC 도구가 있는지 검사하고, 없으면 무엇을 설치할지 알려주고 멈춘다. 하나만 빌드하려면 `-Architecture arm64`처럼 지정한다(기본값 x64).

`cargo build`만 직접 실행해도 실행 파일은 나오지만, 탐색기 메뉴에 필요한 `ShellIcon.ico`와 MSIX는 만들어지지 않는다. 배포물은 스크립트로 만든다.

## 4. 탐색기 메뉴 패키지와 서명

Windows 11 새 메뉴는 sparse MSIX 패키지로 등록한다.

**서명 없는 패키지는 메뉴가 나타나지 않는다.** 서명 인자 없이 빌드하면 서명 없는 패키지가 만들어진다. 이 패키지는 관리자 권한으로 설치는 되지만, 탐색기가 모든 파일(`*`)용 메뉴 항목을 무시해서 메뉴가 나타나지 않는다(ADR-004). 메뉴를 시험할 때는 아래처럼 시험용 인증서로라도 서명한다.

### 시험용 자체 서명 인증서 (개발 PC 전용)

1. 인증서를 만든다(관리자 권한 불필요, 현재 사용자 저장소).
   ```powershell
   $cert = New-SelfSignedCertificate -Type Custom -Subject "CN=WithCrypt Dev" -KeyUsage DigitalSignature `
     -FriendlyName "WithCrypt Dev (test signing)" -CertStoreLocation Cert:\CurrentUser\My `
     -NotAfter (Get-Date).AddYears(2) `
     -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
   Export-Certificate -Cert $cert -FilePath .\target\WithCrypt-Dev.cer
   $cert.Thumbprint
   ```
2. 이 PC가 인증서를 신뢰하게 한다(**관리자 권한** 명령 프롬프트, 한 번만).
   ```powershell
   certutil -addstore TrustedPeople .\target\WithCrypt-Dev.cer
   ```
3. 지문(thumbprint)으로 서명해서 빌드한다. `-Publisher`는 인증서 Subject와 정확히 같아야 한다.
   ```powershell
   .\scripts\build-windows.ps1 -Architecture x64 -Publisher "CN=WithCrypt Dev" -CertificateThumbprint <지문>
   ```

ARM64 기기에서 시험할 때는 그 기기에서도 2단계를 해야 한다. 시험이 끝나면 `certutil -delstore TrustedPeople <지문>`(관리자)으로 신뢰를 지운다.

### 배포용 서명

신뢰된 코드 서명 인증서(PFX)로 서명한다.

```powershell
.\scripts\build-windows.ps1 -Architecture x64,arm64 -Publisher "CN=<인증서 Subject>" -CertificatePath .\withcrypt.pfx -CertificatePassword (Read-Host -AsSecureString)
```

패키지를 다시 만들 때는 `-Version 0.1.3.0`처럼 버전을 올리면 탐색기가 새 패키지로 확실히 인식한다.

### 등록과 확인

```powershell
.\target\x86_64-pc-windows-msvc\release\withcrypt-setup.exe register
.\target\x86_64-pc-windows-msvc\release\withcrypt-setup.exe status
```

- 탐색기는 패키지 메뉴를 시작할 때만 읽는다. 등록 후에는 **탐색기를 재시작**하거나 다시 로그인한다.
- 등록하면 새 메뉴와 클래식 메뉴("더 많은 옵션 표시")가 함께 유지된다. `register --classic-only`는 클래식 메뉴만 등록한다.
- 해제는 `unregister`로 한다. 관리자 권한으로 설치한 패키지는 관리자 권한에서 해제해야 한다.

## 5. 설치 프로그램 (NSIS)

해당 아키텍처를 먼저 3장의 스크립트로 빌드한 뒤 컴파일한다.

```powershell
cd installer
& "C:\Program Files (x86)\NSIS\makensis.exe" /DARCH=x64 Installer.nsi
& "C:\Program Files (x86)\NSIS\makensis.exe" /DARCH=x86 Installer.nsi
& "C:\Program Files (x86)\NSIS\makensis.exe" /DARCH=arm64 Installer.nsi
```

`installer\WithCrypt-setup-<arch>.exe`가 생기며, 설치 프로그램은 다음과 같이 동작한다.
- x64 설치 파일은 x64 Windows에서만, ARM64 설치 파일은 ARM64 Windows에서만 실행된다. x86 설치 파일은 어디서나 실행된다.
- 64비트는 `C:\Program Files\WithCrypt`, 32비트는 `C:\Program Files (x86)\WithCrypt`에 설치한다.
- 설치 중에 `withcrypt-setup.exe register`로 탐색기 메뉴를 등록하고, 제거할 때 `unregister`로 해제한다.

`Installer.nsi`는 CP949(한국어 ANSI)로 저장되어 있다. 편집기에서 UTF-8로 다시 저장하면 한국어 메시지가 깨진다.

## 6. 테스트

```powershell
cargo test --workspace --locked --target x86_64-pc-windows-msvc
cargo test --workspace --locked --target i686-pc-windows-msvc
```

- **x86:** 테스트는 x64 PC에서 그대로 실행된다.
- **ARM64:** x64 PC에서는 빌드·검사(`cargo clippy --target aarch64-pc-windows-msvc`)만 되고 실행은 안 된다. ARM64 기기나 CI에서 테스트한다.

실제 기기에서 확인할 것:
1. GUI 창이 뜨고 암호화·복호화·검증이 되는가. ARM64는 Direct3D 12 경로다.
2. 두 알고리즘 모두 동작하는가. x86과 ARM64에서 AES-256-GCM 파일을 만들고, 다른 아키텍처에서 복호화해 본다.
3. `withcrypt-setup.exe register`를 실행해도 관리자 권한 창이 뜨지 않는가.
4. 우클릭 메뉴가 나오는가. 일반 파일에는 "WithCrypt로 암호화", `.esb`에는 "WithCrypt로 복호화"가 떠야 한다.

## 7. CI

`.github/workflows/ci.yml`의 `windows-arch` 작업은 다음을 한다.
- x86은 `windows-latest`에서 32비트로 빌드·테스트한다.
- ARM64는 `windows-11-arm` 러너에서 네이티브로 빌드·테스트한다.
- 산출물은 `WithCrypt-windows-x86`, `WithCrypt-windows-arm64`로 올라간다.

x64는 기존 `test` 작업이 맡는다. CI 산출물에는 MSIX와 설치 파일이 없다. 서명 인증서가 필요한 단계는 로컬에서 한다.

## 8. 문제 해결

| 증상 | 원인과 해결 |
|---|---|
| `Rust target ... is not installed` | `rustup target add <타깃>` |
| `MSVC tools for arm64 are missing` 또는 `link.exe not found` | Visual Studio Installer에서 "C++ ARM64/ARM64EC 빌드 도구" 설치 |
| `register` 시 0x80073D2B | 서명 없는 패키지는 관리자 권한에서만 설치된다. 서명 빌드를 쓴다(4장). |
| 패키지는 설치됐는데 새 메뉴가 안 보임 | 탐색기 재시작. 서명 없는 패키지라면 시험용 인증서로 서명한다(4장). |
| x86 `withcrypt-setup.exe`가 관리자 권한을 요구 | Windows의 설치 프로그램 감지 때문이다. 빌드 스크립트(`build/windows_resource.rs`)가 `asInvoker` 매니페스트를 넣으므로, 직접 링크한 바이너리가 아니라 이 저장소로 빌드한 것을 쓴다. |
| ARM64에서 GUI가 뜨지 않음 | 그래픽 드라이버의 Direct3D 12 지원을 확인한다(Windows 업데이트·제조사 드라이버). |

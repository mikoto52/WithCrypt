# 빌드 및 배포

각 플랫폼의 검증 결과 확인 전 공개 정식 릴리스로 표시하지 않는다. 코드서명·공증·인스톨러 제작은 아직 수행하지 않았다.

## 라이선스

WithCrypt 자체 코드는 MIT 라이선스다. 배포물에 LICENSE의 저작권 및 허가 고지를 포함한다. 의존성과 포함 글꼴은 각각의 라이선스·저작권 고지를 유지한다. [의존성 라이선스 기록](dependency-licenses.md)은 조사 목록이며 각 의존성의 라이선스 전문을 대체하지 않는다.

## 공통

Rust 1.99.0 stable, Cargo.lock을 사용한다. `cargo build --release --locked --workspace`로 CLI와 GUI를 함께 만든다. x86_64/aarch64를 지원 대상으로 하며 대상 CPU에서 두 스위트를 반드시 포함한다. 암호화가 가능한 하드웨어를 자동으로 다른 알고리즘으로 바꾸지 않는다.

## macOS

Xcode Command Line Tools가 필요하다. CLI는 `target/release/withcrypt`, GUI는 `target/release/withcrypt-desktop`다. `scripts/package-macos.sh`가 CLI와 `.app` 번들을 `dist/macos`에 만든다. Apple Silicon 빌드는 현지에서 검증하며 Intel은 별도 runner로 빌드해야 한다. 배포 시 Developer ID 서명과 notarization을 추가해야 하며 이 프로젝트는 인증서나 비밀번호를 포함하지 않는다.

## Windows

MSVC Rust 툴체인과 Visual Studio C++ Build Tools를 설치한다. `cargo build --release --locked --workspace` 후 `withcrypt.exe`와 `withcrypt-desktop.exe`를 배포한다. 시스템 `whoami.exe`, `icacls.exe`가 필요하다. 출력 파일은 내용을 쓰기 전에 현재 사용자 SID만 접근하도록 ACL을 적용한다. 실제 NTFS no-clobber, ACL, 취소·정리 및 한글 IME 검증은 Windows CI/수동 검증에서 확인한다.

탐색기 메뉴(ADR-004)는 두 가지 구현을 제공하지만 중복 표시를 막기 위해 하나만 활성화한다. Windows 11 기본 등록은 새 메뉴, 이전 Windows와 `--classic-only`는 클래식 메뉴를 사용한다. `withcrypt-desktop.exe`, `withcrypt_shell.dll`, `withcrypt-shell-setup.exe`, `WithCrypt.Shell.msix`를 같은 폴더에 둔다.

```powershell
.\scripts\build-windows.ps1                    # 릴리스 빌드 + 아이콘 + 서명 없는 테스트 패키지
.\target\release\withcrypt-shell-setup.exe register
.\target\release\withcrypt-shell-setup.exe status
.\target\release\withcrypt-shell-setup.exe unregister
```

`cargo build`만 직접 실행하면 탐색기에서 참조하는 `ShellIcon.ico`와 MSIX가 출력 폴더에 복사되지 않는다. 탐색기 통합을 시험할 때는 `build-windows.ps1`을 사용한다. 서명 배포물은 `-Publisher "CN=..." -CertificatePath <pfx>`를 함께 전달한다.

- 클래식 메뉴: 현재 사용자(HKCU)에 등록한다. 관리자 권한이 필요 없다. 실행 파일을 옮기면 다시 등록한다. Windows 11에서는 "더 많은 옵션 표시" 안에 나타난다. `register --classic-only`는 이것만 등록한다.
- Windows 11 새 메뉴: 패키징 스크립트가 만든 `WithCrypt.Shell.msix`를 `Add-AppxPackage -AllowUnsigned`로 설치한다. 서명 빌드는 `-Publisher "CN=..." -CertificatePath <pfx>`로 만들며 `-Publisher`는 인증서 Subject와 같아야 한다. Windows 10에서는 건너뛴다.

## Linux

Ubuntu 빌드 예:

```sh
sudo apt-get install build-essential pkg-config libx11-dev libxi-dev libxrandr-dev libxcursor-dev libxkbcommon-dev libwayland-dev libgl1-mesa-dev libdbus-1-dev fonts-noto-cjk zenity xdg-desktop-portal-gtk
cargo build --release --locked --workspace
```

GUI 런타임에 OpenGL, X11 또는 Wayland, D-Bus 및 데스크톱의 파일 선택 portal/Zenity가 필요하다. CLI는 GUI 런타임과 무관하게 사용한다. 배포 머신의 glibc 호환성을 위해 가장 오래 지원하는 배포판에서 빌드한다. AppImage/deb/rpm 패키지는 아직 만들지 않았다.

## CI

`.github/workflows/ci.yml`은 Windows/macOS/Linux에서 fmt, clippy, cargo test와 릴리스 빌드를 수행한다. 동일 고정 ESB fixture를 모든 OS에서 복호화하고 독립 Python 구현으로 대조한다. 성공한 실행은 CLI/GUI 바이너리를 artifact로 보관한다. 현재 디렉터리는 처음부터 Git 저장소가 아니었으므로 원격 push나 CI 실행을 수행한 것으로 간주하지 않는다.

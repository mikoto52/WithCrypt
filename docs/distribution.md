# 빌드 및 배포

각 플랫폼의 검증 결과 확인 전 공개 정식 릴리스로 표시하지 않는다. 코드서명·공증·인스톨러 제작은 아직 수행하지 않았다.

## 라이선스

WithCrypt 자체 코드는 GPL-3.0-or-later다. 배포물에 LICENSE를 포함하고, 바이너리를 배포할 때는 해당 버전의 대응 소스와 빌드 스크립트도 GPL 조건에 따라 제공한다. 의존성의 저작권·라이선스 고지도 유지한다.

## 공통

Rust 1.99.0 stable, Cargo.lock을 사용한다. `cargo build --release --locked --workspace`로 CLI와 GUI를 함께 만든다. x86_64/aarch64를 지원 대상으로 하며 대상 CPU에서 두 스위트를 반드시 포함한다. 암호화가 가능한 하드웨어를 자동으로 다른 알고리즘으로 바꾸지 않는다.

## macOS

Xcode Command Line Tools가 필요하다. CLI는 `target/release/withcrypt`, GUI는 `target/release/withcrypt-desktop`다. `scripts/package-macos.sh`가 CLI와 `.app` 번들을 `dist/macos`에 만든다. Apple Silicon 빌드는 현지에서 검증하며 Intel은 별도 runner로 빌드해야 한다. 배포 시 Developer ID 서명과 notarization을 추가해야 하며 이 프로젝트는 인증서나 비밀번호를 포함하지 않는다.

## Windows

MSVC Rust 툴체인과 Visual Studio C++ Build Tools를 설치한다. `cargo build --release --locked --workspace` 후 `withcrypt.exe`와 `withcrypt-desktop.exe`를 배포한다. NTFS의 하드링크와 시스템 `whoami.exe`, `icacls.exe`가 필요하다. Windows 임시 평문은 현재 사용자 SID만 접근하도록 ACL을 적용하고 그 ACL을 최종 파일에 유지한다. 실제 NTFS no-clobber, ACL, 취소·정리 및 한글 IME 검증은 Windows CI/수동 검증에서 확인한다. FAT 계열 등 하드링크 미지원 볼륨은 오류를 낸다.

## Linux

Ubuntu 빌드 예:

```sh
sudo apt-get install build-essential pkg-config libx11-dev libxi-dev libxrandr-dev libxcursor-dev libxkbcommon-dev libwayland-dev libgl1-mesa-dev libdbus-1-dev fonts-noto-cjk zenity xdg-desktop-portal-gtk
cargo build --release --locked --workspace
```

GUI 런타임에 OpenGL, X11 또는 Wayland, D-Bus 및 데스크톱의 파일 선택 portal/Zenity가 필요하다. CLI는 GUI 런타임과 무관하게 사용한다. 배포 머신의 glibc 호환성을 위해 가장 오래 지원하는 배포판에서 빌드한다. AppImage/deb/rpm 패키지는 아직 만들지 않았다.

## CI

`.github/workflows/ci.yml`은 Windows/macOS/Linux에서 fmt, clippy, cargo test와 릴리스 빌드를 수행한다. 동일 고정 ESB fixture를 모든 OS에서 복호화하고 독립 Python 구현으로 대조한다. 성공한 실행은 CLI/GUI 바이너리를 artifact로 보관한다. 현재 디렉터리는 처음부터 Git 저장소가 아니었으므로 원격 push나 CI 실행을 수행한 것으로 간주하지 않는다.

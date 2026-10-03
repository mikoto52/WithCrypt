# ADR-002: eframe + egui + rfd

날짜: 2026-10-03. 코어·CLI의 두 스위트 테스트와 독립 벡터 대조 이후 GUI를 추가했다.

선택: eframe/egui 0.36.2, rfd 0.17.2. Rust 네이티브 이벤트 루프에서 같은 코어를 호출할 수 있고 Windows/macOS/Linux를 지원한다. MIT OR Apache-2.0(eframe/egui), MIT(rfd) 라이선스를 검토했다. OpenGL glow 렌더러를 사용하고 네트워크 inspection, 웹뷰, persistence 기능은 켜지 않는다.

검토한 대안: [Iced](https://github.com/iced-rs/iced)는 MIT 라이선스의 다른 Rust 후보지만 이 앱의 작은 단일 작업 폼에는 egui의 입력/레이아웃으로 충분하다. [Slint](https://slint.dev/pricing)는 GPLv3·Royalty-Free·상용 선택지의 조건과 당시 미결정이었던 프로젝트 라이선스의 조합을 추가 검토해야 하므로 이번 선택에서 제외했다. Tauri는 웹뷰와 별도 프런트엔드 배포가 필요해 현재 단일 Rust 코드베이스 목표에서 선택하지 않았다.

접근성은 eframe의 AccessKit 기능을 명시적으로 켠다. 한글 입력은 winit/egui의 IME 경로를 사용하고 OS의 Apple SD Gothic Neo/Malgun Gothic 또는 Linux Noto CJK/Nanum 글꼴을 로드한다. 글꼴 파일을 프로젝트에 복제하거나 재배포하지 않는다. rfd의 네이티브 파일 선택을 사용하며 실제 PathBuf를 별도 보관하여 비 UTF-8 경로를 표시 문자열로 손실 변환하지 않는다.

지원 API가 존재하는 것과 VoiceOver/NVDA/Orca 및 한글 조합 입력이 각 OS에서 완전히 검증된 것은 다르다. 플랫폼 수동 검증 항목은 validation.md에 기록한다. OS 글꼴이 없는 Linux에서는 배포 패키지에 fonts-noto-cjk 의존성이 필요하다.

KDF와 스트리밍은 작업 스레드 하나에서 실행한다. 진행률은 크기 제한 없는 메시지 큐 대신 Mutex의 최신 상태 한 개로 공유하고, 결과만 채널로 보낸다. 창을 닫을 때 작업을 취소하고 정리 완료를 기다린다. 완료 표시는 파일 API의 검증·커밋 성공 이후에만 나타난다.

공식 문서: [eframe 기능과 접근성](https://docs.rs/eframe/0.36.2/eframe/), [egui 플랫폼/IME](https://github.com/emilk/egui), [rfd 플랫폼/다이얼로그](https://docs.rs/rfd/0.17.2/rfd/).

실제 CLI PTY 시험에서 macOS의 대소문자 비구분 파일시스템에서 `withcrypt`와 `WithCrypt`가 동일 경로가 되는 충돌을 발견했다. GUI 바이너리는 `withcrypt-desktop`으로 분리하고 앱 번들·창·제품명은 WithCrypt로 유지한다. Windows에서도 같은 충돌을 방지한다.

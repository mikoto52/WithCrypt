# ADR-001: ESB v1 구현과 의존성

날짜: 2026-10-03. Agent.md의 암호 바이트 정의는 변경하지 않는다.

- Rust 1.99.0 stable을 설치해 실제 빌드했다. 더 낮은 버전을 검증하지 않았으므로 MSRV도 1.99로 선언한다.
- RustCrypto의 같은 aead 0.5 계열을 사용하는 aes-gcm 0.10.3/chacha20poly1305 0.10.1과 argon2 0.5.3, hkdf 0.12.4, hmac 0.12.1, sha2 0.10.9를 선택했다. 최신 메이저 전환은 별도 호환성 검증 후 진행한다. 각 선택 버전의 공식 docs.rs API·라이선스·보안 주의사항을 확인했다. 정확한 모든 전이 버전은 Cargo.lock에 기록한다.
- 암호 의존성은 대체로 MIT OR Apache-2.0, Argon2는 MIT OR Apache-2.0 계열 라이선스를 사용한다. 라이선스 전체 목록은 `cargo metadata`에서 확인한다. WithCrypt 자체 라이선스는 미결정이며 이를 의존성 라이선스와 혼동하지 않는다.
- files 모듈을 코어의 독립된 파일 API로 둔다. CLI와 GUI가 같은 no-clobber·입력 변경·정리 정책을 재사용한다. 스트림 코어는 터미널·GUI·전역 로거에 의존하지 않는다.
- basename은 플랫폼 간 경로 탈출을 막기 위해 구분자, 콜론, NUL, 점/공백으로 끝나는 이름 및 Windows 예약 이름을 거부한다. 작성 시 그런 파일명과 비 UTF-8 파일명은 빈 메타데이터로 생략한다. 파일 내용은 처리한다. 이 추가 제약은 그러한 META를 가진 제3자 작성기의 ESB 수용 범위를 좁히지만 암호 바이트 정의를 바꾸지 않는다.
- NamedTempFile의 일반 persist 대신 명시적 hard_link로 최종 이름을 배타 생성한다. Unix 디렉터리도 fsync한다. Windows 임시 디렉터리 ACL은 시스템 도구로 제한하고 실패하면 작업을 중단한다. 하드링크를 지원하지 않는 볼륨에서 가용성을 위해 보안을 낮추지 않는다.
- 운영체제 별 배포 대상 CPU는 x86_64/aarch64이며, 실제 현지 검증은 macOS aarch64에서 수행한다. 다른 OS CI의 실행 결과를 대신 주장하지 않는다.

공식 API: [AES-GCM](https://docs.rs/aes-gcm/0.10.3/), [XChaCha](https://docs.rs/chacha20poly1305/0.10.1/), [Argon2](https://docs.rs/argon2/0.5.3/), [HKDF](https://docs.rs/hkdf/0.12.4/), [HMAC](https://docs.rs/hmac/0.12.1/), [tempfile 권한](https://docs.rs/tempfile/latest/tempfile/struct.Builder.html#method.permissions).

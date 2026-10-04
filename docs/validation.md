# 검증 기록

날짜: 2026-10-03. 실제 실행 환경: Apple M5, 32 GiB RAM, macOS 26.6.2 (25G83), aarch64, Rust 1.99.0. 처음에는 Agent.md만 있었으며 Git 저장소/원격 CI가 없었다.

## 실행한 검증

- GUI 작성 전에 코어 8개 테스트 그룹과 CLI 인자 테스트가 통과했다. 이후 파일 보호·GUI 작업 테스트를 보강했다.
- 최종 워크스페이스 테스트: 코어 11개 그룹, CLI 단위/프로세스 2개, GUI 2개. 각 그룹은 여러 크기와 두 스위트에 반복 적용한다.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` 통과.
- `cargo build --release --workspace --locked` 및 macOS `.app` 패키징 성공.
- 독립 Python 검증: cryptography 50.0.0의 Argon2id/AESGCM, PyCryptodome의 XChaCha20-Poly1305로 두 고정 벡터의 키·nonce·AAD·HMAC·평문·태그를 대조했다.
- CLI 실제 PTY에서 한글 비밀번호로 두 알고리즘의 암호화/검증/복호화, 잘못된 비밀번호 코드 3, 기존 출력 보호 코드 4를 확인했다. 빠른 비밀번호 입력에도 에코가 없고, Ctrl-C의 코드 130 및 종료 후 터미널 ECHO 복구를 확인했다.
- GUI를 실제 실행하여 한글 렌더링, 각 입력란과 알고리즘 선택, 접근성 트리 노출을 확인했다. GUI 작업 테스트는 두 스위트의 실제 백그라운드 암호화→검증→복호화, 헤더 표시, 비밀번호 필드 비우기와 출력 바이트 일치를 확인한다.
- RustSec 공지 1,290개에 대해 최종 Cargo.lock의 의존성 425개를 `cargo audit`로 검사하여 알려진 취약점 보고 없이 종료했다. 이는 보안 감사나 향후 취약점 부재를 뜻하지 않는다.

보안 테스트에는 빈 파일·1바이트·청크 경계·복수 청크·0..255 데이터, 한글·공백·결합문자 비밀번호, 무작위 salt/prefix, 잘못된 비밀번호, suite 변조와 fallback 금지, 헤더/레코드/태그/FINAL 변조, 삭제·중복·순서 오류·타 파일 레코드 삽입, trailing bytes, 인증된 잘못된 FINAL 크기/개수/HMAC, 짧은 DATA 뒤 DATA, 악의적 길이·인덱스 overflow, Interrupted·짧은 read·부분 write·쓰기 실패·취소가 포함된다. 파일 테스트는 기존 출력·동일 파일·하드링크·심볼릭 링크, 권한 오류, 최종 생성 경합, 입력 변경, 인증 실패·취소 후 미완성 출력 삭제, 처리 중 바뀐 출력 경로의 보존과 Unix 출력 권한을 확인한다.

## 대용량 스트리밍 측정

Release 빌드의 `stress` 예제가 생성형 0xA5 스트림을 용량 1인 메모리 파이프로 암호화하면서 전체 복호화/검증한다. 원본과 암호문 전체를 저장하지 않는다. 저장장치 I/O가 없으므로 실제 SSD 처리량을 의미하지 않는다. 같은 호스트에서 빌드/UI 검증도 진행했으므로 아래 결과는 통제된 성능 비교가 아닌 실행 기록이다.

| 입력 크기 | 알고리즘 | 암호화+전체 검증 시간 | 처리율 |
|---|---|---:|---:|
| 4,294,967,297 바이트 (4 GiB+1) | XChaCha20-Poly1305 | 24.815초 | 165.1 MiB/s |
| 4,294,967,297 바이트 | AES-256-GCM | 28.011초 | 146.2 MiB/s |
| 34,359,738,369 바이트 (물리 RAM+1) | XChaCha20-Poly1305 | 114.039초 | 287.3 MiB/s |
| 34,359,738,369 바이트 | AES-256-GCM | 221.155초 | 148.2 MiB/s |

RAM 초과 실행의 `/usr/bin/time -l` 최대 RSS: **85,835,776 바이트 (81.86 MiB)**, peak memory footprint 85,197,184바이트, swaps 0. 두 스위트 모두 FINAL/HMAC/EOF와 64비트 원본 크기 검증까지 성공했다. 한 번에 파일 전체를 할당하지 않는 동작을 확인했다. 스트레스 측정 후 암호 바이트 정의는 변경하지 않았으며 파일 입출력/터미널 보강은 별도 테스트했다.

## 발견하여 수정한 문제

1. Clap enum 기본 이름이 요구된 `aes-256-gcm`과 달라 명시적 옵션 이름을 지정했다.
2. macOS의 대소문자 비구분 파일시스템에서 CLI `withcrypt`와 GUI `WithCrypt`가 충돌했다. 실제 바이너리 이름을 `withcrypt`/`withcrypt-gui`로 분리하고 GUI 제품명과 앱 번들은 WithCrypt로 유지했다.
3. 프롬프트 직후 즉시 입력하면 rpassword가 raw mode를 적용하기 전 에코될 수 있었다. crossterm으로 안내문 표시 전에 에코를 끄고, 성공/오류/취소에 터미널 상태를 복구한다.
4. tempfile 디렉터리의 기본 권한에 의존하지 않고 Unix에서 생성 시 0700을 지정했다. AES 확장 키의 zeroize 기능도 명시적으로 켰다.

## 미실행 및 배포 전 확인 사항

- Windows/Linux의 실제 빌드·런타임·파일 ACL 검증: CI 구성만 작성했다. 원격 실행 결과는 없다.
- Windows NVDA/IME, macOS VoiceOver의 전체 키보드 흐름, Linux Orca/IME: 미검증. 한글 붙여넣기/렌더링과 IME 조합 입력은 구분해야 한다.
- macOS GUI의 직접 자동 클릭/입력은 포커스 동기화 문제로 종단간 성공을 확인하지 못했다. 실행·화면은 확인했고 백그라운드 작업 테스트는 통과했다.
- 파서 fuzz 대상은 추가했지만 장시간 libFuzzer 캠페인은 수행하지 않았다. `cargo +nightly fuzz run headers`는 별도 선택 검증이며 일반 빌드에 nightly를 요구하지 않는다.
- 실제 디스크 가득 참, 전원 손실·강제 종료의 crash consistency, 악성 파일시스템, TB 단위 SSD 처리량은 측정하지 않았다. 쓰기 오류는 테스트 Writer로 주입했다.
- 코드서명·notarization·Windows 인스톨러·Linux 패키지, 독립 보안 감사는 남아 있다. 프로젝트 라이선스는 이후 의존성 확인과 사용자 결정에 따라 MIT로 변경했다.

## 2026-10-03 — 원본 파일명 복원 및 저장 대화상자 변경

macOS 로컬에서 `cargo test --workspace --locked` 17개 테스트(코어 13, CLI 2, GUI 2), `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo fmt --all -- --check`를 통과했다. 두 알고리즘의 기존 고정 벡터를 유지했다.

추가 검증: 암호화 기본 경로, 한글·공백·다중 확장자 원래 이름 복원, META 준비와 저장 사이 KDF 1회, 기존 파일·원본 보호, 저장 선택 중 입력 변경, META가 정상이어도 FINAL 변조 시 미완성 출력 삭제, 인증된 악성 basename 거부, 빈 이름의 기존 파일에 명시적 저장 이름 지정.

GUI 테스트는 저장 대화상자 함수를 주입하여 두 알고리즘의 기본 파일명·사용자 이름 변경·취소·잘못된 비밀번호 때 대화상자 미호출을 확인했다. 실제 OS 대화상자를 직접 클릭하는 검증은 이번 변경에서 실행하지 않았다. Windows/Linux 실행도 이번 검증 범위에 포함하지 않는다.

`WITHCRYPT_TEST_BINARY=/Users/akira/sources/WithCrypt/target/debug/withcrypt python3 tests/cli_smoke.py`로 실제 PTY에서 두 알고리즘 암호화·검증·디렉터리 복호화, 비밀번호 에코 방지·오류·Ctrl-C·덮어쓰기 방지, 기본 암호화 파일명 및 출력 파일 경로의 디렉터리 오용 거부를 통과했다. PTY 접근은 샌드박스 밖에서 실행했다. 릴리스 앱 패키징 및 커밋·푸시는 수행하지 않았다.

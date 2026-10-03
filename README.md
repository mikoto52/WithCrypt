# WithCrypt

Rust 기반 스트리밍 파일 암호화 프로그램. CLI `withcrypt`와 데스크톱 앱 `WithCrypt`가 같은 ESB v1 코어 및 파일 트랜잭션을 사용합니다.

- XChaCha20-Poly1305(기본), AES-256-GCM 선택. 복호화·검증은 헤더에서 자동 판별합니다.
- Argon2id + HKDF-SHA256, 레코드 AEAD, 암호화된 전체 원본 HMAC-SHA256.
- 4 MiB 청크. 파일 전체를 메모리에 올리지 않습니다.
- 원본 보존, 기존 출력 보호, 완전 검증 후 원자적 새 파일 생성.
- GUI는 작업 하나를 별도 스레드에서 처리하며 비밀번호 확인·표시·진행률·취소를 제공합니다.

## 빌드와 실행

Rust 1.99.0 stable을 사용합니다. `rust-toolchain.toml`과 `Cargo.lock`을 함께 유지하세요. MSRV는 검증 범위를 분명히 하기 위해 동일한 1.99입니다. 기본 `cargo build`는 CLI와 코어만 빌드합니다.

```sh
cargo build --release --locked -p withcrypt-cli
cargo run --release --locked -p withcrypt-desktop

./target/release/withcrypt encrypt original.bin # original.bin.esb 생성
./target/release/withcrypt encrypt original.bin --output aes.esb --algorithm aes-256-gcm
mkdir restored
./target/release/withcrypt decrypt original.bin.esb --output restored
./target/release/withcrypt verify original.bin.esb
```

비밀번호는 터미널에서 에코 없이 입력합니다. 암호화 때 두 번 입력합니다. 공백과 유니코드를 그대로 사용하며 빈 비밀번호는 거부합니다. 인자·환경변수·stdin 파이프로 비밀번호를 전달하는 기능은 없습니다. 비대화형 실행은 즉시 오류를 반환합니다. 작업 중 Ctrl-C로 취소할 수 있으며 Argon2 실행 중 취소는 KDF가 끝나면 반영됩니다.

GUI의 파일 선택 버튼은 유니코드로 표현할 수 없는 실제 파일 경로도 보존합니다. Linux에서 한글 표시용 `fonts-noto-cjk` 또는 `fonts-nanum`을 설치하세요. GUI가 읽는 헤더 알고리즘은 인증 전에는 미검증 정보로 표시됩니다. 암호화·복호화 화면에 출력 경로 입력란은 없으며 시작을 누르면 저장 대화상자를 표시합니다. 복호화는 입력한 비밀번호로 암호화된 헤더의 원본 파일명을 먼저 인증·복호화하고, 확장자를 포함한 이름을 대화상자의 기본값으로 채웁니다. 사용자가 이름과 위치를 바꿀 수 있습니다. 잘못된 비밀번호이면 저장 대화상자를 열지 않습니다.

CLI 암호화의 `--output`은 선택 사항이며 생략하면 원본과 같은 디렉터리에 `<입력파일명>.esb`를 만듭니다. 복호화의 `--output`은 필수이며 **기존 출력 디렉터리**를 지정합니다. 그 안에 인증된 원본 파일명으로 복원합니다. 같은 이름의 파일이 있으면 덮어쓰지 않고 실패합니다. 원본 이름이 없는 기존 ESB나 이식 불가능한 이름을 생략한 ESB는 GUI에서 저장 이름을 지정하세요(기본값 `decrypted.bin`).

## 종료 코드

| 코드 | 의미 |
|---|---|
| 0 | 전체 처리 성공 |
| 2 | 인자, 빈 비밀번호, 미지원 포맷 |
| 3 | 비밀번호 오류 또는 인증·무결성 실패 |
| 4 | I/O, 자원, 기존 출력, 입력 변경, 정리 실패 |
| 130 | 사용자 취소 |

## 검증

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 tests/fixtures/check_vectors.py
cargo run --release --locked -p withcrypt-core --example stress -- 4294967297
```

독립 벡터 검증에는 Python `cryptography>=44` 및 `pycryptodome`가 필요합니다. 일반 Rust 테스트에는 Python이 필요하지 않습니다. stress 예제는 생성형 입력을 용량 제한 파이프로 암호화하고 즉시 전체 검증하므로 실제 대용량 파일을 생성하지 않습니다. RAM 초과 테스트는 인자에 물리 RAM보다 큰 바이트 수를 지정하세요.

상세 실행 결과와 미검증 항목은 [검증 기록](docs/validation.md), OS별 빌드·배포는 [배포 문서](docs/distribution.md)를 참조하세요. CI 설정의 존재는 세 OS에서 이미 통과했다는 뜻이 아닙니다.

## 보안과 범위

자체 ESB 컨테이너는 외부 보안 감사를 받지 않았습니다. 크기는 숨기지 않으며 약한 비밀번호의 오프라인 추측, 악성 OS, 스왑·덤프·SSD의 흔적을 완전히 방어하지 않습니다. 원본 삭제·덮어쓰기·보안 삭제, 폴더, 압축, 비밀번호 복구 서버, 네트워크·텔레메트리는 구현하지 않습니다. 파일 데이터 스트림 외 ACL·xattr·ADS·리소스 포크 등은 보존하지 않습니다.

자세한 [포맷](docs/format-v1.md), [위협 모델](docs/security.md), [설계 결정](docs/adr/001-implementation.md)을 확인하세요. 코어의 저수준 `decrypt`는 전체 성공 전에 인증된 청크를 Writer에 전달하므로 일반 파일 작업은 `files::run`, `files::decrypt_into` 또는 `PreparedDecryption::save`의 파일 트랜잭션을 사용하세요.

WithCrypt는 **MIT License**로 배포됩니다. 라이선스 전문은 [LICENSE](LICENSE)를 참조하세요. 의존성에는 각각의 라이선스가 적용됩니다.

의존성 라이선스 확인 결과와 선택 사항은 [의존성 라이선스 기록](docs/dependency-licenses.md)에 정리했습니다.

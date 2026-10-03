# ESB v1 명세

상태: WithCrypt 0.1.0 구현, 2026-10-03. 아래 바이트 정의는 Agent.md와 동일하다.

## 5. 암호 구성 — v1 기본안

두 스위트를 모두 구현한다: suite_id=1은 XChaCha20-Poly1305, suite_id=2는 AES-256-GCM이다. 단일 파일에는 선택한 한 스위트만 사용한다. 이중 암호화나 자동 알고리즘 전환은 구현하지 않는다. 암호 원시 연산을 직접 구현하지 말고 유지보수되는 라이브러리를 사용한다.

| 항목 | 기본안 |
| --- | --- |
| 비밀번호 KDF | Argon2id, version 0x13 |
| Argon2 파라미터 | m=65536 KiB, t=3, p=4, 출력 32바이트 |
| 파일 salt | OS CSPRNG에서 새로 생성한 16바이트 |
| 키 분리 | HKDF-SHA256 |
| AEAD suite 1 (기본) | XChaCha20-Poly1305, 키 32바이트, nonce 24바이트, tag 16바이트 |
| AEAD suite 2 | AES-256-GCM, 키 32바이트, nonce 12바이트, tag 16바이트; 레코드별 키 파생 |
| 원본 HMAC | HMAC-SHA256, 전체 32바이트 저장 |
| 기본 청크 크기 | 4 MiB |

Argon2 설정은 RFC 9106의 메모리 제약 환경 권고를 출발점으로 사용한다. 실제 처리 시간은 측정한다. 메모리 부족 시 임의로 약한 KDF로 내려가지 말고 오류를 반환한다. v1은 위 KDF 프로파일만 허용하여 변조된 헤더의 과도한 자원 요청을 차단한다. 다른 프로파일 추가는 명세와 테스트 변경을 동반한다.

공통 KDF 및 suite 1 키 파생을 정확히 고정한다. suite 1의 기존 바이트 정의는 유지한다:

```text
password_bytes = 입력 문자열의 UTF-8 바이트 (정규화·trim 없음)
master = Argon2id(password_bytes, salt, m=65536, t=3, p=4, out=32)
prk = HKDF-Extract-SHA256(salt=salt, IKM=master)
k_enc = HKDF-Expand-SHA256(prk, info=ASCII("ESB/v1/encryption"), L=32)
k_mac = HKDF-Expand-SHA256(prk, info=ASCII("ESB/v1/plaintext-hmac"), L=32)
original_hmac = HMAC-SHA256(k_mac, original_file_bytes)
```

suite 2에서는 같은 `prk`로부터 아래처럼 분리한다. `index`는 META와 FINAL을 포함하는 전역 레코드 인덱스다:

```text
k_enc_i = HKDF-Expand-SHA256(prk,
    info=ASCII("ESB/v1/aes-256-gcm/record-key") || nonce_prefix[16] || LE64(index), L=32)
k_mac = HKDF-Expand-SHA256(prk,
    info=ASCII("ESB/v1/aes-256-gcm/plaintext-hmac"), L=32)
original_hmac = HMAC-SHA256(k_mac, original_file_bytes)
```

AES-GCM은 파일 전체를 하나의 키로 처리하지 않고 **매 레코드마다 다른 키**를 파생한다. 각 키로 최대 한 레코드(평문 최대 4 MiB)만 암호화하여 TB 파일에서 한 GCM 키의 누적 사용량이 커지는 문제를 피한다. META·DATA·FINAL에 모두 적용한다. 파일마다 Argon2id는 한 번만 실행하고 가벼운 HKDF-Expand만 레코드마다 실행한다. 파생 키는 해당 레코드 처리 후 지운다.

이 키 사용량 정책은 자체 포맷 설계이며 전체 보안의 증명은 아니다. 구현 시 GCM 라이브러리 한도와 다중 키 환경의 전체 인증 한계를 검토하여 security.md에 기록한다. 단일 메시지 제한과 키별 누적 사용량 제한을 혼동하지 않는다.

info 문자열은 NUL 종료하지 않는다. 비밀번호는 빈 문자열을 거부하고, 암호화 시 두 번 입력하여 확인한다. 공백과 유니코드를 임의로 바꾸지 않는다. 콘솔 입력의 줄 종료 문자는 비밀번호에 포함하지 않는다. 키와 비밀번호의 불필요한 복사를 피하고 zeroize 계열 타입으로 수명을 제한한다. 완전한 메모리 삭제를 보장한다고 표현하지 않는다.

파일 salt 외에 OS CSPRNG에서 독립적인 16바이트 nonce_prefix를 생성한다. 난수 생성 실패는 즉시 실패다. 재시도하는 암호화 작업에서는 salt와 prefix를 모두 새로 생성한다. 테스트용 결정적 난수 경로는 프로덕션 CLI에 노출하지 않는다.

## 6. ESB v1 바이너리 포맷

다음 레이아웃을 `docs/format-v1.md`에 옮기고 테스트 벡터로 고정한다. 모든 정수는 unsigned little-endian이다. Rust struct 메모리를 그대로 직렬화하지 않는다.

### 공개 헤더 H — 정확히 64바이트

| offset | 길이 | 필드 / 값 |
| --- | --- | --- |
| 0 | 8 | magic: `45 53 42 00 0D 0A 1A 0A` |
| 8 | 2 | format_version = 1 |
| 10 | 2 | header_len = 64 |
| 12 | 2 | suite_id = 1 (XChaCha20-Poly1305) 또는 2 (AES-256-GCM) |
| 14 | 2 | flags = 0 |
| 16 | 4 | argon2_memory_kib = 65536 |
| 20 | 4 | argon2_iterations = 3 |
| 24 | 4 | argon2_lanes = 4 |
| 28 | 4 | chunk_size = 4194304 |
| 32 | 16 | salt |
| 48 | 16 | nonce_prefix |

v1은 지정된 헤더 크기·flags·스위트·KDF·청크 크기만 허용한다. 미지원 값은 거부한다. KDF 실행 전 확인하며 헤더값에 따른 임의 메모리 할당을 금지한다. 헤더는 첫 인증 성공 전까지 신뢰할 수 없다.

### 레코드

```text
R = type:u8 || index:u64 || plaintext_len:u32      # 정확히 13바이트
nonce_suite1 = nonce_prefix[16] || LE64(index)    # 24바이트, k_enc 사용
nonce_suite2 = nonce_prefix[0..4] || LE64(index)   # 12바이트, k_enc_i 사용
AAD = ASCII("ESB/v1/record") || H[64] || R[13]
record = R || ciphertext[plaintext_len] || tag[16]
```

AES의 prefix 슬라이스는 첫 4바이트이며 나머지 12바이트도 레코드 키 파생과 헤더 인증에 포함된다. 헤더의 16바이트 nonce_prefix는 두 스위트 모두 새 난수로 채운다. 스위트별 키·nonce 크기를 타입과 enum으로 분리하여 혼용을 방지한다. suite_id는 H의 일부이므로 AAD에 포함된다. 인증 실패 시 다른 알고리즘으로 재시도하지 않으며 미지원 suite_id도 거부한다.

길이 표기는 바이트 수다. AEAD API가 ciphertext와 tag를 결합해서 반환하면 같은 온디스크 배열을 유지한다. 헤더를 재직렬화한 값 대신 파일에서 읽은 정확한 H 바이트를 AAD로 사용한다.

| type | 역할 | 규칙 |
| --- | --- | --- |
| 1 | META | 반드시 첫 레코드, index=0 |
| 2 | DATA | index=1부터 연속 증가, 각 1..4194304바이트 |
| 3 | FINAL | DATA 다음 인덱스, 반드시 한 번, 평문 정확히 48바이트 |

META 평문은 `filename_len:u16 || filename_utf8[filename_len]`이다. 파일명 길이는 최대 4096바이트이며 전체 평문 길이는 정확히 2+filename_len이다. 원본의 확장자를 포함한 basename을 암호화하여 저장한다. 논리적인 ESB 헤더는 공개 H와 암호화된 META로 구성하며, 전체 구조는 `H[64] || META || DATA* || FINAL`이다. 기존 v1의 바이트 배치와 암호 파생은 변경하지 않는다. UTF-8로 표현되지 않는 이름은 길이 0으로 저장하고 사용자에게 알리며 파일 내용은 처리 가능해야 한다. 원본 절대 경로는 저장하지 않는다. META는 빈 파일에도 존재하므로 이 단계에서 비밀번호 오류를 조기에 검출한다.

DATA는 원본 바이트 그대로다. 마지막 DATA를 제외한 DATA는 반드시 청크 크기와 같아야 한다. 짧은 DATA 다음에는 FINAL만 올 수 있다. 빈 원본은 DATA 없이 META와 FINAL로 표현한다. 청크 크기의 정확한 배수라도 빈 DATA를 추가하지 않는다.

FINAL 평문은 다음과 같다:

```text
original_size:u64 || data_chunk_count:u64 || original_hmac[32]
```

수신자는 index를 파일 값에 맞춰 점프하지 않고 예상 인덱스와 비교한다. META/DATA/FINAL 전체에서 같은 키와 nonce를 재사용하지 않는다. 인덱스 및 길이 덧셈은 checked arithmetic으로 처리한다. FINAL 인덱스가 u64 범위를 초과하면 실패한다.

FINAL의 AEAD 인증, 실제 누적 크기, DATA 개수, 상수 시간 HMAC 검증이 모두 성공해야 한다. FINAL 뒤에는 EOF만 허용하고 추가 바이트를 거부한다. 레코드 삭제·복제·교환·타 파일 레코드 삽입·FINAL 누락은 모두 실패해야 한다.


## 검증 순서와 구현 규칙

64바이트만 읽어 Header::parse로 고정 필드를 검사한다. KDF 전 헤더 기반 가변 할당을 하지 않는다. META를 먼저 인증하고 DATA의 연속 인덱스·길이·순서를 확인한다. 각 청크는 인증 후에만 출력에 기록한다. FINAL 인증, 실제 크기와 청크 수, HMAC verify_slice, EOF를 모두 확인한다. 파일 API는 최종 경로를 `create_new`로 배타 생성해 직접 쓰고, 입력 변경 검사와 flush/sync까지 성공해야 결과를 남긴다. 실패하면 자신이 만든 미완성 파일을 삭제한다(ADR-005).

META 인증 후 원본 파일명을 복원에 사용한다. CLI는 사용자가 지정한 기존 디렉터리에 basename을 결합하고 GUI는 저장 대화상자의 기본 파일명으로 사용한다. 전체 파일의 인증 성공 전 결과를 확정하지 않는다. 작성기는 UTF-8이 아니거나 이식 가능한 basename 규칙을 만족하지 않는 이름을 빈 문자열로 생략한다. 독자는 구분자, 경로 탈출, 제어 문자, `:<>"|?*`, 끝의 공백·마침표, Windows 예약 basename을 거부한다. 이름이 빈 기존 파일은 CLI 자동 복원을 거부하며 GUI에서 명시적으로 파일명을 선택할 수 있다. 이 부가 제약은 ADR-001에 명시한다.

고정 벡터: tests/fixtures/suite-{1,2}.hex. 각 JSON에 비밀이 아닌 테스트 비밀번호 바이트, master, PRK, HMAC 키, 레코드 키/nonce/AAD/평문/암호문과 전체 컨테이너 SHA-256을 기록한다. SHA-256은 공개 테스트 벡터 설명용으로만 존재하며 실제 ESB에는 저장되지 않는다. check_vectors.py가 OpenSSL 및 PyCryptodome로 독립 검증한다.

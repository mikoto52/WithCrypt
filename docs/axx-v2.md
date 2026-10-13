# AxCrypt 2.x 복호화

파일 형식 4.0을 공개 명세와 사용자가 생성한 Xecrets CLI 샘플로 대조해 Rust에서 독립 구현했다. AxCrypt/Xecrets 프로그램 소스나 실행 파일을 제품에 포함하지 않는다.

## 사용법

```sh
withcrypt decrypt old.axx --output restored-directory
withcrypt verify old.axx
```

CLI 및 GUI에서 AxCrypt 1.x/2.x를 파일 헤더로 구분한다. GUI는 무결성 확인 후 저장 대화상자에 원본 파일명을 표시하고 이름·위치를 변경할 수 있다. 검증은 평문 파일을 만들지 않는다. 탐색기 복호화 메뉴는 저장 대화상자 없이 원본 폴더에 인증된 원본 파일명으로 복원한다.

## 지원 범위

- AxCrypt 파일 형식 4.0, 비밀번호로 보호한 AES-128/AES-256 키 슬롯. 실제 제공 샘플 검증은 Xecrets CLI가 생성한 AES-256 파일에 한정된다. 실제 AxCrypt 제품과 AES-128 샘플은 추가 검증이 필요하다.
- PBKDF2-HMAC-SHA512, 반복 AES 키 래핑, XOR 카운터 CTR, HMAC-SHA512, zlib 압축 해제, UTF-8 파일명과 비밀번호.
- 여러 데이터 블록과 빈 파일 지원. 데이터 블록 경계를 넘겨도 CTR 위치가 이어진다.
- RSA 개인키만으로 여는 공유 파일, 다른 암호 알고리즘, ASCII armor, 여러 파일을 연결한 스트림은 지원하지 않는다.
- 전체 메타데이터 최대 1 MiB/256개, 비밀번호 키 슬롯 최대 8개, 키 래핑·PBKDF2 반복은 각 최대 1,000,000회다. 제한 초과는 인증 전에 거부한다.

## 인증과 파일 안전성

파일 끝의 HMAC-SHA512를 전체 암호문 및 헤더와 비교한 후 파일명을 해석한다. 그다음 파일을 다시 읽어 64 KiB 단위로 복호화한다. 전체 파일이나 데이터 블록 목록을 메모리에 저장하지 않는다. 압축 해제 결과와 데이터 길이를 인증된 길이에 대조한다. ESB와 동일한 파일 트랜잭션으로 기존 파일을 보호하고 실패·취소 시 미완성 출력을 삭제한다.

## 명세와 실제 샘플의 차이

공개 PDF는 키 재료용 최대 필드 크기를 설명하지만, 제공된 AES-256 파일은 실제 키 32바이트와 IV 16바이트만 래핑한 56바이트 결과를 사용하고 나머지 Wrap 필드는 패딩이다. WrapSalt는 키 길이만큼 잘라 파생 키에 XOR한다.

PDF의 Algorithm Verifier는 16바이트 난수와 그 보수로 기술돼 있으나 Xecrets 샘플에는 동일한 16바이트가 두 번 들어 있다. 구현은 전체 HMAC 인증 이후 두 표현을 검사한다. 검증을 생략하지 않는다. 파일명은 실제 샘플에서 확인한 NUL 종료 UTF-8을 처리한다. PDF의 길이 접두어 표현은 실제 생성 샘플을 확보하기 전까지 지원 범위에 포함하지 않는다.

## 검증

`tests/fixtures/axcrypt-v2/`의 샘플 6개를 기존 `axcrypt-v1/original/`과 바이트 단위로 대조한다. 압축 텍스트, 한글 이름, 빈 파일, JPEG/ZIP, 여러 블록을 포함한다. 잘못된 비밀번호·변조·잘림·추가 데이터·과도한 반복·인증된 경로 탈출과 길이 불일치·취소·기존 출력 보호·작은 읽기 버퍼를 검사한다. GUI에서도 v1/v2 샘플의 복원·저장 이름 변경·검증·오류 처리를 검사한다. 쉘 모드의 원본 폴더 복원과 기존 출력 보호도 검사한다.

Windows 실기 테스트는 사용자 확인이 필요하다.

참고: [공식 AxCrypt v2 포맷 명세](https://axcrypt-download.s3.eu-north-1.amazonaws.com/downloads/AxCryptVersion2AlgorithmsandFileFormat.pdf), [Xecrets CLI 문서](https://github.com/xecrets/xecrets-cli/blob/main/docs/index.md).

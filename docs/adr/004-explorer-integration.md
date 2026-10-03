# ADR-004: Windows 탐색기 메뉴

날짜: 2026-10-03. 사용자 요구: 모든 파일(`.esb` 제외)에 암호화 메뉴, `.esb`에 복호화 메뉴를 표시하고, 메뉴로 실행하면 저장 위치를 묻지 않고 원본과 같은 폴더에 결과를 만든다.

## 결정

두 경로를 함께 제공한다. 둘 다 `withcrypt-desktop.exe --encrypt <파일>` 또는 `--decrypt <파일>`을 실행할 뿐이며 비밀번호와 파일 내용은 데스크톱 앱만 다룬다.

1. **클래식 메뉴(레지스트리)**: `withcrypt-desktop.exe --register-shell`이 HKCU에 동사를 등록하고 `--unregister-shell`이 제거한다. 관리자 권한과 unsafe 코드가 필요 없다. 암호화는 `HKCU\Software\Classes\*\shell\WithCrypt.Encrypt`에 `AppliesTo = NOT System.FileExtension:=.esb`로 등록한다. 복호화는 `SystemFileAssociations\.esb\shell\WithCrypt.Decrypt`에 등록하여 사용자가 지정한 `.esb` 기본 프로그램을 바꾸지 않는다. Windows 11에서는 "더 많은 옵션 표시" 안에 나타난다. 레지스트리 접근은 Microsoft의 안전한 `windows-registry` 크레이트를 사용한다.
2. **Windows 11 새 메뉴(COM)**: `withcrypt-shell` cdylib가 `IExplorerCommand`를 구현한다. sparse package(외부 위치 패키지)의 `desktop4:FileExplorerContextMenus`와 `com:SurrogateServer`로 등록한다. 모든 파일 형식(`*`)에 암호화, `.esb`에 복호화 동사를 걸고 `GetState`에서 확장자로 다시 거른다. 선택 항목이 16개를 넘으면 숨긴다. 각 항목마다 앱 창을 하나씩 연다. 패키지는 서명이 있어야 설치되므로 `scripts/package-windows-shell.ps1`이 makeappx/signtool로 만들고 `Add-AppxPackage -ExternalLocation`으로 설치한다.

메뉴 실행 모드의 앱은 대상 파일, 저장 폴더, 결과 이름, 비밀번호만 보여주는 작은 창이다. 암호화 결과는 `<원본파일명>.esb`, 복호화 결과는 인증된 META 파일명이며 원본과 같은 폴더에 저장한다. META 이름이 없는 오래된 ESB는 `decrypted.bin`이 된다. 같은 이름의 파일이 이미 있으면 덮어쓰거나 이름을 바꾸지 않고 오류로 중단한다. 저장 대화상자는 열지 않는다. 일반 실행(인자 없음)의 동작은 바뀌지 않는다.

## unsafe 예외

Agent.md는 자체 코드의 unsafe를 기본 금지한다. COM in-proc 서버는 `DllGetClassObject`/`DllCanUnloadNow` 내보내기, out-pointer 쓰기, Shell API 호출에 FFI가 필요해서 `withcrypt-shell` 크레이트 하나에만 예외를 둔다. 범위는 다음으로 제한한다.

- out-pointer는 null 검사 후에만 쓴다. 각 unsafe 블록에 `SAFETY` 근거를 남기고 `unsafe_op_in_unsafe_fn`을 거부한다.
- 이 DLL은 암호, 키, 파일 내용을 다루지 않는다. 선택 항목 경로를 읽고 같은 폴더의 `withcrypt-desktop.exe`를 실행하는 일만 한다.
- `withcrypt-core`, `withcrypt-cli`, `withcrypt-desktop`은 계속 `#![forbid(unsafe_code)]`다.

## 한계와 미검증

- COM 경로는 실제로 서명·설치해 탐색기에서 띄워 보지 않았다. 매니페스트는 `makeappx pack`의 스키마 검사를 통과했고, DLL 내보내기와 클래스 팩터리는 단위 테스트로 확인했다. sparse package가 실행 파일 매니페스트의 `msix` 정체성 요소 없이 메뉴만 등록하는지는 실제 설치에서 확인해야 한다.
- 개발용 자체 서명 인증서는 사용자가 신뢰 저장소에 넣어야 하고, 배포에는 신뢰된 코드 서명 인증서가 필요하다.
- 여러 파일을 선택하면 파일마다 비밀번호 창이 따로 뜬다. 일괄 처리는 v1 범위 밖이다.

공식 문서: [IExplorerCommand](https://learn.microsoft.com/windows/win32/api/shobjidl_core/nn-shobjidl_core-iexplorercommand), [외부 위치 패키지로 정체성 부여](https://learn.microsoft.com/windows/apps/desktop/modernize/grant-identity-to-nonpackaged-apps), [desktop4:FileExplorerContextMenus](https://learn.microsoft.com/uwp/schemas/appxpackage/uapmanifestschema/element-desktop4-fileexplorercontextmenus), [AppliesTo](https://learn.microsoft.com/windows/win32/shell/context-menu-handlers).

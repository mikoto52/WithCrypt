# ADR-004: Windows 탐색기 메뉴

날짜: 2026-10-03. 사용자 요구: 모든 파일(`.esb` 제외)에 암호화 메뉴, `.esb`에 복호화 메뉴를 표시하고, 메뉴로 실행하면 저장 위치를 묻지 않고 원본과 같은 폴더에 결과를 만든다.

## 결정

두 경로를 제공하되 Windows 11에서는 패키지 메뉴 하나만 등록한다. 이 메뉴는 새 우클릭 화면과 "더 많은 옵션 표시"의 클래식 화면에 모두 노출되므로 레지스트리 메뉴까지 함께 두면 복호화 항목이 중복된다. 새 메뉴 설치에 성공하면 레지스트리 메뉴를 제거하고, 설치에 실패하거나 이전 Windows이면 클래식 메뉴를 유지한다. 둘 다 `withcrypt-gui.exe --encrypt <파일>` 또는 `--decrypt <파일>`을 실행할 뿐이며 비밀번호와 파일 내용은 데스크톱 앱만 다룬다.

등록·해제는 콘솔 Wrapper `withcrypt-setup.exe`(`register`, `register --classic-only`, `unregister`, `status`)가 맡는다. 기본 `register`는 Windows 11 패키지 메뉴를 우선하고 클래식 메뉴를 fallback으로 사용한다. `--classic-only`는 새 메뉴를 해제한 뒤 레지스트리 메뉴만 등록한다. 같은 폴더의 `withcrypt-gui.exe`, `withcrypt_shell.dll`, `WithCrypt.Shell.msix`를 사용하며 이후 설치 프로그램도 이 Wrapper를 호출한다.

1. **클래식 메뉴(레지스트리)**: Wrapper가 HKCU에 동사를 등록·제거한다. 관리자 권한과 unsafe 코드가 필요 없다. 암호화는 `HKCU\Software\Classes\*\shell\WithCrypt.Encrypt`에 `AppliesTo = NOT System.FileExtension:=.esb`로 등록한다. 복호화는 `SystemFileAssociations\.esb\shell\WithCrypt.Decrypt`에 등록하여 사용자가 지정한 `.esb` 기본 프로그램을 바꾸지 않는다. Windows 11에서는 "더 많은 옵션 표시" 안에 나타난다. 레지스트리 접근은 Microsoft의 안전한 `windows-registry` 크레이트를 사용한다.
2. **Windows 11 새 메뉴(COM)**: `withcrypt-shell` cdylib가 `IExplorerCommand`를 구현한다. sparse package(외부 위치 패키지)의 `desktop4:FileExplorerContextMenus`와 `com:SurrogateServer`로 등록한다. 매니페스트에는 모든 파일 형식(`*`)을 위한 단일 동사만 등록한다. DLL은 선택 파일이 `.esb`이면 제목과 실행 인자를 복호화로, 그 외에는 암호화로 결정한다. 동사를 두 개 등록하면 Windows가 `WithCrypt → 작업` flyout으로 묶으므로 단일 동사로 직접 메뉴를 표시한다. 선택 항목이 16개를 넘거나 ESB와 일반 파일이 섞이면 숨긴다. 각 항목마다 앱 창을 하나씩 연다. `scripts/package-windows-shell.ps1`이 makeappx로 패키지를 만든다. 코드 서명을 마련하기 전까지는 `-Unsigned`로 Microsoft의 [서명 없는 패키지](https://learn.microsoft.com/windows/msix/package/unsigned-package)용 publisher OID를 넣고 서명을 생략하며, Wrapper가 `Add-AppxPackage -ExternalLocation <폴더> -AllowUnsigned`로 설치한다. 이 방식은 Windows 11 전용이고 Microsoft가 테스트 용도로 안내하므로 정식 배포 전에는 서명 빌드로 바꾼다. 매니페스트의 `Application` 항목이 실행 파일 활성화로 취급되므로, 서명 없는 패키지는 관리자 권한(모든 사용자 설치)에서만 설치된다. 일반 권한에서는 0x80073D2B로 실패하며, Wrapper는 이때 클래식 메뉴로 대체 등록해 메뉴가 없는 상태를 남기지 않는다.

메뉴 실행 모드의 앱은 대상 파일, 저장 폴더, 결과 이름, 비밀번호만 보여주는 작은 창이다. 암호화 결과는 `<원본파일명>.esb`, 복호화 결과는 인증된 META 파일명이며 원본과 같은 폴더에 저장한다. META 이름이 없는 오래된 ESB는 `decrypted.bin`이 된다. 같은 이름의 파일이 이미 있으면 덮어쓰거나 이름을 바꾸지 않고 오류로 중단한다. 저장 대화상자는 열지 않는다. 일반 실행(인자 없음)의 동작은 바뀌지 않는다.

## unsafe 예외

Agent.md는 자체 코드의 unsafe를 기본 금지한다. COM in-proc 서버는 `DllGetClassObject`/`DllCanUnloadNow` 내보내기, out-pointer 쓰기, Shell API 호출에 FFI가 필요해서 `withcrypt-shell` 크레이트 하나에만 예외를 둔다. 범위는 다음으로 제한한다.

- out-pointer는 null 검사 후에만 쓴다. 각 unsafe 블록에 `SAFETY` 근거를 남기고 `unsafe_op_in_unsafe_fn`을 거부한다.
- 이 DLL은 암호, 키, 파일 내용을 다루지 않는다. 선택 항목 경로를 읽고 같은 폴더의 `withcrypt-gui.exe`를 실행하는 일만 한다.
- `withcrypt-core`, `withcrypt-cli`, `withcrypt-gui`는 계속 `#![forbid(unsafe_code)]`다.

## 한계와 미검증

- COM 경로는 아직 실제로 설치해 탐색기에서 띄워 보지 않았다. 매니페스트는 `makeappx pack`의 스키마 검사를 통과했고, DLL 내보내기와 클래스 팩터리는 단위 테스트로 확인했다. sparse package가 실행 파일 매니페스트의 `msix` 정체성 요소 없이 메뉴만 등록하는지는 실제 설치에서 확인해야 한다.
- 개발용 자체 서명 인증서는 사용자가 신뢰 저장소에 넣어야 하고, 배포에는 신뢰된 코드 서명 인증서가 필요하다.
- 여러 파일을 선택하면 파일마다 비밀번호 창이 따로 뜬다. 일괄 처리는 v1 범위 밖이다.

공식 문서: [IExplorerCommand](https://learn.microsoft.com/windows/win32/api/shobjidl_core/nn-shobjidl_core-iexplorercommand), [외부 위치 패키지로 정체성 부여](https://learn.microsoft.com/windows/apps/desktop/modernize/grant-identity-to-nonpackaged-apps), [desktop4:FileExplorerContextMenus](https://learn.microsoft.com/uwp/schemas/appxpackage/uapmanifestschema/element-desktop4-fileexplorercontextmenus), [AppliesTo](https://learn.microsoft.com/windows/win32/shell/context-menu-handlers).

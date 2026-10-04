//! Windows 11 top-level Explorer context menu (IExplorerCommand), registered by
//! the WithCrypt sparse package. It only launches `withcrypt-gui.exe` beside
//! this DLL; it never sees passwords or file contents.
//!
//! Unsafe exception (ADR-004): COM exports and Shell API calls require FFI.
//! Every unsafe block is a call on a pointer Explorer supplied or a write to an
//! out-pointer checked for null first.
#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]
use std::{
    ffi::{OsString, c_void},
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    process::Command,
    ptr::null_mut,
};
use windows::Win32::{
    Foundation::{
        CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_FAIL, E_NOTIMPL, E_POINTER, HMODULE,
        S_FALSE,
    },
    System::{
        Com::{CoTaskMemFree, IBindCtx, IClassFactory, IClassFactory_Impl},
        LibraryLoader::{
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            GetModuleFileNameW, GetModuleHandleExW,
        },
    },
    UI::Shell::{
        ECS_ENABLED, ECS_HIDDEN, IEnumExplorerCommand, IExplorerCommand, IExplorerCommand_Impl,
        IShellItemArray, SHStrDupW, SIGDN_FILESYSPATH,
    },
};
use windows_core::{
    BOOL, Error, GUID, HRESULT, HSTRING, IUnknown, Interface, PCWSTR, PWSTR, Ref, Result, implement,
};

/// Must match `scripts/windows-shell/AppxManifest.xml`.
pub const ENCRYPT_CLSID: GUID = GUID::from_u128(0x1d78f081_7dff_47ce_88db_a06e5e8daa3e);
pub const DECRYPT_CLSID: GUID = GUID::from_u128(0x02856102_e872_4e51_95a7_9ad715345703);
/// Each item opens its own password window; refuse larger selections.
const MAX_ITEMS: usize = 16;
/// The app this DLL launches; it must sit in the same folder.
const GUI_EXE: &str = "withcrypt-gui.exe";
const SHELL_ICON: &str = "ShellIcon.ico";

#[derive(Clone, Copy, Debug, PartialEq)]
/// Which menu entry a COM object represents (one CLSID per entry).
enum Verb {
    Encrypt,
    Decrypt,
}
impl Verb {
    /// Maps a CLSID requested by Explorer to its menu entry.
    fn from_clsid(clsid: &GUID) -> Option<Self> {
        if *clsid == ENCRYPT_CLSID {
            Some(Self::Encrypt)
        } else if *clsid == DECRYPT_CLSID {
            Some(Self::Decrypt)
        } else {
            None
        }
    }
    /// Also returned as the command's canonical name.
    fn clsid(self) -> GUID {
        match self {
            Self::Encrypt => ENCRYPT_CLSID,
            Self::Decrypt => DECRYPT_CLSID,
        }
    }
    /// Menu text shown in Explorer.
    fn title(self) -> &'static str {
        match self {
            Self::Encrypt => "WithCrypt로 암호화",
            Self::Decrypt => "WithCrypt로 복호화",
        }
    }
    /// Command-line flag passed to `withcrypt-gui.exe`.
    fn flag(self) -> &'static str {
        match self {
            Self::Encrypt => "--encrypt",
            Self::Decrypt => "--decrypt",
        }
    }
    /// Encrypt applies to every file except `.esb`; Decrypt only to `.esb`.
    fn accepts(self, path: &Path) -> bool {
        let esb = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("esb"));
        match self {
            Self::Encrypt => !esb,
            Self::Decrypt => esb,
        }
    }
    /// True when every selected item fits this entry and the selection is small enough.
    fn applies_to(self, paths: &[PathBuf]) -> bool {
        !paths.is_empty() && paths.len() <= MAX_ITEMS && paths.iter().all(|p| self.accepts(p))
    }
}

/// File-system paths of the items selected in Explorer. Oversized selections
/// return placeholder entries only so the caller can reject them by count.
fn selected_paths(items: &IShellItemArray) -> Result<Vec<PathBuf>> {
    // SAFETY: `items` is a live interface supplied by Explorer for this call.
    let count = unsafe { items.GetCount()? } as usize;
    if count > MAX_ITEMS {
        return Ok(vec![PathBuf::new(); count]);
    }
    let mut paths = Vec::with_capacity(count);
    for index in 0..count as u32 {
        // SAFETY: index < count; the returned names are CoTaskMem strings we own.
        let name = unsafe { items.GetItemAt(index)?.GetDisplayName(SIGDN_FILESYSPATH)? };
        let path = PathBuf::from(OsString::from_wide(unsafe { name.as_wide() }));
        unsafe { CoTaskMemFree(Some(name.0 as *const c_void)) };
        paths.push(path);
    }
    Ok(paths)
}

/// The desktop app is installed next to this DLL (the package external location).
fn sibling_file(name: &str) -> Result<PathBuf> {
    let mut module = HMODULE::default();
    // SAFETY: any address inside this DLL identifies its module; no refcount change.
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(gui_exe as *const () as *const u16),
            &mut module,
        )?
    };
    let mut buffer = vec![0u16; 32768];
    // SAFETY: the buffer length is passed with the slice.
    let len = unsafe { GetModuleFileNameW(Some(module), &mut buffer) } as usize;
    if len == 0 || len >= buffer.len() {
        return Err(Error::from_thread());
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len])).with_file_name(name))
}

fn gui_exe() -> Result<PathBuf> {
    sibling_file(GUI_EXE)
}

/// Copies `text` into a COM-allocated string, as IExplorerCommand requires.
fn co_string(text: &str) -> Result<PWSTR> {
    // SAFETY: SHStrDupW copies into CoTaskMem; Explorer frees it.
    unsafe { SHStrDupW(&HSTRING::from(text)) }
}

#[implement(IExplorerCommand)]
/// One context-menu entry. Explorer asks it for a title, an icon and a
/// visibility state, and calls `Invoke` when the user clicks it.
struct ExplorerCommand(Verb);

impl IExplorerCommand_Impl for ExplorerCommand_Impl {
    fn GetTitle(&self, _items: Ref<IShellItemArray>) -> Result<PWSTR> {
        co_string(self.0.title())
    }
    /// Explorer accepts a standalone ICO path for an IExplorerCommand icon.
    fn GetIcon(&self, _items: Ref<IShellItemArray>) -> Result<PWSTR> {
        co_string(&sibling_file(SHELL_ICON)?.to_string_lossy())
    }
    fn GetToolTip(&self, _items: Ref<IShellItemArray>) -> Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }
    fn GetCanonicalName(&self) -> Result<GUID> {
        Ok(self.0.clsid())
    }
    /// Shows the entry only for selections it can handle; hides it otherwise.
    fn GetState(&self, items: Ref<IShellItemArray>, _ok_to_be_slow: BOOL) -> Result<u32> {
        let visible = items
            .ok()
            .and_then(selected_paths)
            .is_ok_and(|paths| self.0.applies_to(&paths));
        Ok(if visible { ECS_ENABLED } else { ECS_HIDDEN }.0 as u32)
    }
    /// Starts one `withcrypt-gui.exe --encrypt|--decrypt <file>` per item.
    fn Invoke(&self, items: Ref<IShellItemArray>, _bind: Ref<IBindCtx>) -> Result<()> {
        let paths = selected_paths(items.ok()?)?;
        if !self.0.applies_to(&paths) {
            return Err(E_FAIL.into());
        }
        let exe = gui_exe()?;
        for path in paths {
            Command::new(&exe)
                .arg(self.0.flag())
                .arg(path)
                .spawn()
                .map_err(|e| Error::new(E_FAIL, e.to_string()))?;
        }
        Ok(())
    }
    fn GetFlags(&self) -> Result<u32> {
        Ok(0) // ECF_DEFAULT
    }
    fn EnumSubCommands(&self) -> Result<IEnumExplorerCommand> {
        Err(E_NOTIMPL.into())
    }
}

#[implement(IClassFactory)]
/// COM class factory: creates `ExplorerCommand` objects for one entry.
struct Factory(Verb);

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> Result<()> {
        if iid.is_null() || object.is_null() {
            return Err(E_POINTER.into());
        }
        // SAFETY: checked non-null above.
        unsafe { *object = null_mut() };
        if outer.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let command: IExplorerCommand = ExplorerCommand(self.0).into();
        // SAFETY: iid/object were checked; query writes a referenced pointer or null.
        unsafe { command.query(iid, object) }.ok()
    }
    fn LockServer(&self, _lock: BOOL) -> Result<()> {
        Ok(())
    }
}

/// # Safety
/// Called by COM with valid or null pointers; nulls are rejected.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    clsid: *const GUID,
    iid: *const GUID,
    object: *mut *mut c_void,
) -> HRESULT {
    if clsid.is_null() || iid.is_null() || object.is_null() {
        return E_POINTER;
    }
    // SAFETY: checked non-null above.
    unsafe { *object = null_mut() };
    let Some(verb) = Verb::from_clsid(unsafe { &*clsid }) else {
        return CLASS_E_CLASSNOTAVAILABLE;
    };
    let factory: IClassFactory = Factory(verb).into();
    // SAFETY: iid/object were checked.
    unsafe { factory.query(iid, object) }
}

/// The package surrogate host owns the lifetime; never request an unload.
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_FALSE
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verbs_split_on_esb_extension() {
        let paths = |v: &[&str]| v.iter().map(PathBuf::from).collect::<Vec<_>>();
        assert!(Verb::Encrypt.applies_to(&paths(&[r"C:\a\보고서.pdf", r"C:\a\b.tar.gz"])));
        assert!(!Verb::Encrypt.applies_to(&paths(&[r"C:\a\b.pdf", r"C:\a\c.ESB"])));
        assert!(Verb::Decrypt.applies_to(&paths(&[r"C:\a\c.esb", r"C:\a\d.Esb"])));
        assert!(!Verb::Decrypt.applies_to(&paths(&[r"C:\a\c.esb.txt"])));
        assert!(!Verb::Encrypt.applies_to(&[]));
        assert!(!Verb::Encrypt.applies_to(&vec![PathBuf::from("a"); MAX_ITEMS + 1]));
        assert_eq!(Verb::from_clsid(&ENCRYPT_CLSID), Some(Verb::Encrypt));
        assert_eq!(Verb::from_clsid(&DECRYPT_CLSID), Some(Verb::Decrypt));
        assert_eq!(Verb::from_clsid(&GUID::zeroed()), None);
    }
    #[test]
    fn class_factory_creates_commands() {
        let mut object = null_mut();
        let hr = unsafe { DllGetClassObject(&ENCRYPT_CLSID, &IClassFactory::IID, &mut object) };
        assert!(hr.is_ok());
        let factory = unsafe { IClassFactory::from_raw(object) };
        let command: IExplorerCommand = unsafe { factory.CreateInstance(None) }.unwrap();
        let title = unsafe { command.GetTitle(None) }.unwrap();
        assert_eq!(unsafe { title.to_string() }.unwrap(), "WithCrypt로 암호화");
        unsafe { CoTaskMemFree(Some(title.0 as *const c_void)) };
        assert_eq!(
            unsafe { command.GetCanonicalName() }.unwrap(),
            ENCRYPT_CLSID
        );
        let unknown = GUID::from_u128(1);
        assert_eq!(
            unsafe { DllGetClassObject(&unknown, &IClassFactory::IID, &mut object) },
            CLASS_E_CLASSNOTAVAILABLE
        );
        assert!(object.is_null());
        assert!(unsafe { command.GetIcon(None) }.is_ok());
    }
}

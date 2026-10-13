#[path = "../../build/windows_resource.rs"]
mod windows_resource;

fn main() {
    windows_resource::compile(
        "withcrypt-setup",
        "WithCrypt Setup Utility",
        "withcrypt-setup.exe",
        None,
    );
}

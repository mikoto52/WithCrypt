#[path = "../../build/windows_resource.rs"]
mod windows_resource;

fn main() {
    windows_resource::compile(
        "withcrypt-gui",
        "WithCrypt GUI",
        "withcrypt-gui.exe",
        Some("../../resources/AppIcon2.ico"),
    );
}

#[path = "../../build/windows_resource.rs"]
mod windows_resource;

fn main() {
    windows_resource::compile("withcrypt", "WithCrypt CLI", "withcrypt.exe", None);
}

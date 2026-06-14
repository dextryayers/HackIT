use std::path::PathBuf;

fn main() {
    let c_core_path = PathBuf::from("../c_core");
    let include_path = c_core_path.join("include");

    println!("cargo:rerun-if-changed={}/packet_capture.h", include_path.display());
    println!("cargo:rerun-if-changed={}/wifi_stack.h", include_path.display());

    // Only link the C static library if it has been built (by CMake)
    let build_dir = c_core_path.join("build");
    let lib_a = build_dir.join("libhackit_wireless_c.a");
    if lib_a.exists() {
        println!("cargo:rustc-link-search=native={}", build_dir.display());
        println!("cargo:rustc-link-lib=static=hackit_wireless_c");
    } else {
        println!("cargo:warning=libhackit_wireless_c.a not found - C FFI calls will fail at link time");
    }

    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=wlanapi");
        println!("cargo:rustc-link-lib=iphlpapi");
    }
}
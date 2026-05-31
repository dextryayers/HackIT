use std::env;
use std::path::PathBuf;

fn main() {
    let c_core_path = PathBuf::from("../c_core");
    let include_path = c_core_path.join("include");

    println!("cargo:rerun-if-changed={}/packet_capture.h", include_path.display());
    println!("cargo:rerun-if-changed={}/wifi_stack.h", include_path.display());

    // Link the static C library that CMake built
    let build_dir = c_core_path.join("build");
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=hackit_wireless_c");
    
    // Bind MSVC native platform libraries to resolve static link externals
    println!("cargo:rustc-link-lib=wlanapi");
    println!("cargo:rustc-link-lib=iphlpapi");
}

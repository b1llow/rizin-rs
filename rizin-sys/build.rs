use crate::common::search_libs;
use std::env;
use std::error::Error;
use std::path::PathBuf;

#[path = "build/common.rs"]
pub mod common;

const RZ_LIBRARIES: &[&str] = &[
    "rz_arch",
    "rz_egg",
    "rz_reg",
    "rz_bin",
    "rz_flag",
    "rz_search",
    "rz_config",
    "rz_hash",
    "rz_sign",
    "rz_cons",
    "rz_il",
    "rz_socket",
    "rz_core",
    "rz_io",
    "rz_syscall",
    "rz_crypto",
    "rz_lang",
    "rz_type",
    "rz_debug",
    "rz_magic",
    "rz_util",
    "rz_demangler",
    "rz_main",
    "rz_diff",
    "rz_mark",
];

fn main() -> Result<(), Box<dyn Error>> {
    let mut builder = bindgen::Builder::default();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let lib_name = "rz_core";
    if let Ok(librz) = pkg_config::Config::new()
        .atleast_version("0.8.0")
        // .statik(true)            // 需要静态链接时可打开
        .probe(lib_name)
    {
        builder = builder.clang_args(
            librz
                .include_paths
                .iter()
                .map(|p| format!("-I{}", p.to_str().unwrap())),
        );
    } else {
        for lib in RZ_LIBRARIES {
            println!("cargo:rustc-link-lib=dylib={}", lib);
        }
        let (lib_dir, _, _) = search_libs(RZ_LIBRARIES, "RIZIN_DIR")?;
        println!("cargo:rustc-link-search={}", lib_dir.to_str().unwrap());

        if let Ok(dir) = env::var("RIZIN_DIR") {
            let rizin_dir = PathBuf::from(dir);
            let inc_dir = rizin_dir.join("include");
            builder = builder.clang_args([
                "-I",
                inc_dir.to_str().unwrap(),
                "-I",
                inc_dir.join("librz").to_str().unwrap(),
                "-I",
                inc_dir.join("librz").join("sdb").to_str().unwrap(),
            ])
        }
    }

    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = builder
        .derive_default(true)
        .derive_hash(true)
        .derive_eq(true)
        .generate_inline_functions(true)
        .prepend_enum_name(false)
        .array_pointers_in_arguments(true)
        .merge_extern_blocks(true)
        //.c_naming(true)
        .header("wrapper.h")
        .allowlist_type("rz_.*")
        .allowlist_type("Rz.*")
        .allowlist_function("rz_.*")
        .allowlist_var("rz.*")
        .allowlist_var("RZ.*")
        .clang_arg("-fparse-all-comments")
        .clang_arg("-std=c99")
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    Ok(())
}

use crate::common::search_libs;
use bindgen::callbacks::{MacroParsingBehavior, ParseCallbacks};
use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::path::PathBuf;

#[path = "build/common.rs"]
pub mod common;

const IGNORE_MACROS: [&str; 20] = [
    "FE_DIVBYZERO",
    "FE_DOWNWARD",
    "FE_INEXACT",
    "FE_INVALID",
    "FE_OVERFLOW",
    "FE_TONEAREST",
    "FE_TOWARDZERO",
    "FE_UNDERFLOW",
    "FE_UPWARD",
    "FP_INFINITE",
    "FP_INT_DOWNWARD",
    "FP_INT_TONEAREST",
    "FP_INT_TONEARESTFROMZERO",
    "FP_INT_TOWARDZERO",
    "FP_INT_UPWARD",
    "FP_NAN",
    "FP_NORMAL",
    "FP_SUBNORMAL",
    "FP_ZERO",
    "IPPORT_RESERVED",
];

#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> MacroParsingBehavior {
        if self.0.contains(name) {
            MacroParsingBehavior::Ignore
        } else {
            MacroParsingBehavior::Default
        }
    }
}

impl IgnoreMacros {
    fn new() -> Self {
        Self(IGNORE_MACROS.into_iter().map(|s| s.to_owned()).collect())
    }
}

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
        .generate_inline_functions(true)
        .header("wrapper.h")
        .allowlist_type("rz_.*")
        .allowlist_type("Rz.*")
        .allowlist_function("rz_.*")
        .allowlist_var("RZ_.*")
        .clang_arg("-fparse-all-comments")
        .clang_arg("-std=c99")
        .parse_callbacks(Box::new(IgnoreMacros::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    Ok(())
}

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::path::Path;

    use crate::*;

    #[test]
    fn test_bin_file() {
        unsafe {
            let rz_bin = rz_bin_new();
            let io = rz_io_new();
            assert!(!rz_bin.is_null());
            assert!(!io.is_null());
            rz_io_bind(io, &mut (*rz_bin).iob);
            let mut rz_bin_opt = RzBinOptions::default();
            rz_bin_options_init(&mut rz_bin_opt, 0, 0, 0, false);
            let path = Path::new("target/debug/librizin_rs.rlib");
            if path.exists() {
                let cpath = CString::new(path.to_str().unwrap()).unwrap();
                let bf = rz_bin_open(rz_bin, cpath.as_ptr(), &mut rz_bin_opt);
                assert!(!bf.is_null());
            }
        }
    }
}

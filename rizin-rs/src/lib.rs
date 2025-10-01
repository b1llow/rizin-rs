#![allow(dead_code)]

pub mod util;

use crate::util::RzStrBuf;
use anyhow::anyhow;
use core::str;
use rizin_sys;
use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::ptr::{NonNull, addr_of_mut};
use std::str::FromStr;

pub struct RzAnalysisOp(pub rizin_sys::RzAnalysisOp);

impl Drop for RzAnalysisOp {
    fn drop(&mut self) {
        unsafe {
            rizin_sys::rz_analysis_op_fini(addr_of_mut!(self.0));
        }
    }
}

impl RzAnalysisOp {
    pub fn mnemonic(&self) -> anyhow::Result<&str> {
        if self.0.mnemonic.is_null() {
            Err(anyhow!("mnemonic is_null"))
        } else {
            let cstr = unsafe { CStr::from_ptr(self.0.mnemonic) };
            cstr.to_str().map_err(|_| anyhow!("invalid cstr"))
        }
    }

    pub fn il_op(&self) -> Option<rizin_sys::RzAnalysisLiftedILOp> {
        if self.0.il_op.is_null() {
            None
        } else {
            Some(self.0.il_op)
        }
    }

    pub fn il_str(&self, pretty: bool) -> Option<String> {
        self.il_op().map(|op| {
            let mut sb = RzStrBuf::new();
            unsafe {
                rizin_sys::rz_il_op_effect_stringify(op, addr_of_mut!(sb.0), pretty);
            }
            sb.to_string()
        })
    }
}

pub struct RzBinFile<'a> {
    core: &'a RzCore,
    pub inner: NonNull<rizin_sys::RzBinFile>,
}

impl Drop for RzBinFile<'_> {
    fn drop(&mut self) {
        unsafe {
            rizin_sys::rz_bin_file_delete(self.core.0.as_ref().bin, self.inner.as_ptr());
        }
    }
}

pub struct RzCore(pub NonNull<rizin_sys::RzCore>);
unsafe impl Sync for RzCore {}
unsafe impl Send for RzCore {}

impl Drop for RzCore {
    fn drop(&mut self) {
        unsafe {
            rizin_sys::rz_core_free(self.0.as_ptr());
        }
    }
}

impl<'a> RzCore {
    pub fn new() -> Self {
        let core = unsafe { rizin_sys::rz_core_new() };
        Self(NonNull::new(core).unwrap())
    }

    pub fn analysis_op(
        &self,
        bytes: &[u8],
        addr: usize,
        mask: rizin_sys::RzAnalysisOpMask,
    ) -> anyhow::Result<RzAnalysisOp> {
        let mut op: RzAnalysisOp = RzAnalysisOp(Default::default());
        let res = unsafe {
            rizin_sys::rz_analysis_op(
                self.0.as_ref().analysis,
                addr_of_mut!(op.0),
                addr as _,
                bytes.as_ptr() as _,
                bytes.len() as _,
                mask,
            )
        };
        if res <= 0 {
            Err(anyhow!("failed analysis op"))
        } else {
            Ok(op)
        }
    }

    pub fn config_set(&self, k: &str, v: &str) -> anyhow::Result<&Self> {
        let node = unsafe {
            rizin_sys::rz_config_set(
                self.0.as_ref().config,
                CString::new(k)?.as_ptr(),
                CString::new(v)?.as_ptr(),
            )
        };
        NonNull::new(node)
            .map(|_| self)
            .ok_or(anyhow!("{} is null", k))
    }

    pub fn config_get(&self, key: &str) -> Option<&str> {
        unsafe {
            CString::from_str(key)
                .map(|ckey| {
                    let ptr = rizin_sys::rz_config_get(self.0.as_ref().config, ckey.as_ptr());
                    if ptr.is_null() {
                        None
                    } else {
                        Some(CStr::from_ptr(ptr).to_str().expect("invalid utf8"))
                    }
                })
                .ok()
                .flatten()
        }
    }

    fn bin_open(&'a mut self, path: PathBuf) -> anyhow::Result<RzBinFile<'a>> {
        let mut opt = rizin_sys::RzBinOptions::default();
        unsafe {
            rizin_sys::rz_bin_options_init(addr_of_mut!(opt), 0, 0, 0, false);
        }
        let cpath = CString::new(path.to_str().unwrap())?;
        let bf = unsafe {
            rizin_sys::rz_bin_open(self.0.as_ref().bin, cpath.as_ptr(), addr_of_mut!(opt))
        };
        let bf = RzBinFile {
            core: self,
            inner: NonNull::new(bf).ok_or(anyhow!("failed open {}", path.to_str().unwrap()))?,
        };
        Ok(bf)
    }
}

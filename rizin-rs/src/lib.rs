#![allow(dead_code)]

use core::str;
use rizin_sys::*;
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::marker::PhantomData;
use std::mem::{ManuallyDrop, size_of};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::ptr::{NonNull, addr_of, addr_of_mut, null_mut};
use std::{fmt, result, slice};

use anyhow::anyhow;

pub type Result<T> = anyhow::Result<T>;

pub struct Core(pub NonNull<RzCore>);
unsafe impl Sync for Core {}
unsafe impl Send for Core {}

impl Drop for Core {
    fn drop(&mut self) {
        unsafe {
            rz_core_free(self.0.as_ptr());
        }
    }
}

pub struct AnalysisOp(pub RzAnalysisOp);

impl Drop for AnalysisOp {
    fn drop(&mut self) {
        unsafe {
            rz_analysis_op_fini(addr_of_mut!(self.0));
        }
    }
}

pub struct StrBuf(pub RzStrBuf);

impl StrBuf {
    pub fn new() -> Self {
        let mut sb = RzStrBuf::default();
        unsafe { rz_strbuf_init(addr_of_mut!(sb)) };
        Self(sb)
    }
}

impl Display for StrBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> result::Result<(), fmt::Error> {
        let cptr = unsafe { rz_strbuf_drain_nofree(addr_of!(self.0) as _) };
        if cptr.is_null() {
            Ok(())
        } else {
            let cstr = unsafe { CStr::from_ptr(cptr) };
            match cstr.to_str() {
                Ok(str) => f.write_str(str),
                Err(_) => Ok(()),
            }
        }
    }
}

impl Drop for StrBuf {
    fn drop(&mut self) {
        unsafe {
            rz_strbuf_fini(addr_of_mut!(self.0));
        }
    }
}

impl AnalysisOp {
    pub fn mnemonic(&self) -> Result<&str> {
        if self.0.mnemonic.is_null() {
            Err(anyhow!("mnemonic is_null"))
        } else {
            let cstr = unsafe { CStr::from_ptr(self.0.mnemonic) };
            cstr.to_str().map_err(|_| anyhow!("invalid cstr"))
        }
    }

    pub fn il_str(&self, pretty: bool) -> Result<String> {
        if self.0.il_op.is_null() {
            Err(anyhow!("il_op is null"))
        } else {
            let mut sb = StrBuf::new();
            unsafe {
                rz_il_op_effect_stringify(self.0.il_op, addr_of_mut!(sb.0), pretty);
            }
            Ok(sb.to_string())
        }
    }
}

impl Core {
    pub fn new() -> Self {
        let core = unsafe { rz_core_new() };
        Self(NonNull::new(core).unwrap())
    }

    pub fn analysis_op(
        &self,
        bytes: &[u8],
        addr: usize,
        mask: RzAnalysisOpMask,
    ) -> Result<AnalysisOp> {
        let mut op: AnalysisOp = AnalysisOp(Default::default());
        let res = unsafe {
            rz_analysis_op(
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

    pub fn config_set(&self, k: &str, v: &str) -> Result<&Self> {
        let node = unsafe {
            rz_config_set(
                self.0.as_ref().config,
                CString::new(k)?.as_ptr(),
                CString::new(v)?.as_ptr(),
            )
        };
        NonNull::new(node)
            .map(|_| self)
            .ok_or(anyhow!("{} is null", k))
    }

    pub fn config_get(&self, k: &str) -> Result<&CStr> {
        let cstr = unsafe {
            let ptr = rz_config_get(self.0.as_ref().config, CString::new(k)?.as_ptr());
            if ptr.is_null() {
                return Err(anyhow!("{} is null", k));
            }
            CStr::from_ptr(ptr)
        };
        Ok(cstr)
    }
}

pub struct BinFile<'a> {
    core: &'a Core,
    pub bf: NonNull<RzBinFile>,
}

impl<'a> Core {
    fn bin_open(&'a mut self, path: PathBuf) -> Result<BinFile<'a>> {
        let mut rz_bin_opt = RzBinOptions::default();
        unsafe {
            rz_bin_options_init(&mut rz_bin_opt, 0, 0, 0, false);
        }
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let bf = unsafe { rz_bin_open(self.0.as_ref().bin, cpath.as_ptr(), &mut rz_bin_opt) };
        let bf = BinFile {
            core: self,
            bf: NonNull::new(bf).ok_or(anyhow!("failed open {}", path.to_str().unwrap()))?,
        };
        Ok(bf)
    }
}

impl Drop for BinFile<'_> {
    fn drop(&mut self) {
        unsafe {
            rz_bin_file_delete(self.core.0.as_ref().bin, self.bf.as_ptr());
        }
    }
}

pub struct DwarfAbbrev(pub NonNull<RzBinDwarfAbbrev>);

impl DwarfAbbrev {
    pub fn new(input: &[u8]) -> Result<DwarfAbbrev> {
        let reader = RzBinEndianReader {
            data: input.as_ptr() as _,
            owned: false,
            length: input.len() as _,
            offset: 0,
            big_endian: false,
            relocations: null_mut(),
        };
        let abbrev = unsafe {
            let ptr = libc::malloc(size_of::<RzBinEndianReader>());
            libc::memcpy(ptr, addr_of!(reader) as _, size_of::<RzBinEndianReader>());
            rz_bin_dwarf_abbrev_new(ptr as _)
        };
        NonNull::<RzBinDwarfAbbrev>::new(abbrev)
            .map(DwarfAbbrev)
            .ok_or(anyhow!("failed new"))
    }
}

impl Drop for DwarfAbbrev {
    fn drop(&mut self) {
        unsafe {
            rz_bin_dwarf_abbrev_free(self.0.as_ptr());
        }
    }
}

pub struct List<T> {
    pub inner: NonNull<RzList>,
    marker: PhantomData<T>,
}

pub struct ListIter<'a, T: 'a> {
    head: Option<NonNull<RzListIter>>,
    tail: Option<NonNull<RzListIter>>,
    lst: &'a List<T>,
    marker: PhantomData<&'a T>,
}

impl<T> List<T> {
    pub fn new() -> Self {
        let x = unsafe { rz_list_new() };
        Self::try_from(x).unwrap()
    }

    pub fn push(&mut self, value: T) {
        unsafe {
            let val = Box::new(value);
            rz_list_push(self.inner.as_ptr(), Box::into_raw(val) as _);
        }
    }

    pub fn pop(&mut self) -> Option<Box<T>> {
        if self.len() == 0 {
            None
        } else {
            let mut value: *mut T = unsafe { std::mem::zeroed() };
            unsafe {
                let v = rz_list_pop(self.inner.as_ptr());
                if !v.is_null() {
                    value = v as *mut T;
                }
            }
            Some(unsafe { Box::from_raw(value) })
        }
    }

    pub fn len(&self) -> usize {
        unsafe { rz_list_length(self.inner.as_ptr()) as _ }
    }

    pub fn iter(&self) -> ListIter<'_, T> {
        unsafe {
            ListIter {
                head: NonNull::new(self.inner.as_ref().head),
                tail: NonNull::new(self.inner.as_ref().tail),
                lst: self,
                marker: PhantomData,
            }
        }
    }
}

impl<T> TryFrom<*mut RzList> for List<T> {
    type Error = ();

    fn try_from(value: *mut RzList) -> result::Result<Self, Self::Error> {
        let inner = NonNull::new(value).unwrap();
        Ok(Self {
            inner,
            marker: PhantomData,
        })
    }
}

impl<T> Drop for List<T> {
    fn drop(&mut self) {
        unsafe {
            rz_list_free(self.inner.as_ptr());
        }
    }
}

impl<'a, T> Iterator for ListIter<'a, T> {
    type Item = Box<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.head.map(|node| unsafe {
            let it = rz_list_iter_get_next(node.as_ptr());
            let item = node.as_ref().elem as *mut T;
            self.head = NonNull::new(it);
            Box::from_raw(item)
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = unsafe { rz_list_length(self.lst.inner.as_ptr()) };
        (len as _, Some(len as _))
    }
}

impl<'a, T> DoubleEndedIterator for ListIter<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.tail.map(|node| unsafe {
            let it = rz_list_iter_get_prev(node.as_ptr());
            let item = node.as_ref().elem as *mut T;
            self.head = NonNull::new(it);
            Box::from_raw(item)
        })
    }
}

pub struct Vector<T> {
    pub(crate) inner: NonNull<RzVector>,
    marker: PhantomData<T>,
}

impl<T> Vector<T> {
    fn from_raw(value: *mut RzVector) -> Option<Self> {
        Some(Self {
            inner: NonNull::new(value)?,
            marker: PhantomData,
        })
    }
    fn into_raw(self) -> *mut RzVector {
        let ptr = self.inner.as_ptr();
        std::mem::forget(self);
        ptr
    }

    pub fn new(len: usize) -> Self {
        let x = unsafe {
            let vec = rz_vector_new(size_of::<T>(), None, null_mut());
            rz_vector_reserve(vec, len);
            vec
        };
        Self::from_raw(x).unwrap()
    }

    pub fn push(&mut self, value: T) {
        unsafe {
            rz_vector_push(self.inner.as_mut(), addr_of!(value) as _);
            std::mem::forget(value);
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len() == 0 {
            None
        } else {
            let mut value: T = unsafe { std::mem::zeroed() };
            unsafe {
                rz_vector_pop(self.inner.as_mut(), addr_of_mut!(value) as _);
            }
            Some(value)
        }
    }

    pub fn insert(&mut self, index: usize, value: T) {
        unsafe {
            rz_vector_insert(self.inner.as_mut(), index as _, addr_of!(value) as _);
            std::mem::forget(value);
        }
    }

    pub fn remove(&mut self, index: usize) -> Option<T> {
        if index >= self.len() {
            None
        } else {
            let mut value: T = unsafe { std::mem::zeroed() };
            unsafe {
                rz_vector_remove_at(self.inner.as_mut(), index as _, addr_of_mut!(value) as _);
            }
            Some(value)
        }
    }

    pub fn as_mut_ptr(&self) -> *mut T {
        unsafe { self.inner.as_ref().a as _ }
    }

    pub fn len(&self) -> usize {
        unsafe { self.inner.as_ref().len }
    }
}

impl<T> TryFrom<Vec<T>> for Vector<T> {
    type Error = ();

    fn try_from(value: Vec<T>) -> result::Result<Self, Self::Error> {
        let mut vec = Vector::new(value.len());
        value.into_iter().for_each(|x| vec.push(x));
        Ok(vec)
    }
}

impl<T> AsMut<[T]> for Vector<T> {
    fn as_mut(&mut self) -> &mut [T] {
        unsafe { slice::from_raw_parts_mut(self.as_mut_ptr(), self.len()) }
    }
}

impl<T> Deref for Vector<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.as_mut_ptr() as *const T, self.len()) }
    }
}

impl<T> DerefMut for Vector<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { slice::from_raw_parts_mut(self.as_mut_ptr(), self.len()) }
    }
}

impl<T> Drop for Vector<T> {
    fn drop(&mut self) {
        unsafe {
            rz_vector_free(self.inner.as_mut());
        }
    }
}

pub struct PVector<T> {
    pub(crate) inner: NonNull<RzPVector>,
    pub(crate) v: ManuallyDrop<Vector<*mut T>>,
    marker: PhantomData<T>,
}

impl<T> PVector<T> {
    fn from_raw(value: *mut RzPVector) -> Option<Self> {
        NonNull::new(value).and_then(|inner| {
            let v = unsafe { Vector::from_raw(addr_of_mut!((*inner.as_ptr()).v))? };
            Some(Self {
                inner,
                v: ManuallyDrop::new(v),
                marker: PhantomData,
            })
        })
    }
    fn into_raw(self) -> *mut RzPVector {
        let ptr = self.inner.as_ptr();
        std::mem::forget(self);
        ptr
    }
}

impl<T> Drop for PVector<T> {
    fn drop(&mut self) {
        unsafe {
            rz_pvector_free(self.inner.as_ptr());
        }
    }
}

impl<T> AsMut<Vector<*mut T>> for PVector<T> {
    fn as_mut(&mut self) -> &mut Vector<*mut T> {
        &mut self.v
    }
}

impl<T> Deref for PVector<T> {
    type Target = Vector<*mut T>;

    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

impl<T> DerefMut for PVector<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use crate::{Core, List, PVector, Vector};
    use std::vec;

    #[test]
    fn test_core() {
        let _ = Core::new();
    }

    #[test]
    fn test_vector() {
        let vec = Vector::try_from(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert_eq!(
            vec.iter().map(|x| *x).collect::<Vec<i32>>(),
            (0..10).into_iter().collect::<Vec<i32>>()
        );
    }
    #[test]
    fn test_pvector() {
        let vec = unsafe {
            let x = rz_pvector_new(None);
            for i in 0..10 {
                rz_vector_push(addr_of_mut!((*x).v), addr_of!(i) as _);
            }
            PVector::<i32>::from_raw(x).unwrap()
        };
        assert_eq!(
            vec.iter().map(|x| *x as i32).collect::<Vec<i32>>(),
            (0..10).into_iter().collect::<Vec<i32>>()
        );
    }

    #[test]
    fn test_list() {
        let mut list = List::new();
        for i in 0..10 {
            list.push(i);
        }
        let act: Vec<i32> = list.iter().map(|x| *x).collect();
        assert_eq!(act, (0..10).into_iter().collect::<Vec<i32>>());
    }
}

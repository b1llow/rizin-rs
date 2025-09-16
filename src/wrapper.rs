use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::marker::PhantomData;
use std::mem::{size_of, ManuallyDrop};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::ptr::{addr_of, addr_of_mut, null_mut, NonNull};
use std::{fmt, result, slice};

use anyhow::anyhow;

use crate::*;

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

pub struct StrBuf(RzStrBuf);

impl StrBuf {
    pub fn new() -> Self {
        let mut sb = RzStrBuf::default();
        unsafe { rz_strbuf_init(addr_of_mut!(sb)) };
        Self(sb)
    }
}

impl Display for StrBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    pub fn analysis_op(&self, bytes: &[u8], addr: usize) -> Result<AnalysisOp> {
        let mut op: AnalysisOp = AnalysisOp(Default::default());
        let res = unsafe {
            rz_analysis_op(
                self.0.as_ref().analysis,
                addr_of_mut!(op.0),
                addr as _,
                bytes.as_ptr() as _,
                bytes.len() as _,
                RzAnalysisOpMask_RZ_ANALYSIS_OP_MASK_DISASM
                    | RzAnalysisOpMask_RZ_ANALYSIS_OP_MASK_IL,
            )
        };
        if res <= 0 {
            Err(anyhow!("failed analysis op"))
        } else {
            Ok(op)
        }
    }

    pub fn set(&self, k: &str, v: &str) -> Result<&Self> {
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
}

pub struct BinFile<'a> {
    core: &'a Core,
    pub bf: NonNull<RzBinFile>,
}

impl Core {
    unsafe fn open(&mut self, path: PathBuf) -> Result<BinFile> {
        let mut rz_bin_opt = RzBinOptions::default();
        rz_bin_options_init(&mut rz_bin_opt, 0, 0, 0, false);
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let bf = rz_bin_open(self.0.as_ref().bin, cpath.as_ptr(), &mut rz_bin_opt);
        Ok(BinFile {
            core: self,
            bf: NonNull::new(bf).ok_or(anyhow!("failed open {}", path.to_str().unwrap()))?,
        })
    }
}

impl Drop for BinFile<'_> {
    fn drop(&mut self) {
        unsafe {
            rz_bin_file_delete(self.core.0.as_ref().bin, self.bf.as_ptr());
        }
    }
}

impl RzBinEndianReader {
    fn new(input: &[u8], big_endian: bool) -> Self {
        Self {
            data: input.as_ptr() as _,
            owned: false,
            length: input.len() as _,
            offset: 0,
            big_endian,
            relocations: null_mut(),
        }
    }
}

pub struct DwarfAbbrev(pub NonNull<RzBinDwarfAbbrev>);

impl DwarfAbbrev {
    pub fn new(input: &[u8]) -> Result<DwarfAbbrev> {
        let R = RzBinEndianReader::new(input, false);
        let abbrev = unsafe {
            let ptr = libc::malloc(size_of::<RzBinEndianReader>());
            libc::memcpy(ptr, addr_of!(R) as _, size_of::<RzBinEndianReader>());
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
    len: usize,
    marker: PhantomData<&'a T>,
}

impl<T> List<T> {
    pub fn len(&self) -> usize {
        unsafe { rz_list_length(self.inner.as_ptr()) as _ }
    }

    pub fn iter(&self) -> ListIter<'_, T> {
        unsafe {
            ListIter {
                head: NonNull::new(self.inner.as_ref().head),
                tail: NonNull::new(self.inner.as_ref().tail),
                len: self.len(),
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
    type Item = *mut T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.len == 0 {
            None
        } else {
            self.head.map(|node| unsafe {
                let item = node.as_ref().elem as Self::Item;
                self.len -= 1;
                self.head = NonNull::new(rz_list_iter_get_next(node.as_ptr()));
                item
            })
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }
}

impl<'a, T> DoubleEndedIterator for ListIter<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.len == 0 {
            None
        } else {
            self.tail.map(|node| unsafe {
                let item = node.as_ref().elem as Self::Item;
                self.len -= 1;
                self.head = NonNull::new(rz_list_iter_get_prev(node.as_ptr()));
                item
            })
        }
    }
}

pub struct Vector<T> {
    pub(crate) inner: NonNull<RzVector>,
    marker: PhantomData<T>,
}

impl<T> Vector<T> {
    pub fn as_mut_ptr(&self) -> *mut T {
        unsafe { self.inner.as_ref().a as _ }
    }

    pub fn len(&self) -> usize {
        unsafe { self.inner.as_ref().len }
    }
}

impl<T> TryFrom<*mut RzVector> for Vector<T> {
    type Error = ();

    fn try_from(value: *mut RzVector) -> result::Result<Self, Self::Error> {
        Ok(Self {
            inner: NonNull::new(value).ok_or(())?,
            marker: PhantomData,
        })
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

impl<T> TryFrom<*mut RzPVector> for PVector<T> {
    type Error = ();

    fn try_from(value: *mut RzPVector) -> result::Result<Self, Self::Error> {
        let inner = NonNull::new(value).ok_or(())?;
        let v = unsafe { Vector::try_from(addr_of_mut!((*value).v))? };
        Ok(Self {
            inner,
            v: ManuallyDrop::new(v),
            marker: PhantomData,
        })
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
    use std::mem::size_of;

    use crate::wrapper::*;

    #[test]
    fn test_core() {
        let _ = Core::new();
    }

    #[test]
    fn test_vector() {
        let vec = unsafe {
            let x = rz_vector_new(size_of::<i32>(), None, null_mut());
            for i in 0..10 {
                rz_vector_push(x, addr_of!(i) as _);
            }
            Vector::<i32>::try_from(x).unwrap()
        };
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
            PVector::<i32>::try_from(x).unwrap()
        };
        assert_eq!(
            vec.iter().map(|x| *x as i32).collect::<Vec<i32>>(),
            (0..10).into_iter().collect::<Vec<i32>>()
        );
    }
    #[test]
    fn test_list() {
        let list = unsafe {
            let x = rz_list_new();
            for i in 0..10 {
                rz_list_push(x, i as _);
            }
            List::<i32>::try_from(x).unwrap()
        };
        assert_eq!(
            list.iter().map(|x| x as i32).collect::<Vec<i32>>(),
            (0..10).into_iter().collect::<Vec<i32>>()
        );
    }
}

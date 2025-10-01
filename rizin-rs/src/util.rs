use rizin_sys::rz_iterator_next;
use std::ffi::CStr;
use std::fmt::Display;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::ptr::{NonNull, addr_of, addr_of_mut, null_mut};
use std::{fmt, slice};

pub struct RzIterator<'a, T: 'a> {
    pub inner: NonNull<rizin_sys::RzIterator>,
    marker: PhantomData<&'a T>,
}

impl<'a, T: 'a> Iterator for RzIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let nptr = rz_iterator_next(self.inner.as_mut());
            if nptr.is_null() {
                None
            } else {
                (nptr as *const T).as_ref()
            }
        }
    }
}

impl<T> Drop for RzIterator<'_, T> {
    fn drop(&mut self) {
        unsafe {
            let inner = self.inner.as_ref();
            inner.free.map(|ff| ff(inner.cur));
            inner.free_u.map(|ff| ff(inner.u));
        }
    }
}

impl<T> RzIterator<'_, T> {
    pub fn from_raw(raw: *mut rizin_sys::RzIterator) -> Self {
        Self {
            inner: NonNull::new(raw).expect("null ptr"),
            marker: PhantomData,
        }
    }
    pub fn into_raw(self) -> *mut rizin_sys::RzIterator {
        let ptr = self.inner;
        std::mem::forget(self);
        ptr.as_ptr()
    }
}

pub struct RzStrBuf(pub rizin_sys::RzStrBuf);

impl RzStrBuf {
    pub fn new() -> Self {
        let mut sb = rizin_sys::RzStrBuf::default();
        unsafe { rizin_sys::rz_strbuf_init(addr_of_mut!(sb)) };
        Self(sb)
    }
}

impl Display for RzStrBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let cstr = unsafe { rizin_sys::rz_strbuf_get(addr_of!(self.0) as _) };
        if cstr.is_null() {
            Ok(())
        } else {
            let cstr = unsafe { CStr::from_ptr(cstr) };
            match cstr.to_str() {
                Ok(str) => f.write_str(str),
                Err(_) => Ok(()),
            }
        }
    }
}

impl Drop for RzStrBuf {
    fn drop(&mut self) {
        unsafe {
            rizin_sys::rz_strbuf_fini(addr_of_mut!(self.0));
        }
    }
}

pub struct RzList<T> {
    pub inner: NonNull<rizin_sys::RzList>,
    marker: PhantomData<T>,
}

pub struct RzListIter<'a, T: 'a> {
    head: Option<NonNull<rizin_sys::RzListIter>>,
    tail: Option<NonNull<rizin_sys::RzListIter>>,
    lst: &'a RzList<T>,
    marker: PhantomData<&'a T>,
}

impl<T> RzList<T> {
    fn from_raw(value: *mut rizin_sys::RzList) -> Option<Self> {
        NonNull::new(value).map(|inner| Self {
            inner,
            marker: PhantomData,
        })
    }

    fn into_raw(self) -> *mut rizin_sys::RzList {
        let ptr = self.inner.as_ptr();
        std::mem::forget(self);
        ptr
    }

    pub fn new() -> Self {
        let x = unsafe { rizin_sys::rz_list_new() };
        Self::from_raw(x).expect("null ptr")
    }

    pub fn push(&mut self, value: T) {
        unsafe {
            let val = Box::new(value);
            rizin_sys::rz_list_push(self.inner.as_ptr(), Box::into_raw(val) as _);
        }
    }

    pub fn pop(&mut self) -> Option<Box<T>> {
        if self.len() == 0 {
            None
        } else {
            let mut value: *mut T = unsafe { std::mem::zeroed() };
            unsafe {
                let v = rizin_sys::rz_list_pop(self.inner.as_ptr());
                if !v.is_null() {
                    value = v as *mut T;
                }
            }
            Some(unsafe { Box::from_raw(value) })
        }
    }

    pub fn len(&self) -> usize {
        unsafe { rizin_sys::rz_list_length(self.inner.as_ptr()) as _ }
    }

    pub fn iter(&self) -> RzListIter<'_, T> {
        unsafe {
            RzListIter {
                head: NonNull::new(self.inner.as_ref().head),
                tail: NonNull::new(self.inner.as_ref().tail),
                lst: self,
                marker: PhantomData,
            }
        }
    }
}

impl<T> Drop for RzList<T> {
    fn drop(&mut self) {
        unsafe {
            rizin_sys::rz_list_free(self.inner.as_ptr());
        }
    }
}

impl<'a, T> Iterator for RzListIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        self.head
            .map(|node| unsafe {
                let it = rizin_sys::rz_list_iter_get_next(node.as_ptr());
                self.head = NonNull::new(it);
                (node.as_ref().elem as *mut T).as_ref()
            })
            .flatten()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = unsafe { rizin_sys::rz_list_length(self.lst.inner.as_ptr()) };
        (len as _, Some(len as _))
    }
}

impl<'a, T> DoubleEndedIterator for RzListIter<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.tail
            .map(|node| unsafe {
                let it = rizin_sys::rz_list_iter_get_prev(node.as_ptr());
                self.tail = NonNull::new(it);
                (node.as_ref().elem as *mut T).as_ref()
            })
            .flatten()
    }
}

pub struct RzVector<T> {
    pub(crate) inner: NonNull<rizin_sys::RzVector>,
    marker: PhantomData<T>,
}

impl<T> RzVector<T> {
    fn from_raw(value: *mut rizin_sys::RzVector) -> Option<Self> {
        Some(Self {
            inner: NonNull::new(value)?,
            marker: PhantomData,
        })
    }
    fn into_raw(self) -> *mut rizin_sys::RzVector {
        let ptr = self.inner.as_ptr();
        std::mem::forget(self);
        ptr
    }

    pub fn new(len: usize) -> Self {
        let x = unsafe {
            let vec = rizin_sys::rz_vector_new(size_of::<T>(), None, null_mut());
            rizin_sys::rz_vector_reserve(vec, len);
            vec
        };
        Self::from_raw(x).unwrap()
    }

    pub fn push(&mut self, value: T) {
        unsafe {
            rizin_sys::rz_vector_push(self.inner.as_mut(), addr_of!(value) as _);
            std::mem::forget(value);
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len() == 0 {
            None
        } else {
            let mut value: T = unsafe { std::mem::zeroed() };
            unsafe {
                rizin_sys::rz_vector_pop(self.inner.as_mut(), addr_of_mut!(value) as _);
            }
            Some(value)
        }
    }

    pub fn insert(&mut self, index: usize, value: T) {
        unsafe {
            rizin_sys::rz_vector_insert(self.inner.as_mut(), index as _, addr_of!(value) as _);
            std::mem::forget(value);
        }
    }

    pub fn remove(&mut self, index: usize) -> Option<T> {
        if index >= self.len() {
            None
        } else {
            let mut value: T = unsafe { std::mem::zeroed() };
            unsafe {
                rizin_sys::rz_vector_remove_at(
                    self.inner.as_mut(),
                    index as _,
                    addr_of_mut!(value) as _,
                );
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

impl<T> TryFrom<Vec<T>> for RzVector<T> {
    type Error = ();

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        let mut vec = RzVector::new(value.len());
        value.into_iter().for_each(|x| vec.push(x));
        Ok(vec)
    }
}

impl<T> AsMut<[T]> for RzVector<T> {
    fn as_mut(&mut self) -> &mut [T] {
        unsafe { slice::from_raw_parts_mut(self.as_mut_ptr(), self.len()) }
    }
}

impl<T> Deref for RzVector<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.as_mut_ptr() as *const T, self.len()) }
    }
}

impl<T> DerefMut for RzVector<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { slice::from_raw_parts_mut(self.as_mut_ptr(), self.len()) }
    }
}

impl<T> Drop for RzVector<T> {
    fn drop(&mut self) {
        unsafe {
            rizin_sys::rz_vector_free(self.inner.as_mut());
        }
    }
}

pub struct RzPVector<T> {
    pub(crate) inner: NonNull<rizin_sys::RzPVector>,
    pub(crate) v: ManuallyDrop<RzVector<*mut T>>,
    marker: PhantomData<T>,
}

impl<T> RzPVector<T> {
    fn from_raw(value: *mut rizin_sys::RzPVector) -> Option<Self> {
        NonNull::new(value).and_then(|inner| {
            let v = unsafe { RzVector::from_raw(addr_of_mut!((*inner.as_ptr()).v))? };
            Some(Self {
                inner,
                v: ManuallyDrop::new(v),
                marker: PhantomData,
            })
        })
    }
    fn into_raw(self) -> *mut rizin_sys::RzPVector {
        let ptr = self.inner.as_ptr();
        std::mem::forget(self);
        ptr
    }
}

impl<T> Drop for RzPVector<T> {
    fn drop(&mut self) {
        unsafe {
            rizin_sys::rz_pvector_free(self.inner.as_ptr());
        }
    }
}

impl<T> AsMut<RzVector<*mut T>> for RzPVector<T> {
    fn as_mut(&mut self) -> &mut RzVector<*mut T> {
        &mut self.v
    }
}

impl<T> Deref for RzPVector<T> {
    type Target = RzVector<*mut T>;

    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

impl<T> DerefMut for RzPVector<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use crate::RzCore;
    use crate::util::{RzIterator, RzList, RzPVector, RzVector};
    use crate::*;
    use rizin_sys::{rz_iterator_new, rz_list_newf};
    use std::ffi::c_void;
    use std::ptr::{addr_of, null_mut};
    use std::vec;

    #[test]
    fn test_core() {
        let _ = RzCore::new();
    }

    unsafe extern "C" fn free_box(x: *mut c_void) {
        unsafe {
            if !x.is_null() {
                drop(Box::from_raw(x));
            }
        }
    }

    #[test]
    fn test_vector() {
        let vec = RzVector::try_from(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert_eq!(
            vec.iter().map(|x| *x).collect::<Vec<i32>>(),
            (0..10).into_iter().collect::<Vec<i32>>()
        );
    }
    #[test]
    fn test_pvector() {
        let vec = unsafe {
            let x = rizin_sys::rz_pvector_new(None);
            for i in 0..10 {
                rizin_sys::rz_vector_push(addr_of_mut!((*x).v), addr_of!(i) as _);
            }
            RzPVector::<i32>::from_raw(x).unwrap()
        };
        assert_eq!(
            vec.iter().map(|x| *x as i32).collect::<Vec<i32>>(),
            (0..10).into_iter().collect::<Vec<i32>>()
        );
    }

    #[test]
    fn test_list() {
        let mut list = RzList::from_raw(unsafe { rz_list_newf(Some(free_box)) }).unwrap();
        for i in 0..10 {
            list.push(i);
        }
        let act: Vec<i32> = list.iter().map(|x| *x).collect();
        assert_eq!(act, (0..10).into_iter().collect::<Vec<i32>>());
        let rev: Vec<i32> = list.iter().rev().map(|x| *x).collect();
        assert_eq!(rev, (0..10).rev().into_iter().collect::<Vec<i32>>());
    }

    #[test]
    fn test_iter() {
        unsafe extern "C" fn iter_n(x: *mut rizin_sys::RzIterator) -> *mut std::os::raw::c_void {
            unsafe {
                let x = &mut *x;
                let y: Box<i32> = Box::from_raw(x.u as _);
                if *y < 10 {
                    let ny = Box::new(*y + 1);
                    x.u = Box::into_raw(ny) as _;
                    Box::into_raw(y) as _
                } else {
                    x.u = null_mut();
                    null_mut()
                }
            }
        }

        let data = Box::new(0);
        let iter: RzIterator<i32> = RzIterator::from_raw(unsafe {
            rz_iterator_new(
                Some(iter_n),
                Some(free_box),
                Some(free_box),
                Box::into_raw(data) as _,
            )
        });
        let act: Vec<i32> = iter.map(|x| *x).collect();
        assert_eq!(act, (0..10).into_iter().collect::<Vec<i32>>());
    }
}

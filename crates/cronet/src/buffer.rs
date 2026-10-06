//! Memory Cronet reads response bodies into and upload bodies out of.

use std::{
    any::Any,
    fmt,
    ops::{Deref, DerefMut},
    ptr::{self, NonNull},
    slice,
    sync::OnceLock,
};

use cronet_sys as sys;

use crate::ffi::Opaque;

/// A block of memory Cronet reads or writes, owned by whoever holds it.
///
/// [`UrlRequest::read`](crate::UrlRequest::read) hands a buffer to Cronet, and
/// [`UrlRequestCallback::on_read_completed`](crate::UrlRequestCallback::on_read_completed)
/// hands it back, so one buffer can serve every read of a response.
pub struct Buffer(NonNull<sys::Cronet_Buffer>);

/// A borrowed [`Buffer`]: its bytes, through `Deref<Target = [u8]>`.
pub struct BufferRef(Opaque);

// SAFETY: a buffer is a block of memory with no thread affinity; whatever
// owns its memory is `Send` (`Buffer::from_owner`) or belongs to Cronet.
unsafe impl Send for Buffer {}
// SAFETY: `&` only reads.
unsafe impl Sync for Buffer {}
// SAFETY: as for `Buffer`.
unsafe impl Send for BufferRef {}
// SAFETY: as for `Buffer`.
unsafe impl Sync for BufferRef {}

/// What a buffer made by [`Buffer::from_owner`] keeps in its client context.
type Owner = Box<dyn Any + Send>;

impl Buffer {
    /// A buffer of `size` zeroed bytes, allocated by Cronet.
    pub fn zeroed(size: usize) -> Self {
        let buffer = Self::create();
        // SAFETY: the buffer is new and uninitialized; its memory is zeroed
        // before anything can read it.
        unsafe {
            sys::Cronet_Buffer_InitWithAlloc(buffer.0.as_ptr(), size as u64);
            let data = sys::Cronet_Buffer_GetData(buffer.0.as_ptr());
            if !data.is_null() {
                ptr::write_bytes(data.cast::<u8>(), 0, size);
            }
        }
        buffer
    }

    /// A buffer over the memory of `owner`, which it keeps until Cronet is
    /// done with it, then drops.
    pub fn from_owner<T: AsMut<[u8]> + Send + 'static>(owner: T) -> Self {
        let mut owner = Box::new(owner);
        let bytes = (*owner).as_mut();
        let (data, size) = (bytes.as_mut_ptr(), bytes.len());
        let owner: Box<Owner> = Box::new(owner);
        let buffer = Self::create();
        // SAFETY: the memory lives on the heap with `owner`, which the buffer
        // keeps in its client context until `drop_owner` frees it.
        unsafe {
            sys::Cronet_Buffer_SetClientContext(buffer.0.as_ptr(), Box::into_raw(owner).cast());
            sys::Cronet_Buffer_InitWithDataAndCallback(buffer.0.as_ptr(), data.cast(), size as u64, owner_callback());
        }
        buffer
    }

    fn create() -> Self {
        // SAFETY: allocation has no preconditions.
        Self(NonNull::new(unsafe { sys::Cronet_Buffer_Create() }).expect("Cronet_Buffer_Create returned null"))
    }

    /// # Safety
    ///
    /// `raw` is a live, initialized buffer whose ownership passes to the result.
    pub(crate) unsafe fn from_raw(raw: sys::Cronet_BufferPtr) -> Self {
        Self(NonNull::new(raw).expect("Cronet passed a null buffer"))
    }

    pub(crate) fn into_raw(self) -> sys::Cronet_BufferPtr {
        std::mem::ManuallyDrop::new(self).0.as_ptr()
    }
}

impl From<Vec<u8>> for Buffer {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_owner(bytes)
    }
}

impl From<Box<[u8]>> for Buffer {
    fn from(bytes: Box<[u8]>) -> Self {
        Self::from_owner(bytes)
    }
}

impl From<bytes::BytesMut> for Buffer {
    fn from(bytes: bytes::BytesMut) -> Self {
        Self::from_owner(bytes)
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: the buffer is owned; destroying it runs its callback, if any.
        unsafe { sys::Cronet_Buffer_Destroy(self.0.as_ptr()) }
    }
}

impl Deref for Buffer {
    type Target = BufferRef;

    fn deref(&self) -> &BufferRef {
        // SAFETY: the buffer lives as long as `self`.
        unsafe { BufferRef::from_ptr(self.0.as_ptr()) }
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut BufferRef {
        // SAFETY: the buffer lives as long as `self`, borrowed uniquely.
        unsafe { BufferRef::from_ptr_mut(self.0.as_ptr()) }
    }
}

impl BufferRef {
    /// # Safety
    ///
    /// `ptr` is a live, initialized buffer, unmodified for `'a`.
    pub(crate) unsafe fn from_ptr<'a>(ptr: sys::Cronet_BufferPtr) -> &'a Self {
        // SAFETY: `Self` is zero-sized; the caller vouches for the buffer.
        unsafe { &*ptr.cast::<Self>() }
    }

    /// # Safety
    ///
    /// `ptr` is a live, initialized buffer, untouched by anything else for `'a`.
    pub(crate) unsafe fn from_ptr_mut<'a>(ptr: sys::Cronet_BufferPtr) -> &'a mut Self {
        // SAFETY: `Self` is zero-sized; the caller vouches for the buffer.
        unsafe { &mut *ptr.cast::<Self>() }
    }

    fn as_ptr(&self) -> sys::Cronet_BufferPtr {
        (self as *const Self).cast_mut().cast()
    }

    fn raw_parts(&self) -> (*mut u8, usize) {
        // SAFETY: the buffer is live.
        unsafe {
            let size = sys::Cronet_Buffer_GetSize(self.as_ptr());
            (sys::Cronet_Buffer_GetData(self.as_ptr()).cast(), size as usize)
        }
    }
}

impl Deref for BufferRef {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self.raw_parts() {
            (_, 0) => &[],
            // SAFETY: the buffer's memory is initialized (`Buffer::zeroed`
            // clears it) and lives as long as the buffer.
            (data, size) => unsafe { slice::from_raw_parts(data, size) },
        }
    }
}

impl DerefMut for BufferRef {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self.raw_parts() {
            (_, 0) => &mut [],
            // SAFETY: as for `deref`, and `&mut self` makes the access unique.
            (data, size) => unsafe { slice::from_raw_parts_mut(data, size) },
        }
    }
}

impl fmt::Debug for BufferRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

/// The one callback every `from_owner` buffer shares: it frees the owner kept
/// in the destroyed buffer's client context.
fn owner_callback() -> sys::Cronet_BufferCallbackPtr {
    struct Callback(sys::Cronet_BufferCallbackPtr);
    // SAFETY: the callback is stateless and lives for the whole process.
    unsafe impl Send for Callback {}
    // SAFETY: as above.
    unsafe impl Sync for Callback {}

    static CALLBACK: OnceLock<Callback> = OnceLock::new();
    CALLBACK
        .get_or_init(|| {
            // SAFETY: `drop_owner` matches `Cronet_BufferCallback_OnDestroyFunc`.
            Callback(unsafe { sys::Cronet_BufferCallback_CreateWith(Some(drop_owner)) })
        })
        .0
}

unsafe extern "C" fn drop_owner(_: sys::Cronet_BufferCallbackPtr, buffer: sys::Cronet_BufferPtr) {
    // SAFETY: called while the buffer is being destroyed, when its members
    // are still intact; its context is the `Owner` `from_owner` leaked.
    unsafe {
        let owner = sys::Cronet_Buffer_GetClientContext(buffer);
        if !owner.is_null() {
            drop(Box::from_raw(owner.cast::<Owner>()));
        }
    }
}

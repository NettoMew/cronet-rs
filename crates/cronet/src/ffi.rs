//! What every wrapper needs from the C side: strings both ways, and the
//! macros that turn Cronet's objects into owned and borrowed Rust types.

use std::{
    borrow::Cow,
    cell::UnsafeCell,
    ffi::{CStr, CString, c_char},
    marker::PhantomData,
};

/// Reads a string Cronet owns, without copying when it is UTF-8.
///
/// # Safety
///
/// `ptr` is null or points to a nul-terminated string that stays unmodified
/// and alive for `'a`.
pub(crate) unsafe fn string<'a>(ptr: *const c_char) -> Cow<'a, str> {
    if ptr.is_null() {
        return Cow::Borrowed("");
    }
    // SAFETY: forwarded to the caller.
    String::from_utf8_lossy(unsafe { CStr::from_ptr(ptr) }.to_bytes())
}

/// A string for Cronet to copy.
///
/// # Panics
///
/// If `value` contains a NUL byte: C cannot represent it.
pub(crate) fn c_string(value: &str) -> CString {
    CString::new(value).unwrap_or_else(|_| panic!("string passed to Cronet contains a NUL byte: {value:?}"))
}

/// The body of a borrowed handle: zero-sized, so a `&Ref` can be made from
/// the object's address, and neither `Send` nor `Sync` unless granted.
pub(crate) struct Opaque(UnsafeCell<PhantomData<*mut ()>>);

/// Declares an owned handle to a Cronet value object (`$owned`, destroyed on
/// drop) and its borrowed form (`$borrowed`, as `&` or `&mut`), the way the
/// standard library pairs `String` with `str`.
macro_rules! value_type {
    (
        $(#[$meta:meta])*
        pub struct $owned:ident / $borrowed:ident ($raw:ty) {
            create: $create:path,
            destroy: $destroy:path $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $owned(::core::ptr::NonNull<$raw>);

        #[doc = concat!("A borrowed [`", stringify!($owned), "`], owned by Cronet or by an `", stringify!($owned), "`.")]
        pub struct $borrowed($crate::ffi::Opaque);

        impl $owned {
            #[doc = concat!("A new `", stringify!($owned), "` with Cronet's defaults.")]
            pub fn new() -> Self {
                // SAFETY: allocation has no preconditions.
                let raw = unsafe { $create() };
                Self(::core::ptr::NonNull::new(raw).expect(concat!(stringify!($create), " returned null")))
            }

            #[allow(dead_code)]
            pub(crate) fn into_raw(self) -> *mut $raw {
                ::core::mem::ManuallyDrop::new(self).0.as_ptr()
            }
        }

        impl Default for $owned {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Drop for $owned {
            fn drop(&mut self) {
                // SAFETY: the handle owns the object, and nothing borrows it any more.
                unsafe { $destroy(self.0.as_ptr()) }
            }
        }

        impl ::core::ops::Deref for $owned {
            type Target = $borrowed;

            fn deref(&self) -> &$borrowed {
                // SAFETY: the object lives as long as the handle.
                unsafe { $borrowed::from_ptr(self.0.as_ptr()) }
            }
        }

        impl ::core::ops::DerefMut for $owned {
            fn deref_mut(&mut self) -> &mut $borrowed {
                // SAFETY: the object lives as long as the handle, which is borrowed uniquely.
                unsafe { $borrowed::from_ptr_mut(self.0.as_ptr()) }
            }
        }

        impl ::core::borrow::Borrow<$borrowed> for $owned {
            fn borrow(&self) -> &$borrowed {
                self
            }
        }

        impl AsRef<$borrowed> for $owned {
            fn as_ref(&self) -> &$borrowed {
                self
            }
        }

        #[allow(dead_code)]
        impl $borrowed {
            /// # Safety
            ///
            /// `ptr` points to a live object that nothing modifies for `'a`.
            pub(crate) unsafe fn from_ptr<'a>(ptr: *mut $raw) -> &'a Self {
                // SAFETY: `Self` is zero-sized; the caller vouches for the object.
                unsafe { &*ptr.cast::<Self>() }
            }

            /// # Safety
            ///
            /// `ptr` points to a live object that nothing else touches for `'a`.
            pub(crate) unsafe fn from_ptr_mut<'a>(ptr: *mut $raw) -> &'a mut Self {
                // SAFETY: `Self` is zero-sized; the caller vouches for the object.
                unsafe { &mut *ptr.cast::<Self>() }
            }

            pub(crate) fn as_ptr(&self) -> *mut $raw {
                (self as *const Self).cast_mut().cast()
            }
        }

        // SAFETY: Cronet's value objects are plain data with no thread
        // affinity; `&` only reads them and `&mut` is exclusive.
        unsafe impl Send for $owned {}
        // SAFETY: as above.
        unsafe impl Sync for $owned {}
        // SAFETY: as above.
        unsafe impl Send for $borrowed {}
        // SAFETY: as above.
        unsafe impl Sync for $borrowed {}
    };
}

/// Getter and setter pairs for the fields of a Cronet value object, on its
/// borrowed type. Setters return `&mut Self` so that they chain.
macro_rules! properties {
    ($borrowed:ident { $($body:tt)* }) => {
        impl $borrowed {
            $crate::ffi::properties!(@each $($body)*);
        }
    };

    (@each) => {};

    (@each $(#[$meta:meta])* string $name:ident, $set_name:ident: $get:path, $set:path; $($rest:tt)*) => {
        $(#[$meta])*
        pub fn $name(&self) -> ::std::borrow::Cow<'_, str> {
            // SAFETY: the object is live, and the string is not modified while `self` is borrowed.
            unsafe { $crate::ffi::string($get(self.as_ptr())) }
        }

        #[doc = concat!("Sets [`", stringify!($name), "`](Self::", stringify!($name), ").")]
        ///
        /// # Panics
        ///
        /// If `value` contains a NUL byte.
        pub fn $set_name(&mut self, value: &str) -> &mut Self {
            let value = $crate::ffi::c_string(value);
            // SAFETY: the object is live and uniquely borrowed; Cronet copies the string.
            unsafe { $set(self.as_ptr(), value.as_ptr()) };
            self
        }

        $crate::ffi::properties!(@each $($rest)*);
    };

    (@each $(#[$meta:meta])* $ty:ty as $name:ident, $set_name:ident: $get:path, $set:path; $($rest:tt)*) => {
        $(#[$meta])*
        pub fn $name(&self) -> $ty {
            // SAFETY: the object is live.
            <$ty as $crate::ffi::FromC>::from_c(unsafe { $get(self.as_ptr()) })
        }

        #[doc = concat!("Sets [`", stringify!($name), "`](Self::", stringify!($name), ").")]
        pub fn $set_name(&mut self, value: $ty) -> &mut Self {
            // SAFETY: the object is live and uniquely borrowed.
            unsafe { $set(self.as_ptr(), $crate::ffi::FromC::into_c(value)) };
            self
        }

        $crate::ffi::properties!(@each $($rest)*);
    };
}

pub(crate) use {properties, value_type};

/// A Rust value with a C representation that converts losslessly both ways
/// (or, for enums, maps unknown values to a fallback).
pub(crate) trait FromC: Sized {
    type C;
    fn from_c(c: Self::C) -> Self;
    fn into_c(self) -> Self::C;
}

macro_rules! identity_from_c {
    ($($ty:ty),*) => {$(
        impl FromC for $ty {
            type C = $ty;
            fn from_c(c: $ty) -> $ty {
                c
            }
            fn into_c(self) -> $ty {
                self
            }
        }
    )*};
}

identity_from_c!(bool, i32, i64, u64, f64);

/// A Rust enum over a C enum, with the variant unknown C values become.
macro_rules! c_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident: $raw:ty {
            $( $(#[$variant_meta:meta])* $variant:ident = $c:path, )*
        }
        unknown => $fallback:ident;
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$variant_meta])* $variant, )*
        }

        impl $crate::ffi::FromC for $name {
            type C = $raw;

            fn from_c(c: $raw) -> Self {
                match c {
                    $( $c => Self::$variant, )*
                    _ => Self::$fallback,
                }
            }

            fn into_c(self) -> $raw {
                match self {
                    $( Self::$variant => $c, )*
                }
            }
        }
    };
}

pub(crate) use c_enum;

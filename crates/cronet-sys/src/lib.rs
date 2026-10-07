//! Raw bindings to Cronet's C API, as built by [naiveproxy]: the generated
//! `cronet.idl` API, the stream engine and dialer additions of `cronet_c.h`,
//! and the bidirectional stream API of gRPC support.
//!
//! The library is reached one of two ways:
//!
//! - **Linked** (default): `libcronet` is linked when the final binary is.
//!   Point `CRONET_LIB_DIR` at a directory produced by `cargo xtask package`,
//!   or leave it unset to link whatever `cronet` the linker finds.
//! - **Loaded** (feature `dynamic`): nothing is linked; `libcronet` is opened at
//!   run time by [`load`], or on first use from the default locations.
//!
//! Either way the functions below have the same names and signatures, so code
//! written against them does not care which.
//!
//! The program being built has the last word: with `CRONET_LINK_KIND` set,
//! the library is linked even when a dependency asked for `dynamic`, and
//! [`load`] finds it open from the start. That is how a static executable,
//! which can open nothing at run time, gets it.
//!
//! [naiveproxy]: https://github.com/klzgrad/naiveproxy

#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    clippy::missing_safety_doc
)]
#![allow(rustdoc::broken_intra_doc_links, rustdoc::invalid_html_tags, rustdoc::bare_urls)]

/// Declares the C functions. Generated bindings invoke this once with every
/// function; what it expands to depends on how the library is reached.
#[cfg(linked)]
macro_rules! cronet_api {
    ($( $(#[$meta:meta])* pub fn $name:ident($($arg:ident: $ty:ty),* $(,)?) $(-> $ret:ty)?; )*) => {
        unsafe extern "C" {
            $( $(#[$meta])* pub fn $name($($arg: $ty),*) $(-> $ret)?; )*
        }
    };
}

#[cfg(not(linked))]
macro_rules! cronet_api {
    ($( $(#[$meta:meta])* pub fn $name:ident($($arg:ident: $ty:ty),* $(,)?) $(-> $ret:ty)?; )*) => {
        /// Every entry point, resolved once when the library is loaded.
        pub(crate) struct Api {
            $( $name: unsafe extern "C" fn($($ty),*) $(-> $ret)?, )*
        }

        impl Api {
            /// # Safety
            ///
            /// `library` must be libcronet, so that each symbol has the
            /// signature declared here.
            pub(crate) unsafe fn resolve(library: &$crate::loader::Library) -> Result<Self, $crate::LoadError> {
                Ok(Self {
                    // SAFETY: the caller vouches for the signatures.
                    $( $name: unsafe { library.symbol(concat!(stringify!($name), "\0"))? }, )*
                })
            }
        }

        $(
            $(#[$meta])*
            #[inline]
            #[allow(clippy::too_many_arguments)]
            pub unsafe fn $name($($arg: $ty),*) $(-> $ret)? {
                // SAFETY: forwarded; the caller upholds the C function's contract.
                unsafe { ($crate::loader::api().$name)($($arg),*) }
            }
        )*
    };
}

mod bindings;
mod loader;

/// The Chromium version the bindings' headers come from, such as
/// `150.0.7871.63`: what a matching library reports as its version.
pub const CHROMIUM_VERSION: &str = include_str!("../include/CHROMIUM_VERSION").trim_ascii();

pub use bindings::*;
pub use loader::{LoadError, ensure_loaded};
#[cfg(feature = "dynamic")]
pub use loader::{is_loaded, load, load_default};

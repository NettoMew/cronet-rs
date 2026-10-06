//! Opening libcronet at run time (feature `dynamic`).
//!
//! The library is opened at most once per process: the first of [`load`],
//! [`load_default`], or any binding called before them wins, and its outcome,
//! success or failure, is what every later call sees.
//!
//! When linked instead, only [`LoadError`] and [`ensure_loaded`] remain, so
//! that code built either way can check for the library the same way.

use std::{error, fmt, path::PathBuf};

/// libcronet could not be opened.
#[derive(Debug, Clone)]
pub struct LoadError {
    kind: Kind,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
enum Kind {
    /// Nothing by any of the names opened; why, for each attempt.
    NotFound(Vec<String>),
    Open {
        path: PathBuf,
        reason: String,
    },
    Symbol {
        name: &'static str,
        reason: String,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::NotFound(attempts) => write!(f, "libcronet not found ({})", attempts.join("; ")),
            Kind::Open { path, reason } => write!(f, "cannot open {}: {reason}", path.display()),
            Kind::Symbol { name, reason } => write!(f, "libcronet lacks {name}: {reason}"),
        }
    }
}

impl error::Error for LoadError {}

/// Makes sure the library is there before anything calls into it: a linked
/// library always is; a loaded one is opened from the default locations if
/// nothing has opened it yet.
pub fn ensure_loaded() -> Result<(), LoadError> {
    #[cfg(feature = "dynamic")]
    return dynamic::load_default();
    #[cfg(not(feature = "dynamic"))]
    Ok(())
}

#[cfg(feature = "dynamic")]
pub(crate) use dynamic::{Library, api};
#[cfg(feature = "dynamic")]
pub use dynamic::{is_loaded, load, load_default};

#[cfg(feature = "dynamic")]
mod dynamic {
    use std::{
        env,
        path::{Path, PathBuf},
        sync::OnceLock,
    };

    use super::{Kind, LoadError};
    use crate::bindings::Api;

    /// The file names the library goes by, in order of preference.
    const NAMES: &[&str] = if cfg!(windows) {
        // Chromium's build makes `cronet.dll`; release archives often rename it.
        &["cronet.dll", "libcronet.dll"]
    } else if cfg!(target_vendor = "apple") {
        &["libcronet.dylib"]
    } else {
        &["libcronet.so"]
    };

    struct Loaded {
        api: Api,
        // The functions in `api` point into this; it is never unloaded.
        _library: Library,
    }

    static LIBRARY: OnceLock<Result<Loaded, LoadError>> = OnceLock::new();

    /// Opens libcronet from `path`, unless it is already open.
    ///
    /// Only the first attempt to open the library counts: if it is already
    /// open, or failed to open, this returns that outcome and ignores `path`.
    pub fn load(path: impl Into<PathBuf>) -> Result<(), LoadError> {
        let path = path.into();
        outcome(LIBRARY.get_or_init(|| open(&path)))
    }

    /// Opens libcronet from where an application would ship it, unless it is
    /// already open: next to the executable first, then wherever the system's
    /// loader looks for a library by name (`LD_LIBRARY_PATH` and the linker
    /// cache on Linux, `PATH` among others on Windows).
    pub fn load_default() -> Result<(), LoadError> {
        outcome(LIBRARY.get_or_init(open_default))
    }

    /// Whether the library is open.
    pub fn is_loaded() -> bool {
        matches!(LIBRARY.get(), Some(Ok(_)))
    }

    /// The entry points, opening the library on first use.
    ///
    /// # Panics
    ///
    /// If the library cannot be opened: a binding was called with nothing to
    /// call into.
    pub(crate) fn api() -> &'static Api {
        match LIBRARY.get_or_init(open_default) {
            Ok(loaded) => &loaded.api,
            Err(error) => panic!("{error}"),
        }
    }

    fn outcome(result: &Result<Loaded, LoadError>) -> Result<(), LoadError> {
        result.as_ref().map(|_| ()).map_err(Clone::clone)
    }

    fn open_default() -> Result<Loaded, LoadError> {
        if let Some(directory) = env::current_exe().ok().as_deref().and_then(Path::parent) {
            for name in NAMES {
                let path = directory.join(name);
                if path.is_file() {
                    return open(&path);
                }
            }
        }
        let mut attempts = Vec::new();
        for name in NAMES {
            match open(Path::new(name)) {
                Err(LoadError {
                    kind: Kind::Open { reason, .. },
                }) => attempts.push(format!("{name}: {reason}")),
                found => return found,
            }
        }
        Err(LoadError {
            kind: Kind::NotFound(attempts),
        })
    }

    fn open(path: &Path) -> Result<Loaded, LoadError> {
        // SAFETY: libcronet's initializers have no preconditions, and it is
        // never unloaded, so its finalizers never run under us.
        let library = unsafe { libloading::Library::new(path) }
            .map(Library)
            .map_err(|error| LoadError {
                kind: Kind::Open {
                    path: path.to_owned(),
                    reason: error.to_string(),
                },
            })?;
        // SAFETY: the library is libcronet, whose symbols have the signatures
        // the bindings declare.
        let api = unsafe { Api::resolve(&library)? };
        Ok(Loaded { api, _library: library })
    }

    /// An open libcronet.
    pub(crate) struct Library(libloading::Library);

    impl Library {
        /// The address of the nul-terminated symbol `name`, as a `T`.
        ///
        /// # Safety
        ///
        /// `T` must be the type of the symbol: here, its function pointer type.
        pub(crate) unsafe fn symbol<T: Copy>(&self, name: &'static str) -> Result<T, LoadError> {
            // SAFETY: forwarded to the caller.
            match unsafe { self.0.get::<T>(name) } {
                Ok(symbol) => Ok(*symbol),
                Err(error) => {
                    let name = name.strip_suffix('\0').unwrap_or(name);
                    Err(LoadError {
                        kind: Kind::Symbol {
                            name,
                            reason: error.to_string(),
                        },
                    })
                }
            }
        }
    }
}

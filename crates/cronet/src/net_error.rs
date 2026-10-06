//! Chromium's network error codes.

use std::{error, fmt, io};

mod generated;

/// A Chromium network error: one of the negative codes in
/// `net/base/net_error_list.h`, such as [`NetError::CONNECTION_REFUSED`].
///
/// Cronet reports these from streams and requests, and expects them back from
/// dialers. Codes this version does not know are kept as they are.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetError(i32);

/// One row of the table generated from `net_error_list.h`.
pub(crate) struct Entry {
    code: i32,
    name: &'static str,
    description: &'static str,
}

impl NetError {
    /// The error with Chromium's numeric `code`.
    pub const fn from_code(code: i32) -> Self {
        Self(code)
    }

    /// The numeric code, such as `-102`.
    pub const fn code(self) -> i32 {
        self.0
    }

    fn entry(self) -> Option<&'static Entry> {
        generated::TABLE
            .binary_search_by_key(&self.0, |entry| entry.code)
            .ok()
            .map(|index| &generated::TABLE[index])
    }

    /// Chromium's name, such as `ERR_CONNECTION_REFUSED`; `None` for a code
    /// this version does not know.
    pub fn name(self) -> Option<&'static str> {
        self.entry().map(|entry| entry.name)
    }

    /// The comment Chromium documents the error with; empty if there is none.
    pub fn description(self) -> &'static str {
        self.entry().map_or("", |entry| entry.description)
    }

    /// Whether the error is a timeout.
    pub fn is_timeout(self) -> bool {
        self == Self::TIMED_OUT || self == Self::CONNECTION_TIMED_OUT
    }

    /// The `std::io` kind closest to the error: the one the matching socket
    /// error would have, `Other` when there is none.
    pub fn io_kind(self) -> io::ErrorKind {
        use io::ErrorKind::*;
        match self {
            Self::CONNECTION_REFUSED => ConnectionRefused,
            Self::CONNECTION_RESET => ConnectionReset,
            Self::CONNECTION_ABORTED => ConnectionAborted,
            Self::CONNECTION_CLOSED => UnexpectedEof,
            Self::SOCKET_NOT_CONNECTED => NotConnected,
            Self::TIMED_OUT | Self::CONNECTION_TIMED_OUT => TimedOut,
            Self::ADDRESS_UNREACHABLE => HostUnreachable,
            Self::ADDRESS_IN_USE => AddrInUse,
            Self::ADDRESS_INVALID | Self::INVALID_ARGUMENT => InvalidInput,
            Self::INTERNET_DISCONNECTED => NetworkDown,
            Self::ACCESS_DENIED => PermissionDenied,
            Self::FILE_NOT_FOUND => NotFound,
            Self::OUT_OF_MEMORY => OutOfMemory,
            Self::NOT_IMPLEMENTED => Unsupported,
            _ => Other,
        }
    }

    /// The error to give Cronet for a failed dial: the one inside `error` if
    /// it carries one, else the closest match by kind, else
    /// [`CONNECTION_FAILED`](Self::CONNECTION_FAILED).
    pub fn from_io_error(error: &io::Error) -> Self {
        if let Some(net_error) = error.get_ref().and_then(|inner| inner.downcast_ref::<Self>()) {
            return *net_error;
        }
        match error.kind() {
            io::ErrorKind::TimedOut => Self::CONNECTION_TIMED_OUT,
            io::ErrorKind::ConnectionRefused => Self::CONNECTION_REFUSED,
            io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => Self::ADDRESS_UNREACHABLE,
            io::ErrorKind::ConnectionReset => Self::CONNECTION_RESET,
            io::ErrorKind::ConnectionAborted => Self::CONNECTION_ABORTED,
            io::ErrorKind::Interrupted => Self::ABORTED,
            _ => Self::CONNECTION_FAILED,
        }
    }
}

/// As Chromium prints it: `net::ERR_CONNECTION_REFUSED`.
impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "net::{name}"),
            None => write!(f, "net error {}", self.0),
        }
    }
}

impl fmt::Debug for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetError({}", self.0)?;
        if let Some(name) = self.name() {
            write!(f, " {name}")?;
        }
        f.write_str(")")
    }
}

impl error::Error for NetError {}

impl From<NetError> for io::Error {
    fn from(error: NetError) -> Self {
        io::Error::new(error.io_kind(), error)
    }
}

impl From<&io::Error> for NetError {
    fn from(error: &io::Error) -> Self {
        Self::from_io_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_complete() {
        assert!(generated::TABLE.windows(2).all(|pair| pair[0].code < pair[1].code));
        assert_eq!(NetError::CONNECTION_REFUSED.code(), -102);
        assert_eq!(NetError::CONNECTION_REFUSED.name(), Some("ERR_CONNECTION_REFUSED"));
        assert_eq!(NetError::CONNECTION_REFUSED.to_string(), "net::ERR_CONNECTION_REFUSED");
        assert_eq!(
            format!("{:?}", NetError::CONNECTION_REFUSED),
            "NetError(-102 ERR_CONNECTION_REFUSED)"
        );
        assert_eq!(
            NetError::CONNECTION_REFUSED.description(),
            "A connection attempt was refused."
        );
    }

    #[test]
    fn unknown_codes_survive() {
        let unknown = NetError::from_code(-99999);
        assert_eq!(unknown.name(), None);
        assert_eq!(unknown.to_string(), "net error -99999");
        assert_eq!(format!("{unknown:?}"), "NetError(-99999)");
        assert_eq!(unknown.description(), "");
    }

    #[test]
    fn round_trips_through_io_errors() {
        let error = io::Error::from(NetError::ADDRESS_UNREACHABLE);
        assert_eq!(error.kind(), io::ErrorKind::HostUnreachable);
        assert_eq!(NetError::from_io_error(&error), NetError::ADDRESS_UNREACHABLE);
        assert_eq!(
            NetError::from_io_error(&io::ErrorKind::TimedOut.into()),
            NetError::CONNECTION_TIMED_OUT
        );
        assert_eq!(
            NetError::from_io_error(&io::Error::other("x")),
            NetError::CONNECTION_FAILED
        );
    }
}

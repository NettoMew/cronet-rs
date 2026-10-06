//! The two kinds of failure Cronet reports: an API call it refused
//! ([`ApiError`]), and a request that failed ([`Error`]).

use std::{borrow::Cow, error, fmt};

use cronet_sys as sys;

use crate::{
    NetError,
    ffi::{c_enum, properties, value_type},
};

/// An API call Cronet refused: its `Cronet_RESULT` when that is not success.
///
/// Cronet aborts the process on these instead, unless
/// [`EngineParams::set_enable_check_result`](crate::EngineParamsRef::set_enable_check_result)
/// turned that off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ApiError {
    /// Illegal argument.
    IllegalArgument,
    /// Storage path must be set to existing directory.
    IllegalArgumentStoragePathMustExist,
    /// Public key pin is invalid.
    IllegalArgumentInvalidPin,
    /// Host name is invalid.
    IllegalArgumentInvalidHostname,
    /// Invalid HTTP method.
    IllegalArgumentInvalidHttpMethod,
    /// Invalid HTTP header.
    IllegalArgumentInvalidHttpHeader,
    /// Illegal state.
    IllegalState,
    /// Storage path is used by another engine.
    IllegalStateStoragePathInUse,
    /// Cannot shut down the engine from the network thread.
    IllegalStateCannotShutdownEngineFromNetworkThread,
    /// The engine has already started.
    IllegalStateEngineAlreadyStarted,
    /// The request has already started.
    IllegalStateRequestAlreadyStarted,
    /// The request is not initialized.
    IllegalStateRequestNotInitialized,
    /// The request is already initialized.
    IllegalStateRequestAlreadyInitialized,
    /// The request is not started.
    IllegalStateRequestNotStarted,
    /// No redirect to follow.
    IllegalStateUnexpectedRedirect,
    /// Unexpected read attempt.
    IllegalStateUnexpectedRead,
    /// Unexpected read failure.
    IllegalStateReadFailed,
    /// Null pointer or empty data.
    NullPointer,
    /// The hostname cannot be null.
    NullPointerHostname,
    /// The set of SHA-256 pins cannot be null.
    NullPointerSha256Pins,
    /// The pin expiration date cannot be null.
    NullPointerExpirationDate,
    /// Engine is required.
    NullPointerEngine,
    /// URL is required.
    NullPointerUrl,
    /// Callback is required.
    NullPointerCallback,
    /// Executor is required.
    NullPointerExecutor,
    /// Method is required.
    NullPointerMethod,
    /// Invalid header name.
    NullPointerHeaderName,
    /// Invalid header value.
    NullPointerHeaderValue,
    /// Params is required.
    NullPointerParams,
    /// Executor for RequestFinishedInfoListener is required.
    NullPointerRequestFinishedInfoListenerExecutor,
    /// A code this version of the crate does not know.
    Unknown(i32),
}

macro_rules! api_error_codes {
    ($($variant:ident = $c:path,)*) => {
        impl ApiError {
            /// `Ok` for success, the error otherwise.
            pub(crate) fn check(result: sys::Cronet_RESULT) -> Result<(), Self> {
                match result {
                    sys::Cronet_RESULT_SUCCESS => Ok(()),
                    $( $c => Err(Self::$variant), )*
                    other => Err(Self::Unknown(other)),
                }
            }

            /// Cronet's numeric code.
            pub fn code(self) -> i32 {
                match self {
                    $( Self::$variant => $c, )*
                    Self::Unknown(code) => code,
                }
            }
        }
    };
}

api_error_codes! {
    IllegalArgument = sys::Cronet_RESULT_ILLEGAL_ARGUMENT,
    IllegalArgumentStoragePathMustExist = sys::Cronet_RESULT_ILLEGAL_ARGUMENT_STORAGE_PATH_MUST_EXIST,
    IllegalArgumentInvalidPin = sys::Cronet_RESULT_ILLEGAL_ARGUMENT_INVALID_PIN,
    IllegalArgumentInvalidHostname = sys::Cronet_RESULT_ILLEGAL_ARGUMENT_INVALID_HOSTNAME,
    IllegalArgumentInvalidHttpMethod = sys::Cronet_RESULT_ILLEGAL_ARGUMENT_INVALID_HTTP_METHOD,
    IllegalArgumentInvalidHttpHeader = sys::Cronet_RESULT_ILLEGAL_ARGUMENT_INVALID_HTTP_HEADER,
    IllegalState = sys::Cronet_RESULT_ILLEGAL_STATE,
    IllegalStateStoragePathInUse = sys::Cronet_RESULT_ILLEGAL_STATE_STORAGE_PATH_IN_USE,
    IllegalStateCannotShutdownEngineFromNetworkThread =
        sys::Cronet_RESULT_ILLEGAL_STATE_CANNOT_SHUTDOWN_ENGINE_FROM_NETWORK_THREAD,
    IllegalStateEngineAlreadyStarted = sys::Cronet_RESULT_ILLEGAL_STATE_ENGINE_ALREADY_STARTED,
    IllegalStateRequestAlreadyStarted = sys::Cronet_RESULT_ILLEGAL_STATE_REQUEST_ALREADY_STARTED,
    IllegalStateRequestNotInitialized = sys::Cronet_RESULT_ILLEGAL_STATE_REQUEST_NOT_INITIALIZED,
    IllegalStateRequestAlreadyInitialized = sys::Cronet_RESULT_ILLEGAL_STATE_REQUEST_ALREADY_INITIALIZED,
    IllegalStateRequestNotStarted = sys::Cronet_RESULT_ILLEGAL_STATE_REQUEST_NOT_STARTED,
    IllegalStateUnexpectedRedirect = sys::Cronet_RESULT_ILLEGAL_STATE_UNEXPECTED_REDIRECT,
    IllegalStateUnexpectedRead = sys::Cronet_RESULT_ILLEGAL_STATE_UNEXPECTED_READ,
    IllegalStateReadFailed = sys::Cronet_RESULT_ILLEGAL_STATE_READ_FAILED,
    NullPointer = sys::Cronet_RESULT_NULL_POINTER,
    NullPointerHostname = sys::Cronet_RESULT_NULL_POINTER_HOSTNAME,
    NullPointerSha256Pins = sys::Cronet_RESULT_NULL_POINTER_SHA256_PINS,
    NullPointerExpirationDate = sys::Cronet_RESULT_NULL_POINTER_EXPIRATION_DATE,
    NullPointerEngine = sys::Cronet_RESULT_NULL_POINTER_ENGINE,
    NullPointerUrl = sys::Cronet_RESULT_NULL_POINTER_URL,
    NullPointerCallback = sys::Cronet_RESULT_NULL_POINTER_CALLBACK,
    NullPointerExecutor = sys::Cronet_RESULT_NULL_POINTER_EXECUTOR,
    NullPointerMethod = sys::Cronet_RESULT_NULL_POINTER_METHOD,
    NullPointerHeaderName = sys::Cronet_RESULT_NULL_POINTER_HEADER_NAME,
    NullPointerHeaderValue = sys::Cronet_RESULT_NULL_POINTER_HEADER_VALUE,
    NullPointerParams = sys::Cronet_RESULT_NULL_POINTER_PARAMS,
    NullPointerRequestFinishedInfoListenerExecutor =
        sys::Cronet_RESULT_NULL_POINTER_REQUEST_FINISHED_INFO_LISTENER_EXECUTOR,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::IllegalArgument => "illegal argument",
            Self::IllegalArgumentStoragePathMustExist => "storage path must be set to an existing directory",
            Self::IllegalArgumentInvalidPin => "public key pin is invalid",
            Self::IllegalArgumentInvalidHostname => "host name is invalid",
            Self::IllegalArgumentInvalidHttpMethod => "invalid HTTP method",
            Self::IllegalArgumentInvalidHttpHeader => "invalid HTTP header",
            Self::IllegalState => "illegal state",
            Self::IllegalStateStoragePathInUse => "storage path is used by another engine",
            Self::IllegalStateCannotShutdownEngineFromNetworkThread => "cannot shut down engine from network thread",
            Self::IllegalStateEngineAlreadyStarted => "the engine has already started",
            Self::IllegalStateRequestAlreadyStarted => "the request has already started",
            Self::IllegalStateRequestNotInitialized => "the request is not initialized",
            Self::IllegalStateRequestAlreadyInitialized => "the request is already initialized",
            Self::IllegalStateRequestNotStarted => "the request is not started",
            Self::IllegalStateUnexpectedRedirect => "no redirect to follow",
            Self::IllegalStateUnexpectedRead => "unexpected read attempt",
            Self::IllegalStateReadFailed => "unexpected read failure",
            Self::NullPointer => "null pointer or empty data",
            Self::NullPointerHostname => "the hostname cannot be null",
            Self::NullPointerSha256Pins => "the set of SHA-256 pins cannot be null",
            Self::NullPointerExpirationDate => "the pin expiration date cannot be null",
            Self::NullPointerEngine => "engine is required",
            Self::NullPointerUrl => "URL is required",
            Self::NullPointerCallback => "callback is required",
            Self::NullPointerExecutor => "executor is required",
            Self::NullPointerMethod => "method is required",
            Self::NullPointerHeaderName => "invalid header name",
            Self::NullPointerHeaderValue => "invalid header value",
            Self::NullPointerParams => "params is required",
            Self::NullPointerRequestFinishedInfoListenerExecutor => {
                "executor for RequestFinishedInfoListener is required"
            }
            Self::Unknown(code) => return write!(f, "cronet result {code}"),
        };
        f.write_str(text)
    }
}

impl error::Error for ApiError {}

c_enum! {
    /// What kind of failure an [`Error`] is.
    pub enum ErrorCode: sys::Cronet_Error_ERROR_CODE {
        /// The app's callback returned an error.
        Callback = sys::Cronet_Error_ERROR_CODE_ERROR_CALLBACK,
        /// The host could not be resolved to an IP address.
        HostnameNotResolved = sys::Cronet_Error_ERROR_CODE_ERROR_HOSTNAME_NOT_RESOLVED,
        /// The device was not connected to any network.
        InternetDisconnected = sys::Cronet_Error_ERROR_CODE_ERROR_INTERNET_DISCONNECTED,
        /// The network configuration changed while the request was processed.
        NetworkChanged = sys::Cronet_Error_ERROR_CODE_ERROR_NETWORK_CHANGED,
        /// A timeout expired. Timeouts while connecting are
        /// [`ConnectionTimedOut`](Self::ConnectionTimedOut) instead.
        TimedOut = sys::Cronet_Error_ERROR_CODE_ERROR_TIMED_OUT,
        /// The connection was closed unexpectedly.
        ConnectionClosed = sys::Cronet_Error_ERROR_CODE_ERROR_CONNECTION_CLOSED,
        /// The connection attempt timed out.
        ConnectionTimedOut = sys::Cronet_Error_ERROR_CODE_ERROR_CONNECTION_TIMED_OUT,
        /// The connection attempt was refused.
        ConnectionRefused = sys::Cronet_Error_ERROR_CODE_ERROR_CONNECTION_REFUSED,
        /// The connection was unexpectedly reset.
        ConnectionReset = sys::Cronet_Error_ERROR_CODE_ERROR_CONNECTION_RESET,
        /// There is no route to the host or network.
        AddressUnreachable = sys::Cronet_Error_ERROR_CODE_ERROR_ADDRESS_UNREACHABLE,
        /// QUIC failed; see [`ErrorRef::quic_detailed_error_code`].
        QuicProtocolFailed = sys::Cronet_Error_ERROR_CODE_ERROR_QUIC_PROTOCOL_FAILED,
        /// Anything else; see [`ErrorRef::internal_error_code`].
        Other = sys::Cronet_Error_ERROR_CODE_ERROR_OTHER,
    }
    unknown => Other;
}

value_type! {
    /// Why a request failed, as passed to
    /// [`UrlRequestCallback::on_failed`](crate::UrlRequestCallback::on_failed).
    ///
    /// Callbacks see an [`ErrorRef`] that Cronet owns; `to_owned` copies it
    /// into an `Error`, which is a `std::error::Error` like any other.
    pub struct Error / ErrorRef (sys::Cronet_Error) {
        create: sys::Cronet_Error_Create,
        destroy: sys::Cronet_Error_Destroy,
    }
}

properties!(ErrorRef {
    /// What kind of failure this is.
    ErrorCode as error_code, set_error_code: sys::Cronet_Error_error_code_get, sys::Cronet_Error_error_code_set;
    /// A message explaining the error.
    string message, set_message: sys::Cronet_Error_message_get, sys::Cronet_Error_message_set;
    /// Whether retrying right away might succeed: true after
    /// [`ErrorCode::NetworkChanged`], since the new network may work, but
    /// false after [`ErrorCode::InternetDisconnected`], which needs a delay.
    bool as immediately_retryable, set_immediately_retryable:
        sys::Cronet_Error_immediately_retryable_get, sys::Cronet_Error_immediately_retryable_set;
    /// The QUIC error code, when [`error_code`](Self::error_code) is
    /// [`ErrorCode::QuicProtocolFailed`].
    i32 as quic_detailed_error_code, set_quic_detailed_error_code:
        sys::Cronet_Error_quic_detailed_error_code_get, sys::Cronet_Error_quic_detailed_error_code_set;
});

impl ErrorRef {
    /// Chromium's error: more specific than [`error_code`](Self::error_code),
    /// though the values may change between versions.
    pub fn internal_error_code(&self) -> NetError {
        // SAFETY: the object is live.
        NetError::from_code(unsafe { sys::Cronet_Error_internal_error_code_get(self.as_ptr()) })
    }

    /// Sets [`internal_error_code`](Self::internal_error_code).
    pub fn set_internal_error_code(&mut self, value: NetError) -> &mut Self {
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_Error_internal_error_code_set(self.as_ptr(), value.code()) };
        self
    }

    /// Whether this is a timeout, the way `std::io` would see it.
    pub fn is_timeout(&self) -> bool {
        matches!(self.error_code(), ErrorCode::TimedOut | ErrorCode::ConnectionTimedOut)
    }
}

impl ToOwned for ErrorRef {
    type Owned = Error;

    fn to_owned(&self) -> Error {
        let mut copy = Error::new();
        copy.set_error_code(self.error_code())
            .set_message(&self.message())
            .set_internal_error_code(self.internal_error_code())
            .set_immediately_retryable(self.immediately_retryable())
            .set_quic_detailed_error_code(self.quic_detailed_error_code());
        copy
    }
}

impl Clone for Error {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

impl fmt::Debug for ErrorRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("error_code", &self.error_code())
            .field("message", &self.message())
            .field("internal_error_code", &self.internal_error_code())
            .field("immediately_retryable", &self.immediately_retryable())
            .field("quic_detailed_error_code", &self.quic_detailed_error_code())
            .finish()
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl fmt::Display for ErrorRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message: Cow<'_, str> = self.message();
        if message.is_empty() {
            write!(f, "{}", self.internal_error_code())
        } else {
            f.write_str(&message)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        let kind = match error.error_code() {
            ErrorCode::TimedOut | ErrorCode::ConnectionTimedOut => std::io::ErrorKind::TimedOut,
            _ => error.internal_error_code().io_kind(),
        };
        std::io::Error::new(kind, error)
    }
}

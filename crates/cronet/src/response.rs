//! HTTP headers, and what a request learned about its response.

use std::{borrow::Cow, fmt};

use cronet_sys as sys;

use crate::ffi::{c_string, properties, string, value_type};

value_type! {
    /// One HTTP header: a name and a value.
    pub struct HttpHeader / HttpHeaderRef (sys::Cronet_HttpHeader) {
        create: sys::Cronet_HttpHeader_Create,
        destroy: sys::Cronet_HttpHeader_Destroy,
    }
}

properties!(HttpHeaderRef {
    /// The header's name.
    string name, set_name: sys::Cronet_HttpHeader_name_get, sys::Cronet_HttpHeader_name_set;
    /// The header's value.
    string value, set_value: sys::Cronet_HttpHeader_value_get, sys::Cronet_HttpHeader_value_set;
});

impl HttpHeader {
    /// A header named `name` with `value`.
    ///
    /// # Panics
    ///
    /// If either contains a NUL byte.
    pub fn with(name: &str, value: &str) -> Self {
        let mut header = Self::new();
        header.set_name(name).set_value(value);
        header
    }
}

impl ToOwned for HttpHeaderRef {
    type Owned = HttpHeader;

    fn to_owned(&self) -> HttpHeader {
        HttpHeader::with(&self.name(), &self.value())
    }
}

impl Clone for HttpHeader {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

impl fmt::Debug for HttpHeaderRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name(), self.value())
    }
}

impl fmt::Debug for HttpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

value_type! {
    /// What a request learned about its response: status, headers, protocol,
    /// and the redirects that led to it.
    pub struct UrlResponseInfo / UrlResponseInfoRef (sys::Cronet_UrlResponseInfo) {
        create: sys::Cronet_UrlResponseInfo_Create,
        destroy: sys::Cronet_UrlResponseInfo_Destroy,
    }
}

properties!(UrlResponseInfoRef {
    /// The URL the response is for: after redirects, so not necessarily the
    /// one requested.
    string url, set_url: sys::Cronet_UrlResponseInfo_url_get, sys::Cronet_UrlResponseInfo_url_set;
    /// The HTTP status code. A response from the cache, revalidated or not,
    /// keeps its original code.
    i32 as status_code, set_status_code:
        sys::Cronet_UrlResponseInfo_http_status_code_get, sys::Cronet_UrlResponseInfo_http_status_code_set;
    /// The status line's text: `OK` for `HTTP/1.1 200 OK`.
    string status_text, set_status_text:
        sys::Cronet_UrlResponseInfo_http_status_text_get, sys::Cronet_UrlResponseInfo_http_status_text_set;
    /// Whether the response came from the cache, including responses
    /// revalidated over the network first.
    bool as was_cached, set_was_cached:
        sys::Cronet_UrlResponseInfo_was_cached_get, sys::Cronet_UrlResponseInfo_was_cached_set;
    /// The protocol negotiated with the server, such as `h2` or `h3`; empty
    /// if none was, or for plain HTTP.
    string negotiated_protocol, set_negotiated_protocol:
        sys::Cronet_UrlResponseInfo_negotiated_protocol_get, sys::Cronet_UrlResponseInfo_negotiated_protocol_set;
    /// The proxy server the request went through.
    string proxy_server, set_proxy_server:
        sys::Cronet_UrlResponseInfo_proxy_server_get, sys::Cronet_UrlResponseInfo_proxy_server_set;
    /// At least how many bytes were received from the network for this
    /// request, before decompression, including headers and redirects.
    i64 as received_byte_count, set_received_byte_count:
        sys::Cronet_UrlResponseInfo_received_byte_count_get, sys::Cronet_UrlResponseInfo_received_byte_count_set;
});

impl UrlResponseInfoRef {
    /// The URL chain: the URL requested first, then each redirect followed.
    pub fn url_chain(&self) -> impl ExactSizeIterator<Item = Cow<'_, str>> + '_ {
        // SAFETY: the object is live.
        let len = unsafe { sys::Cronet_UrlResponseInfo_url_chain_size(self.as_ptr()) };
        (0..len).map(move |index| {
            // SAFETY: `index` is in bounds, and nothing modifies the chain while `self` is borrowed.
            unsafe { string(sys::Cronet_UrlResponseInfo_url_chain_at(self.as_ptr(), index)) }
        })
    }

    /// Appends to [`url_chain`](Self::url_chain).
    ///
    /// # Panics
    ///
    /// If `url` contains a NUL byte.
    pub fn add_url_chain(&mut self, url: &str) -> &mut Self {
        let url = c_string(url);
        // SAFETY: the object is live and uniquely borrowed; Cronet copies the string.
        unsafe { sys::Cronet_UrlResponseInfo_url_chain_add(self.as_ptr(), url.as_ptr()) };
        self
    }

    /// Empties [`url_chain`](Self::url_chain).
    pub fn clear_url_chain(&mut self) -> &mut Self {
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_UrlResponseInfo_url_chain_clear(self.as_ptr()) };
        self
    }

    /// The response headers, in the order they arrived.
    pub fn headers(&self) -> impl ExactSizeIterator<Item = &HttpHeaderRef> + '_ {
        // SAFETY: the object is live.
        let len = unsafe { sys::Cronet_UrlResponseInfo_all_headers_list_size(self.as_ptr()) };
        (0..len).map(move |index| {
            // SAFETY: `index` is in bounds, and the list is not modified while `self` is borrowed.
            unsafe { HttpHeaderRef::from_ptr(sys::Cronet_UrlResponseInfo_all_headers_list_at(self.as_ptr(), index)) }
        })
    }

    /// The first header named `name`, ignoring ASCII case.
    pub fn header(&self, name: &str) -> Option<Cow<'_, str>> {
        self.headers()
            .find(|header| header.name().eq_ignore_ascii_case(name))
            .map(HttpHeaderRef::value)
    }

    /// Appends a copy of `header` to [`headers`](Self::headers).
    pub fn add_header(&mut self, header: &HttpHeaderRef) -> &mut Self {
        // SAFETY: both objects are live; Cronet copies the header.
        unsafe { sys::Cronet_UrlResponseInfo_all_headers_list_add(self.as_ptr(), header.as_ptr()) };
        self
    }

    /// Empties [`headers`](Self::headers).
    pub fn clear_headers(&mut self) -> &mut Self {
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_UrlResponseInfo_all_headers_list_clear(self.as_ptr()) };
        self
    }
}

impl ToOwned for UrlResponseInfoRef {
    type Owned = UrlResponseInfo;

    fn to_owned(&self) -> UrlResponseInfo {
        let mut copy = UrlResponseInfo::new();
        copy.set_url(&self.url())
            .set_status_code(self.status_code())
            .set_status_text(&self.status_text())
            .set_was_cached(self.was_cached())
            .set_negotiated_protocol(&self.negotiated_protocol())
            .set_proxy_server(&self.proxy_server())
            .set_received_byte_count(self.received_byte_count());
        for url in self.url_chain() {
            copy.add_url_chain(&url);
        }
        for header in self.headers() {
            copy.add_header(header);
        }
        copy
    }
}

impl Clone for UrlResponseInfo {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

impl fmt::Debug for UrlResponseInfoRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UrlResponseInfo")
            .field("url", &self.url())
            .field("url_chain", &self.url_chain().collect::<Vec<_>>())
            .field("status_code", &self.status_code())
            .field("status_text", &self.status_text())
            .field("headers", &self.headers().collect::<Vec<_>>())
            .field("was_cached", &self.was_cached())
            .field("negotiated_protocol", &self.negotiated_protocol())
            .field("proxy_server", &self.proxy_server())
            .field("received_byte_count", &self.received_byte_count())
            .finish()
    }
}

impl fmt::Debug for UrlResponseInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

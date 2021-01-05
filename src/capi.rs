//! C API binding

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr::NonNull;
use std::slice;
use std::time::Duration;

use crate::hassh::{Hassh, Hassher};

/// Create a new `Hassher` object to analyze SSH fingerprinting
#[no_mangle]
pub extern "C" fn hassher_new() -> NonNull<Hassher> {
    let hassher = Box::into_raw(Box::new(Hassher::default()));
    unsafe { NonNull::new_unchecked(hassher) }
}

/// Free the `Hassher` object
///
/// @param hassher  The `Hassher` object
#[no_mangle]
pub extern "C" fn hassher_free(hassher: Option<NonNull<Hassher>>) {
    if let Some(hassher) = hassher {
        drop(unsafe { Box::from_raw(hassher.as_ptr()) })
    }
}

/// Anaylze a buffered packet
///
/// @param hassher  The `Hassher` object to analyze SSH fingerprinting
/// @param buf      The packet to analyze
/// @param len      The packet length
/// @param ts       The packet timestamp (optional)
/// @return         The pointer to the new `Hassh` object, should be free with `hassh_free`
#[no_mangle]
pub extern "C" fn hassher_process_packet(
    hassher: Option<NonNull<Hassher>>,
    buf: Option<NonNull<u8>>,
    len: usize,
    ts: u64,
) -> Option<NonNull<Hassh>> {
    hassher.zip(buf).and_then(|(mut hassher, buf)| {
        let hassher = unsafe { hassher.as_mut() };
        let buf = unsafe { slice::from_raw_parts(buf.as_ptr(), len) };
        let ts = if ts == 0 {
            None
        } else {
            Some(Duration::from_micros(ts))
        };

        hassher
            .process_packet(buf, ts)
            .map(Box::new)
            .map(Box::into_raw)
            .and_then(NonNull::new)
    })
}

/// Free the `Hassh` object
///
/// @param hassh    The `Hassh` object
#[no_mangle]
pub extern "C" fn hassh_free(hassh: Option<NonNull<Hassh>>) {
    if let Some(hassh) = hassh {
        drop(unsafe { Box::from_raw(hassh.as_ptr()) })
    }
}

/// Get the client algorithm of the Hassh
///
/// @param hassh    The pointer to the `Hassh` object
/// @return         The client algorithm, should be `free` by caller
#[no_mangle]
pub extern "C" fn hassh_client_algo(hassh: Option<NonNull<Hassh>>) -> Option<NonNull<c_char>> {
    hassh
        .and_then(|hassh| CString::new(unsafe { hassh.as_ref() }.client_algo()).ok())
        .and_then(|algo| NonNull::new(unsafe { libc::strdup(algo.as_ptr()) }))
}

/// Get the server algorithm of the Hassh
///
/// @param hassh    The pointer to the `Hassh` object
/// @return         The server algorithm, should be `free` by caller
#[no_mangle]
pub extern "C" fn hassh_sever_algo(hassh: Option<NonNull<Hassh>>) -> Option<NonNull<c_char>> {
    hassh
        .and_then(|hassh| CString::new(unsafe { hassh.as_ref() }.server_algo()).ok())
        .and_then(|algo| NonNull::new(unsafe { libc::strdup(algo.as_ptr()) }))
}

/// Get the client hash digest of the Hassh
///
/// @param hassh    The pointer to the `Hassh` object
/// @return         The client hash digest, should be `free` by caller
#[no_mangle]
pub extern "C" fn hassh_client_hash(hassh: Option<NonNull<Hassh>>) -> Option<NonNull<c_char>> {
    hassh
        .map(|hassh| format!("{:x}", unsafe { hassh.as_ref() }.client_hash()))
        .and_then(|hash| CString::new(hash).ok())
        .and_then(|hash| NonNull::new(unsafe { libc::strdup(hash.as_ptr()) }))
}

/// Get the server hash digest  of the Hassh
///
/// @param hassh    The pointer to the `Hassh` object
/// @return         The server hash digest, should be `free` by caller
#[no_mangle]
pub extern "C" fn hassh_sever_hash(hassh: Option<NonNull<Hassh>>) -> Option<NonNull<c_char>> {
    hassh
        .map(|hassh| format!("{:x}", unsafe { hassh.as_ref() }.server_hash()))
        .and_then(|hash| CString::new(hash).ok())
        .and_then(|hash| NonNull::new(unsafe { libc::strdup(hash.as_ptr()) }))
}

#[cfg(feature = "pcap-file")]
mod pcap {
    use std::ffi::CStr;
    use std::fs::File;
    use std::os::raw::c_char;
    use std::ptr::NonNull;
    use std::slice;

    use crate::{pcap, Hassh};

    type BufReader<'a> = pcap::Reader<'a, &'a [u8]>;
    type FileReader<'a> = pcap::Reader<'a, File>;

    /// Parse a PCAP buffer to analyze SSH fingerprinting
    ///
    /// @param buf      The packet to analyze
    /// @param len      The packet length
    /// @return         The pointer to the new `BufReader` object, should be free with `hassh_buf_reader_free`
    #[no_mangle]
    pub extern "C" fn hassh_parse_pcap_buf(
        buf: Option<NonNull<c_char>>,
        len: usize,
    ) -> Option<NonNull<BufReader<'static>>> {
        buf.and_then(|buf| {
            let buf = unsafe { slice::from_raw_parts(buf.cast().as_ptr(), len) };

            pcap::parse(buf).ok()
        })
        .map(Box::new)
        .map(Box::into_raw)
        .and_then(NonNull::new)
    }

    /// Parse a PCAP file to analyze SSH fingerprinting
    ///
    /// @param filename The PCAP filename
    /// @return         The pointer to the new `FileReader` object, should be free with `hassh_file_reader_free`
    #[no_mangle]
    pub extern "C" fn hassh_open_pcap_file<'a>(
        filename: Option<NonNull<c_char>>,
    ) -> Option<NonNull<FileReader<'a>>> {
        filename
            .map(|filename| {
                unsafe { CStr::from_ptr(filename.cast().as_ptr()) }
                    .to_string_lossy()
                    .to_string()
            })
            .and_then(|filename| pcap::open(filename).ok())
            .map(Box::new)
            .map(Box::into_raw)
            .and_then(NonNull::new)
    }

    /// Free the `BufReader` object
    ///
    /// @param reader  The `BufReader` object
    #[no_mangle]
    pub extern "C" fn hassh_buf_reader_free(reader: Option<NonNull<BufReader>>) {
        if let Some(reader) = reader {
            drop(unsafe { Box::from_raw(reader.as_ptr()) })
        }
    }

    /// Free the `FileReader` object
    ///
    /// @param reader  The `FileReader` object
    #[no_mangle]
    pub extern "C" fn hassh_file_reader_free(reader: Option<NonNull<FileReader>>) {
        if let Some(reader) = reader {
            drop(unsafe { Box::from_raw(reader.as_ptr()) })
        }
    }

    /// Anaylze the PCAP buffer for next `Hassh`
    ///
    /// @param reader  The `BufReader` object to analyze SSH fingerprinting
    /// @return         The pointer to the new `Hassh` object, should be free with `hassh_free`, or nullptr for EOF
    #[no_mangle]
    pub extern "C" fn hassh_buf_reader_next(
        reader: Option<NonNull<BufReader>>,
    ) -> Option<NonNull<Hassh>> {
        reader
            .and_then(|mut reader| unsafe { reader.as_mut() }.next())
            .map(Box::new)
            .map(Box::into_raw)
            .and_then(NonNull::new)
    }

    /// Anaylze the PCAP file for next `Hassh`
    ///
    /// @param reader  The `FileReader` object to analyze SSH fingerprinting
    /// @return         The pointer to the new `Hassh` object, should be free with `hassh_free`, or nullptr for EOF
    #[no_mangle]
    pub extern "C" fn hassh_file_reader_next(
        reader: Option<NonNull<FileReader>>,
    ) -> Option<NonNull<Hassh>> {
        reader
            .and_then(|mut reader| unsafe { reader.as_mut() }.next())
            .map(Box::new)
            .map(Box::into_raw)
            .and_then(NonNull::new)
    }
}

#[cfg(feature = "live-capture")]
mod live {
    use std::ffi::CStr;
    use std::os::raw::c_char;
    use std::ptr::NonNull;

    use crate::{live, Hassh};

    /// Capture live traffic on the device
    ///
    /// @param intf     The interface name
    /// @return         The `Capture` object, should be free with `hassh_capture_free`
    #[no_mangle]
    pub extern "C" fn hassh_live_capture(
        intf: Option<NonNull<c_char>>,
    ) -> Option<NonNull<live::Capture>> {
        intf.and_then(|intf| {
            let intf = unsafe { CStr::from_ptr(intf.as_ptr()) }.to_string_lossy();
            live::capture(&intf).ok()
        })
        .map(Box::new)
        .map(Box::into_raw)
        .and_then(NonNull::new)
    }

    /// Free the `Capture` object
    ///
    /// @param cap  The `Capture` object
    #[no_mangle]
    pub extern "C" fn hassh_capture_free(cap: Option<NonNull<live::Capture>>) {
        if let Some(cap) = cap {
            drop(unsafe { Box::from_raw(cap.as_ptr()) })
        }
    }

    /// Adds a filter to the capture using the given BPF program string.
    ///
    /// @param cap      The `Capture` object
    /// @param filter   The BPF program string
    #[no_mangle]
    pub extern "C" fn hassh_capture_filter(
        cap: Option<NonNull<live::Capture>>,
        filter: Option<NonNull<c_char>>,
    ) -> bool {
        if let Some((mut cap, filter)) = cap.zip(filter) {
            let filter = unsafe { CStr::from_ptr(filter.as_ptr()) }.to_string_lossy();
            unsafe { cap.as_mut() }.with_filter(&filter).is_ok()
        } else {
            false
        }
    }

    /// Capture and anaylze the live traffic for next `Hassh`
    ///
    /// @param cap      The `Capture` object to analyze SSH fingerprinting
    /// @return         The pointer to the new `Hassh` object, should be free with `hassh_free`, or nullptr for EOF
    #[no_mangle]
    pub extern "C" fn hassh_capture_next(
        cap: Option<NonNull<live::Capture>>,
    ) -> Option<NonNull<Hassh>> {
        cap.and_then(|mut cap| unsafe { cap.as_mut() }.next())
            .map(Box::new)
            .map(Box::into_raw)
            .and_then(NonNull::new)
    }
}

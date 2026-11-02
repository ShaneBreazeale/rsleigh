//! Whole-binary analysis results, computed once per binary and shared by
//! every function decompiled from it.
//!
//! Each decompile used to re-derive imports, DWARF and PDB debug info, and
//! unwind tables from the whole image. `rsleigh FILE --all` on a 3 MB PE
//! spent most of its time there (resolve_imports alone was 104 ms per call,
//! three calls per function). Each [`Cache`] keeps the result for the most
//! recent binary.
//!
//! A byte buffer is identified by its address and length plus a sample of
//! its contents, so a later buffer that reuses the same allocation is not
//! mistaken for the earlier one. A file is identified by path, length, and
//! modification time.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    Bytes {
        addr: usize,
        len: usize,
        sample: u64,
    },
    File {
        path: PathBuf,
        len: u64,
        modified: Option<SystemTime>,
    },
}

impl Key {
    pub(crate) fn bytes(data: &[u8]) -> Self {
        Key::Bytes {
            addr: data.as_ptr() as usize,
            len: data.len(),
            sample: sample(data),
        }
    }

    /// `None` when the file cannot be inspected; the caller then parses
    /// without caching.
    pub(crate) fn file(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        Some(Key::File {
            path: path.to_path_buf(),
            len: meta.len(),
            modified: meta.modified().ok(),
        })
    }
}

/// FNV-1a over the first and last 4 KiB and 256 evenly spaced 64-byte runs.
fn sample(data: &[u8]) -> u64 {
    const RUN: usize = 64;
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            hash = (hash ^ b as u64).wrapping_mul(0x0100_0000_01b3);
        }
    };
    let edge = data.len().min(4096);
    feed(&data[..edge]);
    feed(&data[data.len() - edge..]);
    let stride = (data.len() / 256).max(RUN);
    let mut at = 0;
    while at + RUN <= data.len() {
        feed(&data[at..at + RUN]);
        at += stride;
    }
    hash
}

/// One cached result, for the most recently requested key.
pub(crate) struct Cache<T>(Mutex<Option<(Key, Arc<T>)>>);

impl<T> Cache<T> {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// The value for `key`, computing it on a miss. Concurrent callers for
    /// the same binary wait for the first computation instead of repeating
    /// it.
    pub(crate) fn get(&self, key: Key, compute: impl FnOnce() -> T) -> Arc<T> {
        // A panic while computing leaves the slot empty or holding a
        // complete earlier value, so a poisoned lock is still consistent.
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cached, value)) = slot.as_ref() {
            if *cached == key {
                return Arc::clone(value);
            }
        }
        let value = Arc::new(compute());
        *slot = Some((key, Arc::clone(&value)));
        value
    }
}

/// [`Cache::get`] for an optional key: without one, compute uncached.
pub(crate) fn cached<T: Clone>(
    cache: &Cache<T>,
    key: Option<Key>,
    compute: impl FnOnce() -> T,
) -> T {
    match key {
        Some(key) => (*cache.get(key, compute)).clone(),
        None => compute(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn same_buffer_is_computed_once() {
        let cache = Cache::new();
        let calls = Cell::new(0);
        let data = vec![7u8; 10_000];
        for _ in 0..3 {
            let v = cache.get(Key::bytes(&data), || {
                calls.set(calls.get() + 1);
                data.len()
            });
            assert_eq!(*v, 10_000);
        }
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn changed_contents_at_the_same_address_are_recomputed() {
        let cache = Cache::new();
        let calls = Cell::new(0);
        let mut data = vec![0u8; 100_000];
        let first = *cache.get(Key::bytes(&data), || {
            calls.set(calls.get() + 1);
            data[0]
        });
        data[0] = 1;
        let second = *cache.get(Key::bytes(&data), || {
            calls.set(calls.get() + 1);
            data[0]
        });
        assert_eq!((first, second, calls.get()), (0, 1, 2));
    }

    #[test]
    fn short_and_empty_buffers_have_keys() {
        assert_ne!(Key::bytes(&[1, 2, 3]), Key::bytes(&[1, 2, 4]));
        let _ = Key::bytes(&[]);
    }
}

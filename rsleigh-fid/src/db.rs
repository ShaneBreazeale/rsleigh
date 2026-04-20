//! FID database: compact binary format for (hash_quad, name, lib_id) rows.
//!
//! File layout (little-endian, gzipped on disk):
//!   magic        u32  = 0x46494431  ("FID1")
//!   n_libs       u32
//!   libs:        [u16 len, bytes]*
//!   n_entries    u32
//!   entries:     [full u64, specific u64, code_units u32, body_len u32,
//!                 lib_id u16, name_len u16, name_bytes*] repeated

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::HashMap;
use std::io::{self, Read, Write};

use crate::hash::FidHashQuad;

const MAGIC: u32 = 0x4649_4431;

#[derive(Debug, Clone)]
pub struct FidEntry {
    pub hash: FidHashQuad,
    pub lib_id: u16,
    pub name: String,
}

#[derive(Debug, Default)]
pub struct FidDb {
    pub libs: Vec<String>,
    pub entries: Vec<FidEntry>,
    by_full: HashMap<u64, Vec<usize>>,
    by_specific: HashMap<u64, Vec<usize>>,
}

impl FidDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_lib(&mut self, name: impl Into<String>) -> u16 {
        let name = name.into();
        if let Some(i) = self.libs.iter().position(|l| l == &name) {
            return i as u16;
        }
        self.libs.push(name);
        (self.libs.len() - 1) as u16
    }

    pub fn insert(&mut self, entry: FidEntry) {
        let idx = self.entries.len();
        self.by_full.entry(entry.hash.full).or_default().push(idx);
        self.by_specific.entry(entry.hash.specific).or_default().push(idx);
        self.entries.push(entry);
    }

    /// Look up all entries with a matching specific-hash.
    /// Prefer specific over full: disambiguates funcs with same body
    /// but different callees.
    pub fn match_specific(&self, specific: u64) -> &[usize] {
        self.by_specific.get(&specific).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn match_full(&self, full: u64) -> &[usize] {
        self.by_full.get(&full).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn write<W: Write>(&self, w: W) -> io::Result<()> {
        let mut gz = GzEncoder::new(w, Compression::default());
        gz.write_u32::<LittleEndian>(MAGIC)?;
        gz.write_u32::<LittleEndian>(self.libs.len() as u32)?;
        for l in &self.libs {
            let b = l.as_bytes();
            gz.write_u16::<LittleEndian>(b.len() as u16)?;
            gz.write_all(b)?;
        }
        gz.write_u32::<LittleEndian>(self.entries.len() as u32)?;
        for e in &self.entries {
            gz.write_u64::<LittleEndian>(e.hash.full)?;
            gz.write_u64::<LittleEndian>(e.hash.specific)?;
            gz.write_u32::<LittleEndian>(e.hash.code_units)?;
            gz.write_u32::<LittleEndian>(e.hash.body_len)?;
            gz.write_u16::<LittleEndian>(e.lib_id)?;
            let b = e.name.as_bytes();
            gz.write_u16::<LittleEndian>(b.len() as u16)?;
            gz.write_all(b)?;
        }
        gz.finish()?;
        Ok(())
    }

    pub fn read<R: Read>(r: R) -> io::Result<Self> {
        let mut gz = GzDecoder::new(r);
        let magic = gz.read_u32::<LittleEndian>()?;
        if magic != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
        }
        let n_libs = gz.read_u32::<LittleEndian>()?;
        let mut libs = Vec::with_capacity(n_libs as usize);
        for _ in 0..n_libs {
            let l = gz.read_u16::<LittleEndian>()? as usize;
            let mut buf = vec![0u8; l];
            gz.read_exact(&mut buf)?;
            libs.push(String::from_utf8_lossy(&buf).into_owned());
        }
        let n_entries = gz.read_u32::<LittleEndian>()?;
        let mut db = FidDb { libs, ..Self::default() };
        for _ in 0..n_entries {
            let full = gz.read_u64::<LittleEndian>()?;
            let specific = gz.read_u64::<LittleEndian>()?;
            let code_units = gz.read_u32::<LittleEndian>()?;
            let body_len = gz.read_u32::<LittleEndian>()?;
            let lib_id = gz.read_u16::<LittleEndian>()?;
            let nl = gz.read_u16::<LittleEndian>()? as usize;
            let mut buf = vec![0u8; nl];
            gz.read_exact(&mut buf)?;
            let name = String::from_utf8_lossy(&buf).into_owned();
            db.insert(FidEntry {
                hash: FidHashQuad { full, specific, code_units, body_len },
                lib_id,
                name,
            });
        }
        Ok(db)
    }
}

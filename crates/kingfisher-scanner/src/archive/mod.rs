//! Shared archive extraction used by the CLI and Python input pipeline.
mod asar;
pub mod decompress;
pub mod limits;
#[doc(hidden)]
pub mod scan_tar;
#[doc(hidden)]
pub mod scan_zip;

use std::{
    fs::File,
    io::{self, Seek, SeekFrom, Write},
};

/// Storage passed from a scan extractor to the matcher.
#[doc(hidden)]
pub enum ScanArchiveData {
    Bytes(Vec<u8>),
    File(File),
    Mapped(memmap2::Mmap),
}

#[doc(hidden)]
pub struct ScanArchiveMember {
    pub name: String,
    pub data: ScanArchiveData,
}

#[doc(hidden)]
pub enum ScanArchive {
    Members(Box<dyn Iterator<Item = ScanArchiveMember> + Send>),
    Raw(ScanArchiveData),
    Original,
}

enum BufferStorage {
    Bytes(Vec<u8>),
    File(File),
}

/// Keep small outputs in memory and spill larger ones to an owned temporary file.
/// A sparse raw fallback can retain long zero runs without writing them to disk.
struct ScanArchiveBuffer {
    data: BufferStorage,
    max_in_memory: usize,
    len: u64,
    sparse: bool,
}

impl Default for ScanArchiveBuffer {
    fn default() -> Self {
        Self::new(1024 * 1024)
    }
}

impl ScanArchiveBuffer {
    fn new(max_in_memory: usize) -> Self {
        Self { data: BufferStorage::Bytes(Vec::new()), max_in_memory, len: 0, sparse: false }
    }

    fn sparse() -> Self {
        Self { sparse: true, ..Self::default() }
    }

    fn finish(self) -> io::Result<ScanArchiveData> {
        match self.data {
            BufferStorage::Bytes(bytes) => Ok(ScanArchiveData::Bytes(bytes)),
            BufferStorage::File(mut file) => {
                if self.sparse {
                    file.set_len(self.len)?;
                }
                file.rewind()?;
                Ok(ScanArchiveData::File(file))
            }
        }
    }

    fn write_file(file: &mut File, sparse: bool, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if sparse {
            if bytes.len() >= 4096 {
                let (blocks, tail) = bytes.as_chunks::<64>();
                if blocks.iter().all(|block| *block == [0; 64]) && tail.iter().all(|&b| b == 0) {
                    return Ok(());
                }
            }
            file.seek(SeekFrom::Start(offset))?;
        }
        file.write_all(bytes)
    }
}

impl Write for ScanArchiveBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let BufferStorage::Bytes(existing) = &mut self.data
            && bytes.len() > self.max_in_memory.saturating_sub(existing.len())
        {
            let mut file = tempfile::tempfile()?;
            Self::write_file(&mut file, self.sparse, 0, existing)?;
            self.data = BufferStorage::File(file);
        }
        match &mut self.data {
            BufferStorage::Bytes(data) => data.extend_from_slice(bytes),
            BufferStorage::File(file) => Self::write_file(file, self.sparse, self.len, bytes)?,
        }
        self.len += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.data {
            BufferStorage::Bytes(_) => Ok(()),
            BufferStorage::File(file) => file.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn sparse_buffer_preserves_zero_runs_and_the_final_length() -> io::Result<()> {
        let mut buffer = ScanArchiveBuffer { sparse: true, ..ScanArchiveBuffer::new(4) };
        let zeros = [0; 4096];
        buffer.write_all(b"head")?;
        buffer.write_all(&zeros)?;
        buffer.write_all(b"tail")?;
        buffer.write_all(&zeros)?;
        let ScanArchiveData::File(mut file) = buffer.finish()? else {
            panic!("expected the fallback to spill");
        };
        let mut actual = Vec::new();
        file.read_to_end(&mut actual)?;
        assert_eq!(actual, [&b"head"[..], &zeros, b"tail", &zeros].concat());
        Ok(())
    }
}

//! Resource budgets for one scan. Never installed as process-global state.
use std::io::{self, Read};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceLimits {
    pub unlimited: bool,
}

impl ResourceLimits {
    pub fn limit<T>(self, default: T) -> Option<T> {
        if self.unlimited { None } else { Some(default) }
    }

    pub fn reached<T: PartialOrd>(self, value: T, limit: T) -> bool {
        !self.unlimited && value >= limit
    }

    pub fn exceeds<T: PartialOrd>(self, value: T, limit: T) -> bool {
        !self.unlimited && value > limit
    }

    pub fn cap<T: Ord>(self, value: T, limit: T) -> T {
        if self.unlimited { value } else { value.min(limit) }
    }

    pub fn reader<R: Read>(self, reader: R, limit: u64) -> LimitedReader<R> {
        LimitedReader { inner: reader, remaining: self.limit(limit) }
    }
}

pub struct LimitedReader<R> {
    inner: R,
    remaining: Option<u64>,
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.remaining.map_or(buffer.len(), |n| n.min(buffer.len() as u64) as usize);
        let read = self.inner.read(&mut buffer[..count])?;
        if let Some(remaining) = &mut self.remaining {
            *remaining -= read as u64;
        }
        Ok(read)
    }
}

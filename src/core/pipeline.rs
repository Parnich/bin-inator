use std::{
    ffi::{OsStr, OsString},
    io::Write,
    path::{Path, PathBuf},
};

use crc32fast::Hasher as Crc32;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::core::{
    error::ConvertError,
    options::{ByteSwap, Overwrite, RawOptions},
};

const PAD_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct PayloadResult {
    pub outputs: Vec<PathBuf>,
    pub bytes: u64,
    pub sha256: String,
    pub crc32: u32,
}

/// Streaming output pipeline: transforms -> hash -> optional padding -> split.
pub struct PayloadWriter {
    output_dir: PathBuf,
    base: OsString,
    split: bool,
    split_size: Option<u64>,
    pad_to: Option<u64>,
    pad_byte: u8,
    swap: ByteSwap,
    bit_reverse: bool,
    overwrite: Overwrite,

    current: Option<NamedTempFile>,
    current_written: u64,
    completed: Vec<NamedTempFile>,
    pending: Vec<u8>,
    scratch: Vec<u8>,

    total_written: u64,
    sha: Sha256,
    crc: Crc32,
}

impl PayloadWriter {
    pub fn new(
        output_dir: &Path,
        stem: &OsStr,
        options: &RawOptions,
        overwrite: Overwrite,
    ) -> Result<Self, ConvertError> {
        let split_size = options.split_size.filter(|size| *size > 0);
        let pad_to = options.pad_to.filter(|align| *align > 0);
        if let Some(align) = pad_to
            && align > 1 << 31
        {
            return Err(ConvertError::InvalidOptions(
                "padding alignment must be at most 2 GiB".to_owned(),
            ));
        }

        let split = split_size.is_some();
        let base = resolve_base_stem(output_dir, stem, split, overwrite)?;

        Ok(Self {
            output_dir: output_dir.to_path_buf(),
            base,
            split,
            split_size,
            pad_to,
            pad_byte: options.pad_byte.value(),
            swap: options.swap,
            bit_reverse: options.bit_reverse,
            overwrite,
            current: None,
            current_written: 0,
            completed: Vec::new(),
            pending: Vec::new(),
            scratch: Vec::new(),
            total_written: 0,
            sha: Sha256::new(),
            crc: Crc32::new(),
        })
    }

    /// First path that will be produced. Used for same-file protection.
    pub fn primary_path(&self) -> PathBuf {
        target_path(&self.output_dir, &self.base, self.split, 1)
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), ConvertError> {
        if self.swap == ByteSwap::None && !self.bit_reverse {
            return self.write_raw(data);
        }

        let mut out = std::mem::take(&mut self.scratch);
        out.clear();
        out.extend_from_slice(&self.pending);
        out.extend_from_slice(data);
        self.pending.clear();

        if self.bit_reverse {
            for byte in &mut out {
                *byte = byte.reverse_bits();
            }
        }

        if let Some(word_size) = self.swap.word_size() {
            let full = out.len() / word_size * word_size;
            match word_size {
                2 => {
                    for pair in out[..full].chunks_exact_mut(2) {
                        pair.swap(0, 1);
                    }
                }
                4 => {
                    for word in out[..full].chunks_exact_mut(4) {
                        word.reverse();
                    }
                }
                _ => {}
            }
            self.pending.extend_from_slice(&out[full..]);
            out.truncate(full);
        }

        let result = self.write_raw(&out);
        self.scratch = out;
        result
    }

    fn write_raw(&mut self, mut data: &[u8]) -> Result<(), ConvertError> {
        while !data.is_empty() {
            if let Some(size) = self.split_size
                && self.current_written >= size
            {
                self.finish_part()?;
            }
            if self.current.is_none() {
                self.open_part()?;
            }

            let take = match self.split_size {
                Some(size) => size
                    .saturating_sub(self.current_written)
                    .min(data.len() as u64) as usize,
                None => data.len(),
            };
            if take == 0 {
                self.finish_part()?;
                continue;
            }

            let temp = self
                .current
                .as_mut()
                .expect("current part was opened above");
            temp.as_file_mut().write_all(&data[..take])?;
            self.sha.update(&data[..take]);
            self.crc.update(&data[..take]);
            self.current_written += take as u64;
            self.total_written += take as u64;
            data = &data[take..];
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<PayloadResult, ConvertError> {
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            self.write_raw(&pending)?;
        }

        if let Some(align) = self.pad_to {
            let remainder = self.total_written % align;
            if remainder != 0 {
                self.write_padding(align - remainder)?;
            }
        }

        if self.current.is_none() && self.completed.is_empty() {
            self.open_part()?;
        }
        self.finish_part()?;

        let mut outputs = Vec::with_capacity(self.completed.len());
        for (index, temp) in self.completed.into_iter().enumerate() {
            let path = target_path(&self.output_dir, &self.base, self.split, index as u32 + 1);
            persist_temp(temp, &path, self.overwrite)?;
            outputs.push(path);
        }

        let digest = self.sha.finalize();
        Ok(PayloadResult {
            outputs,
            bytes: self.total_written,
            sha256: hex(&digest),
            crc32: self.crc.finalize(),
        })
    }

    fn open_part(&mut self) -> Result<(), ConvertError> {
        if self.current.is_some() {
            return Ok(());
        }

        let index = self.completed.len() as u32 + 1;
        let path = target_path(&self.output_dir, &self.base, self.split, index);
        if self.overwrite == Overwrite::Error && path.exists() {
            return Err(ConvertError::OutputExists(path));
        }

        let temp = tempfile::Builder::new()
            .prefix(".bin-inator-")
            .suffix(".part")
            .tempfile_in(&self.output_dir)?;
        self.current = Some(temp);
        self.current_written = 0;
        Ok(())
    }

    fn finish_part(&mut self) -> Result<(), ConvertError> {
        if let Some(temp) = self.current.take() {
            temp.as_file().sync_all()?;
            self.completed.push(temp);
        }
        self.current_written = 0;
        Ok(())
    }

    fn write_padding(&mut self, mut remaining: u64) -> Result<(), ConvertError> {
        let buffer = vec![self.pad_byte; PAD_CHUNK_SIZE];
        while remaining > 0 {
            let take = remaining.min(PAD_CHUNK_SIZE as u64) as usize;
            self.write_raw(&buffer[..take])?;
            remaining -= take as u64;
        }
        Ok(())
    }
}

fn resolve_base_stem(
    output_dir: &Path,
    stem: &OsStr,
    split: bool,
    overwrite: Overwrite,
) -> Result<OsString, ConvertError> {
    for suffix in 0..=9999 {
        let base = base_stem(stem, suffix);
        let first = target_path(output_dir, &base, split, 1);
        if !first.exists() {
            return Ok(base);
        }

        match overwrite {
            Overwrite::Error => return Err(ConvertError::OutputExists(first)),
            Overwrite::Replace => return Ok(base),
            Overwrite::Suffix => {}
        }
    }

    Err(ConvertError::OutputExists(target_path(
        output_dir,
        &base_stem(stem, 0),
        split,
        1,
    )))
}

fn base_stem(stem: &OsStr, suffix: u32) -> OsString {
    let mut name = stem.to_os_string();
    if suffix > 0 {
        name.push(format!(" ({suffix})"));
    }
    name
}

fn target_path(output_dir: &Path, base: &OsStr, split: bool, index: u32) -> PathBuf {
    let mut name = base.to_os_string();
    if split {
        name.push(format!(".part{index:03}.bin"));
    } else {
        name.push(".bin");
    }
    output_dir.join(name)
}

fn persist_temp(
    temp: NamedTempFile,
    path: &Path,
    overwrite: Overwrite,
) -> Result<(), ConvertError> {
    if overwrite == Overwrite::Replace {
        temp.persist(path)
            .map(|_| ())
            .map_err(|error| ConvertError::Io(error.error))
    } else {
        temp.persist_noclobber(path).map(|_| ()).map_err(|error| {
            if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                ConvertError::OutputExists(path.to_path_buf())
            } else {
                ConvertError::Io(error.error)
            }
        })
    }
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0F) as usize] as char);
    }
    output
}

use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

use crc32fast::Hasher as Crc32;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::core::{
    container::{self, ContainerInfo},
    detect::{InputKind, detect},
    error::ConvertError,
    executable::{self, ExecutableInfo},
    pipeline::hex,
    progress::CancellationToken,
};

const HEAD_SIZE: u64 = 64;
const SAMPLE_SIZE: usize = 64 * 1024;
const HASH_CHUNK: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct TextInfo {
    /// `utf-8`, `utf-16le`, `utf-16be`, `ascii` or `unknown`.
    pub encoding: String,
    pub bom: Option<String>,
    pub ascii: bool,
    pub utf8: bool,
    pub has_nul: bool,
    pub line_endings: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageInfo {
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub mime: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Inspection {
    pub path: String,
    pub size: u64,
    pub kind: &'static str,
    pub mime: Option<String>,
    pub magic_extension: Option<String>,
    pub head_hex: String,
    pub text: Option<TextInfo>,
    pub image: Option<ImageInfo>,
    pub executable: Option<ExecutableInfo>,
    pub container: Option<ContainerInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hashes {
    pub sha256: String,
    pub crc32: u32,
}

/// Collect type-specific details without reading the whole file.
pub fn inspect_file(path: &Path) -> Result<Inspection, ConvertError> {
    let detected = detect(path)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(ConvertError::NotAFile(path.to_path_buf()));
    }
    let size = metadata.len();

    let mut file = File::open(path)?;
    let head_len = size.min(HEAD_SIZE) as usize;
    let mut head = vec![0_u8; head_len];
    if head_len > 0 {
        file.read_exact(&mut head)?;
    }

    let text = if detected.kind == InputKind::Text {
        Some(inspect_text(&mut file, size)?)
    } else {
        None
    };
    let image = if detected.kind == InputKind::Image {
        image_info(path)
    } else {
        None
    };
    let executable = executable::inspect(path)?;
    let container = if detected.kind == InputKind::Container {
        Some(container::inspect(path)?)
    } else {
        None
    };

    Ok(Inspection {
        path: path.display().to_string(),
        size,
        kind: detected.kind.as_str(),
        mime: detected.mime,
        magic_extension: detected.extension,
        head_hex: hex(&head),
        text,
        image,
        executable,
        container,
    })
}

/// Stream SHA-256 and CRC32 for a file, reporting progress in bytes.
pub fn hash_file<F>(
    path: &Path,
    cancel: &CancellationToken,
    mut on_progress: F,
) -> Result<Hashes, ConvertError>
where
    F: FnMut(u64, u64),
{
    let mut file = File::open(path)?;
    let total = file.metadata()?.len();
    let mut buffer = vec![0_u8; HASH_CHUNK];
    let mut processed = 0_u64;
    let mut sha = Sha256::new();
    let mut crc = Crc32::new();

    on_progress(0, total);
    while processed < total {
        if cancel.is_cancelled() {
            return Err(ConvertError::Cancelled);
        }

        let to_read = (total - processed).min(HASH_CHUNK as u64) as usize;
        let read = match file.read(&mut buffer[..to_read]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };

        sha.update(&buffer[..read]);
        crc.update(&buffer[..read]);
        processed += read as u64;
        on_progress(processed, total);
    }

    Ok(Hashes {
        sha256: hex(&sha.finalize()),
        crc32: crc.finalize(),
    })
}

fn inspect_text(file: &mut File, size: u64) -> io::Result<TextInfo> {
    let sample_len = size.min(SAMPLE_SIZE as u64) as usize;
    let mut sample = vec![0_u8; sample_len];
    if sample_len > 0 {
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut sample)?;
    }

    let bom = if sample.starts_with(&[0xEF, 0xBB, 0xBF]) {
        Some("utf-8")
    } else if sample.starts_with(&[0xFF, 0xFE]) {
        Some("utf-16le")
    } else if sample.starts_with(&[0xFE, 0xFF]) {
        Some("utf-16be")
    } else {
        None
    };

    let body = bom.map_or(sample.as_slice(), |_| match bom {
        Some("utf-8") => &sample[3..],
        Some(_) => &sample[2..],
        None => &sample[..],
    });

    let ascii = body.is_ascii();
    let has_nul = body.contains(&0);
    let utf8 = bom == Some("utf-8") || (bom.is_none() && std::str::from_utf8(body).is_ok());
    let encoding = match bom {
        Some(encoding) => encoding,
        None if has_nul => "binary",
        None if ascii => "ascii",
        None if utf8 => "utf-8",
        None => "unknown",
    };

    let line_endings = if matches!(bom, Some("utf-16le") | Some("utf-16be")) {
        "unknown (utf-16)".to_owned()
    } else {
        detect_line_endings(body)
    };

    Ok(TextInfo {
        encoding: encoding.to_owned(),
        bom: bom.map(str::to_owned),
        ascii,
        utf8,
        has_nul,
        line_endings,
    })
}

fn detect_line_endings(bytes: &[u8]) -> String {
    let mut crlf = 0_u64;
    let mut lf = 0_u64;
    let mut cr = 0_u64;
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                if bytes.get(index + 1) == Some(&b'\n') {
                    crlf += 1;
                    index += 2;
                } else {
                    cr += 1;
                    index += 1;
                }
            }
            b'\n' => {
                lf += 1;
                index += 1;
            }
            _ => index += 1,
        }
    }

    match (crlf, lf, cr) {
        (0, 0, 0) => "none".to_owned(),
        (_, 0, 0) => "crlf".to_owned(),
        (0, _, 0) => "lf".to_owned(),
        (0, 0, _) => "cr".to_owned(),
        _ => format!("mixed (crlf {crlf}, lf {lf}, cr {cr})"),
    }
}

fn image_info(path: &Path) -> Option<ImageInfo> {
    let (width, height) = image::image_dimensions(path).ok()?;
    let format = image::ImageFormat::from_path(path).ok();
    Some(ImageInfo {
        width,
        height,
        format: format
            .as_ref()
            .and_then(|format| format.extensions_str().first())
            .map(|extension| (*extension).to_owned())
            .unwrap_or_else(|| "unknown".to_owned()),
        mime: format
            .as_ref()
            .map(|format| format.to_mime_type().to_owned())
            .unwrap_or_else(|| "application/octet-stream".to_owned()),
    })
}

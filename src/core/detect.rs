use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::core::container::MAGIC;

const SAMPLE_SIZE: u64 = 4096;

/// Broad input category used by the UI and the future conversion pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Text,
    Image,
    Executable,
    DiskImage,
    Container,
    Binary,
    Unknown,
}

impl InputKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Executable => "executable",
            Self::DiskImage => "disk_image",
            Self::Container => "container",
            Self::Binary => "binary",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detected {
    pub kind: InputKind,
    pub mime: Option<String>,
    pub extension: Option<String>,
    pub size: u64,
}

/// Detect the input type from magic bytes first, then from its extension.
pub fn detect(path: &Path) -> io::Result<Detected> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a regular file: {}", path.display()),
        ));
    }

    let inferred = infer::get_from_path(path).ok().flatten();
    let mime = inferred.as_ref().map(|t| t.mime_type().to_string());
    let extension = inferred.as_ref().map(|t| t.extension().to_string());

    let mut kind = if has_container_magic(path)? {
        InputKind::Container
    } else {
        classify(mime.as_deref(), path)
    };
    if kind == InputKind::Unknown {
        let sample = read_sample(path)?;
        kind = if looks_like_text(&sample) {
            InputKind::Text
        } else {
            InputKind::Binary
        };
    }

    Ok(Detected {
        kind,
        mime,
        extension,
        size: metadata.len(),
    })
}

fn classify(mime: Option<&str>, path: &Path) -> InputKind {
    if let Some(mime) = mime {
        if mime.starts_with("image/") {
            return InputKind::Image;
        }
        if mime.starts_with("text/")
            || mime.contains("json")
            || mime.contains("xml")
            || mime.contains("yaml")
        {
            return InputKind::Text;
        }
        if mime.contains("executable")
            || mime.contains("dosexec")
            || mime.contains("x-elf")
            || mime.contains("mach-binary")
        {
            return InputKind::Executable;
        }
        if mime.contains("iso9660") || mime.contains("disk-image") {
            return InputKind::DiskImage;
        }
    }

    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match extension.as_str() {
        "txt" | "md" | "markdown" | "csv" | "tsv" | "json" | "jsonl" | "toml" | "yaml" | "yml"
        | "xml" | "html" | "htm" | "css" | "js" | "ts" | "rs" | "py" | "c" | "h" | "cpp"
        | "hpp" | "cs" | "java" | "go" | "sh" | "ps1" | "bat" | "cmd" | "ini" | "cfg" | "conf"
        | "log" | "sql" | "lua" => InputKind::Text,
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "tif" | "tiff" | "ico" | "avif"
        | "heic" | "qoi" | "tga" | "ppm" | "pgm" => InputKind::Image,
        "exe" | "dll" | "sys" | "elf" | "so" | "dylib" | "o" | "obj" | "lib" | "a" => {
            InputKind::Executable
        }
        "iso" | "img" | "dmg" | "vhd" | "vhdx" | "qcow2" | "vmdk" | "dd" | "raw" => {
            InputKind::DiskImage
        }
        "binator" => InputKind::Container,
        _ => InputKind::Unknown,
    }
}

fn has_container_magic(path: &Path) -> io::Result<bool> {
    let mut magic = [0_u8; MAGIC.len()];
    let mut file = File::open(path)?;
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(&magic == MAGIC),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn read_sample(path: &Path) -> io::Result<Vec<u8>> {
    let mut sample = Vec::with_capacity(SAMPLE_SIZE as usize);
    File::open(path)?
        .take(SAMPLE_SIZE)
        .read_to_end(&mut sample)?;
    Ok(sample)
}

fn looks_like_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }

    // UTF-8 BOM, UTF-16 LE/BE BOM.
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF])
        || bytes.starts_with(&[0xFF, 0xFE])
        || bytes.starts_with(&[0xFE, 0xFF])
    {
        return true;
    }

    if bytes.contains(&0) {
        return false;
    }

    match std::str::from_utf8(bytes) {
        Ok(_) => true,
        // The 4 KiB sample may end in the middle of a multi-byte character.
        Err(error) => error.valid_up_to() > 0 && error.valid_up_to() + 4 >= bytes.len(),
    }
}

/// Best-effort output name: replace the final extension with `.bin`.
pub fn output_file_name(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| std::ffi::OsStr::new("output"));

    let mut name = std::ffi::OsString::from(stem);
    name.push(".bin");
    PathBuf::from(name)
}

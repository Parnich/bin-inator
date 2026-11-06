use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crc32fast::Hasher as Crc32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::core::{
    detect::detect, error::ConvertError, options::Overwrite, pipeline::hex,
    progress::CancellationToken,
};

pub const MAGIC: &[u8; 8] = b"BINATOR1";
pub const VERSION: u16 = 1;
pub const HEADER_SIZE: u64 = 64;
pub const TRAILER_SIZE: u64 = 36;
const CHUNK_SIZE: usize = 1024 * 1024;
const MAX_METADATA_SIZE: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMetadata {
    pub source_name: String,
    pub source_size: u64,
    pub kind: String,
    pub mime: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    pub created_unix_ms: u64,
    pub tool: String,
    pub tool_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerInfo {
    pub metadata: ContainerMetadata,
    pub payload_offset: u64,
    pub payload_len: u64,
    pub container_size: u64,
}

#[derive(Debug, Clone)]
pub struct PackReport {
    pub output: PathBuf,
    pub payload_bytes: u64,
    pub sha256: String,
    pub crc32: u32,
    pub elapsed: Duration,
}

#[derive(Debug, Clone)]
pub struct UnpackReport {
    pub input: PathBuf,
    pub output: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub crc32: u32,
    pub metadata: ContainerMetadata,
    pub elapsed: Duration,
}

struct Header {
    header_size: u64,
    payload_offset: u64,
    payload_len: u64,
    metadata_len: u32,
}

/// Read the header, metadata and layout of a container without touching the payload.
pub fn inspect(path: &Path) -> Result<ContainerInfo, ConvertError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(ConvertError::NotAFile(path.to_path_buf()));
    }

    let mut file = File::open(path)?;
    let header = read_header(&mut file, metadata.len())?;
    let container = read_metadata(&mut file, &header)?;

    Ok(ContainerInfo {
        metadata: container,
        payload_offset: header.payload_offset,
        payload_len: header.payload_len,
        container_size: metadata.len(),
    })
}

/// Pack a file into a `BINATOR1` container without changing its bytes.
pub fn pack<F>(
    input: &Path,
    output: &Path,
    overwrite: Overwrite,
    note: Option<String>,
    cancel: &CancellationToken,
    mut on_progress: F,
) -> Result<PackReport, ConvertError>
where
    F: FnMut(u64, u64),
{
    let started = Instant::now();
    let source_meta = fs::metadata(input)?;
    if !source_meta.is_file() {
        return Err(ConvertError::NotAFile(input.to_path_buf()));
    }
    let payload_len = source_meta.len();

    let parent = output.parent().filter(|path| !path.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let target = resolve_target(output, overwrite)?;
    if same_file(input, &target) {
        return Err(ConvertError::SameFile(input.to_path_buf()));
    }

    let detected = detect(input)?;
    let container_metadata = ContainerMetadata {
        source_name: input
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "output.bin".to_owned()),
        source_size: payload_len,
        kind: detected.kind.as_str().to_owned(),
        mime: detected.mime.clone(),
        note,
        created_unix_ms: unix_millis(),
        tool: "bin-inator".to_owned(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
    };

    let metadata_json = serde_json::to_vec(&container_metadata)?;
    if metadata_json.len() > MAX_METADATA_SIZE as usize {
        return Err(ConvertError::Container(
            "metadata is too large for a container header".to_owned(),
        ));
    }

    let payload_offset = HEADER_SIZE + metadata_json.len() as u64;
    let header = build_header(payload_offset, payload_len, metadata_json.len() as u32)?;

    let mut temp = tempfile::Builder::new()
        .prefix(".bin-inator-")
        .suffix(".binator.part")
        .tempfile_in(parent)?;

    temp.write_all(&header)?;
    temp.write_all(&metadata_json)?;

    let mut source = File::open(input)?;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut processed = 0_u64;
    let mut sha = Sha256::new();
    let mut crc = Crc32::new();

    on_progress(0, payload_len);
    while processed < payload_len {
        if cancel.is_cancelled() {
            return Err(ConvertError::Cancelled);
        }

        let to_read = (payload_len - processed).min(CHUNK_SIZE as u64) as usize;
        let read = match source.read(&mut buffer[..to_read]) {
            Ok(0) => {
                return Err(ConvertError::Container(format!(
                    "input ended early at {processed} of {payload_len} bytes"
                )));
            }
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };

        temp.write_all(&buffer[..read])?;
        sha.update(&buffer[..read]);
        crc.update(&buffer[..read]);
        processed += read as u64;
        on_progress(processed, payload_len);
    }

    let digest = sha.finalize();
    let crc32 = crc.finalize();
    temp.write_all(&crc32.to_le_bytes())?;
    temp.write_all(&digest)?;

    temp.as_file().sync_all()?;
    persist_temp(temp, &target, overwrite)?;

    Ok(PackReport {
        output: target,
        payload_bytes: payload_len,
        sha256: hex(&digest),
        crc32,
        elapsed: started.elapsed(),
    })
}

/// Unpack a `BINATOR1` container back into the original bytes.
pub fn unpack<F>(
    input: &Path,
    output_dir: &Path,
    overwrite: Overwrite,
    cancel: &CancellationToken,
    mut on_progress: F,
) -> Result<UnpackReport, ConvertError>
where
    F: FnMut(u64, u64),
{
    let started = Instant::now();
    let source_meta = fs::metadata(input)?;
    if !source_meta.is_file() {
        return Err(ConvertError::NotAFile(input.to_path_buf()));
    }

    let mut source = File::open(input)?;
    let header = read_header(&mut source, source_meta.len())?;
    let container_metadata = read_metadata(&mut source, &header)?;

    fs::create_dir_all(output_dir)?;
    let name = sanitize_file_name(&container_metadata.source_name);
    let target = resolve_target(&output_dir.join(name), overwrite)?;
    if same_file(input, &target) {
        return Err(ConvertError::SameFile(input.to_path_buf()));
    }

    source.seek(SeekFrom::Start(header.payload_offset))?;

    let mut temp = tempfile::Builder::new()
        .prefix(".bin-inator-")
        .suffix(".bin.part")
        .tempfile_in(output_dir)?;

    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut processed = 0_u64;
    let mut sha = Sha256::new();
    let mut crc = Crc32::new();

    on_progress(0, header.payload_len);
    while processed < header.payload_len {
        if cancel.is_cancelled() {
            return Err(ConvertError::Cancelled);
        }

        let to_read = (header.payload_len - processed).min(CHUNK_SIZE as u64) as usize;
        let read = match source.read(&mut buffer[..to_read]) {
            Ok(0) => {
                return Err(ConvertError::Container(format!(
                    "payload ended early at {processed} of {} bytes",
                    header.payload_len
                )));
            }
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };

        temp.write_all(&buffer[..read])?;
        sha.update(&buffer[..read]);
        crc.update(&buffer[..read]);
        processed += read as u64;
        on_progress(processed, header.payload_len);
    }

    let digest = sha.finalize();
    let crc32 = crc.finalize();

    let mut trailer = [0_u8; TRAILER_SIZE as usize];
    source.read_exact(&mut trailer)?;
    let expected_crc = u32::from_le_bytes(trailer[..4].try_into().expect("four bytes"));
    let expected_sha = &trailer[4..];

    if expected_crc != crc32 || expected_sha != digest.as_slice() {
        return Err(ConvertError::Container(
            "payload checksum mismatch".to_owned(),
        ));
    }

    temp.as_file().sync_all()?;
    persist_temp(temp, &target, overwrite)?;

    Ok(UnpackReport {
        input: input.to_path_buf(),
        output: target,
        bytes: header.payload_len,
        sha256: hex(&digest),
        crc32,
        metadata: container_metadata,
        elapsed: started.elapsed(),
    })
}

fn build_header(
    payload_offset: u64,
    payload_len: u64,
    metadata_len: u32,
) -> Result<[u8; HEADER_SIZE as usize], ConvertError> {
    let mut header = [0_u8; HEADER_SIZE as usize];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_le_bytes());
    header[10..12].copy_from_slice(&0_u16.to_le_bytes());
    header[12..16].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    header[16..24].copy_from_slice(&payload_offset.to_le_bytes());
    header[24..32].copy_from_slice(&payload_len.to_le_bytes());
    header[32..36].copy_from_slice(&metadata_len.to_le_bytes());

    let mut crc = Crc32::new();
    crc.update(&header[..36]);
    header[36..40].copy_from_slice(&crc.finalize().to_le_bytes());

    Ok(header)
}

fn read_header(file: &mut File, file_size: u64) -> Result<Header, ConvertError> {
    if file_size < HEADER_SIZE + TRAILER_SIZE {
        return Err(ConvertError::Container(
            "file is too small to be a container".to_owned(),
        ));
    }

    let mut header = [0_u8; HEADER_SIZE as usize];
    file.read_exact(&mut header)?;

    if &header[..8] != MAGIC {
        return Err(ConvertError::Container("bad magic".to_owned()));
    }

    let version = u16::from_le_bytes(header[8..10].try_into().expect("two bytes"));
    if version != VERSION {
        return Err(ConvertError::Container(format!(
            "unsupported version {version}"
        )));
    }

    let header_size = u32::from_le_bytes(header[12..16].try_into().expect("four bytes")) as u64;
    if header_size < HEADER_SIZE {
        return Err(ConvertError::Container(
            "header size is smaller than the format minimum".to_owned(),
        ));
    }

    let stored_crc = u32::from_le_bytes(header[36..40].try_into().expect("four bytes"));
    let mut crc = Crc32::new();
    crc.update(&header[..36]);
    if crc.finalize() != stored_crc {
        return Err(ConvertError::Container(
            "header checksum mismatch".to_owned(),
        ));
    }

    let payload_offset = u64::from_le_bytes(header[16..24].try_into().expect("eight bytes"));
    let payload_len = u64::from_le_bytes(header[24..32].try_into().expect("eight bytes"));
    let metadata_len = u32::from_le_bytes(header[32..36].try_into().expect("four bytes"));

    if metadata_len > MAX_METADATA_SIZE {
        return Err(ConvertError::Container(
            "metadata length exceeds the format limit".to_owned(),
        ));
    }

    let expected_offset = header_size + metadata_len as u64;
    if payload_offset != expected_offset {
        return Err(ConvertError::Container(
            "payload offset does not match the header".to_owned(),
        ));
    }

    let expected_size = payload_offset
        .checked_add(payload_len)
        .and_then(|size| size.checked_add(TRAILER_SIZE))
        .ok_or_else(|| ConvertError::Container("container size overflows".to_owned()))?;
    if expected_size != file_size {
        return Err(ConvertError::Container(format!(
            "container size mismatch: expected {expected_size} bytes, got {file_size}"
        )));
    }

    Ok(Header {
        header_size,
        payload_offset,
        payload_len,
        metadata_len,
    })
}

fn read_metadata(file: &mut File, header: &Header) -> Result<ContainerMetadata, ConvertError> {
    file.seek(SeekFrom::Start(header.header_size))?;
    let mut json = vec![0_u8; header.metadata_len as usize];
    file.read_exact(&mut json)?;
    serde_json::from_slice(&json)
        .map_err(|error| ConvertError::Container(format!("metadata is not valid JSON: {error}")))
}

fn resolve_target(path: &Path, overwrite: Overwrite) -> Result<PathBuf, ConvertError> {
    if !path.exists() {
        return Ok(path.to_path_buf());
    }

    match overwrite {
        Overwrite::Error => Err(ConvertError::OutputExists(path.to_path_buf())),
        Overwrite::Replace => Ok(path.to_path_buf()),
        Overwrite::Suffix => {
            for index in 1..=9999 {
                let candidate = suffixed(path, index);
                if !candidate.exists() {
                    return Ok(candidate);
                }
            }
            Err(ConvertError::OutputExists(path.to_path_buf()))
        }
    }
}

fn suffixed(path: &Path, index: u32) -> PathBuf {
    let mut name = path
        .file_stem()
        .map(|stem| stem.to_os_string())
        .unwrap_or_else(|| OsString::from("output"));
    name.push(format!(" ({index})"));
    if let Some(extension) = path.extension() {
        name.push(".");
        name.push(extension);
    }
    path.with_file_name(name)
}

fn sanitize_file_name(name: &str) -> OsString {
    let base = Path::new(name)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut sanitized: String = base
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0' => '_',
            other => other,
        })
        .collect();
    sanitized = sanitized.trim().to_owned();

    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        return OsString::from("output.bin");
    }

    // Windows reserves these device names even with an extension.
    let stem = sanitized
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        stem.as_str(),
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
    ) {
        sanitized.insert(0, '_');
    }

    OsString::from(sanitized)
}

fn same_file(input: &Path, output: &Path) -> bool {
    if let (Ok(input), Ok(output)) = (fs::canonicalize(input), fs::canonicalize(output))
        && input == output
    {
        return true;
    }

    let Some(parent) = output.parent() else {
        return false;
    };
    let Some(name) = output.file_name() else {
        return false;
    };

    match (fs::canonicalize(input), fs::canonicalize(parent)) {
        (Ok(input), Ok(parent)) => parent.join(name) == input,
        _ => false,
    }
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
            if error.error.kind() == io::ErrorKind::AlreadyExists {
                ConvertError::OutputExists(path.to_path_buf())
            } else {
                ConvertError::Io(error.error)
            }
        })
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::core::{
    detect::{InputKind, detect},
    error::ConvertError,
    formats::{raster, text},
    options::{ConvertOptions, ImageMode},
    pipeline::{PayloadResult, PayloadWriter},
    progress::CancellationToken,
};

const CHUNK_SIZE: usize = 1024 * 1024;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
pub struct ConvertReport {
    pub input: PathBuf,
    pub outputs: Vec<PathBuf>,
    pub bytes: u64,
    pub sha256: String,
    pub crc32: u32,
    pub sidecar: Option<PathBuf>,
    pub elapsed: Duration,
}

impl ConvertReport {
    pub fn primary_output(&self) -> &Path {
        &self.outputs[0]
    }
}

/// Convert `input` into one or more `.bin` files in `output_dir`.
pub fn convert_file<F>(
    input: &Path,
    output_dir: &Path,
    options: &ConvertOptions,
    cancel: &CancellationToken,
    mut on_progress: F,
) -> Result<ConvertReport, ConvertError>
where
    F: FnMut(u64, u64),
{
    let started = Instant::now();
    let metadata = fs::metadata(input)?;
    if !metadata.is_file() {
        return Err(ConvertError::NotAFile(input.to_path_buf()));
    }

    fs::create_dir_all(output_dir)?;
    if cancel.is_cancelled() {
        return Err(ConvertError::Cancelled);
    }

    let stem = input
        .file_stem()
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| OsStr::new("output"));
    let mut writer = PayloadWriter::new(output_dir, stem, &options.raw, options.overwrite)?;

    if paths_refer_to_same_file(input, &writer.primary_path()) {
        return Err(ConvertError::SameFile(input.to_path_buf()));
    }

    let detected = detect(input)?;
    on_progress(0, metadata.len());
    let mut image_metadata = None;

    match (
        detected.kind,
        options.text.output_encoding,
        options.image.mode,
    ) {
        (InputKind::Text, Some(_), _) => {
            if cancel.is_cancelled() {
                return Err(ConvertError::Cancelled);
            }
            let payload = text::transcode(input, &options.text)?;
            on_progress(0, payload.len() as u64);
            writer.write(&payload)?;
            on_progress(payload.len() as u64, payload.len() as u64);
        }
        (InputKind::Image, _, ImageMode::Pixels) => {
            if cancel.is_cancelled() {
                return Err(ConvertError::Cancelled);
            }
            let payload = raster::dump_pixels(input, options.image.format)?;
            let payload_len = payload.bytes.len() as u64;
            image_metadata = Some(payload.metadata);
            on_progress(0, payload_len);
            writer.write(&payload.bytes)?;
            on_progress(payload_len, payload_len);
        }
        _ => {
            stream_copy(
                input,
                metadata.len(),
                options.raw.trim_trailing_zeros,
                &mut writer,
                cancel,
                &mut on_progress,
            )?;
        }
    }

    if cancel.is_cancelled() {
        return Err(ConvertError::Cancelled);
    }

    let result = writer.finish()?;
    let sidecar = if options.sidecar {
        Some(write_sidecar(
            input,
            metadata.len(),
            detected.kind,
            &result,
            image_metadata.as_ref(),
            options,
        )?)
    } else {
        None
    };

    on_progress(result.bytes, result.bytes);

    Ok(ConvertReport {
        input: input.to_path_buf(),
        outputs: result.outputs,
        bytes: result.bytes,
        sha256: result.sha256,
        crc32: result.crc32,
        sidecar,
        elapsed: started.elapsed(),
    })
}

fn stream_copy<F>(
    input: &Path,
    total: u64,
    trim_trailing_zeros: bool,
    writer: &mut PayloadWriter,
    cancel: &CancellationToken,
    on_progress: &mut F,
) -> Result<(), ConvertError>
where
    F: FnMut(u64, u64),
{
    let mut source = File::open(input)?;
    let effective_total = if trim_trailing_zeros {
        trailing_nonzero_len(&mut source, total)?
    } else {
        total
    };
    source.seek(SeekFrom::Start(0))?;

    on_progress(0, effective_total);
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut processed = 0_u64;
    let mut last_emit: Option<Instant> = None;

    while processed < effective_total {
        if cancel.is_cancelled() {
            return Err(ConvertError::Cancelled);
        }

        let to_read = (effective_total - processed).min(CHUNK_SIZE as u64) as usize;
        let read = match source.read(&mut buffer[..to_read]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };

        writer.write(&buffer[..read])?;
        processed += read as u64;

        if last_emit.is_none_or(|last| last.elapsed() >= PROGRESS_INTERVAL) {
            on_progress(processed, effective_total);
            last_emit = Some(Instant::now());
        }
    }

    on_progress(processed, effective_total);
    Ok(())
}

fn trailing_nonzero_len(source: &mut File, total: u64) -> io::Result<u64> {
    let mut end = total;
    let mut buffer = vec![0_u8; 64 * 1024];

    while end > 0 {
        let start = end.saturating_sub(buffer.len() as u64);
        let len = (end - start) as usize;
        source.seek(SeekFrom::Start(start))?;
        source.read_exact(&mut buffer[..len])?;

        if let Some(index) = buffer[..len].iter().rposition(|byte| *byte != 0) {
            return Ok(start + index as u64 + 1);
        }
        end = start;
    }

    Ok(0)
}

#[derive(Serialize)]
struct Sidecar<'a> {
    source: String,
    source_size: u64,
    kind: &'static str,
    output_bytes: u64,
    sha256: &'a str,
    crc32: String,
    parts: Vec<String>,
    image: Option<&'a raster::ImageMetadata>,
    options: &'a ConvertOptions,
    created_unix_ms: u64,
}

fn write_sidecar(
    input: &Path,
    source_size: u64,
    kind: InputKind,
    result: &PayloadResult,
    image: Option<&raster::ImageMetadata>,
    options: &ConvertOptions,
) -> Result<PathBuf, ConvertError> {
    let primary = result
        .outputs
        .first()
        .ok_or_else(|| ConvertError::InvalidOptions("no output was produced".to_owned()))?;
    let parent = primary.parent().unwrap_or_else(|| Path::new("."));

    let mut sidecar_name = primary
        .file_name()
        .unwrap_or_else(|| OsStr::new("output.bin"))
        .to_os_string();
    sidecar_name.push(".json");
    let sidecar_path = parent.join(sidecar_name);

    let parts = result
        .outputs
        .iter()
        .filter_map(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();

    let created_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let sidecar = Sidecar {
        source: input.display().to_string(),
        source_size,
        kind: kind.as_str(),
        output_bytes: result.bytes,
        sha256: &result.sha256,
        crc32: format!("{:08x}", result.crc32),
        parts,
        image,
        options,
        created_unix_ms,
    };

    let json = serde_json::to_vec_pretty(&sidecar)?;
    let mut temp = tempfile::Builder::new()
        .prefix(".bin-inator-")
        .suffix(".json.part")
        .tempfile_in(parent)?;
    temp.write_all(&json)?;
    temp.as_file().sync_all()?;
    temp.persist(&sidecar_path)
        .map_err(|error| ConvertError::Io(error.error))?;

    Ok(sidecar_path)
}

fn paths_refer_to_same_file(input: &Path, output: &Path) -> bool {
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

/// Output name shown in the UI before conversion.
pub fn preview_output_name(input: &Path, split: bool) -> PathBuf {
    let stem = input
        .file_stem()
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| OsStr::new("output"));
    let mut name = OsString::from(stem);
    if split {
        name.push(".part###.bin");
    } else {
        name.push(".bin");
    }
    PathBuf::from(name)
}

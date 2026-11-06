use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::core::{
    error::ConvertError,
    executable::{SectionInfo, inspect as inspect_executable},
    options::Overwrite,
    pipeline::hex,
    progress::CancellationToken,
};

const CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedSection {
    pub name: String,
    pub output: String,
    pub offset: u64,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtractReport {
    pub input: String,
    pub output_dir: String,
    pub format: String,
    pub machine: String,
    pub outputs: Vec<ExtractedSection>,
    pub total_bytes: u64,
    pub elapsed_ms: u64,
}

struct PendingSection {
    temp: NamedTempFile,
    target: PathBuf,
    name: String,
    offset: u64,
    bytes: u64,
    sha256: String,
}

/// Extract selected PE/ELF sections into header-free `.bin` files.
///
/// `selection == None` extracts every non-empty section. Items may be section
/// names (with or without a leading dot) or indices as printed by `inspect`.
pub fn extract_sections<F>(
    input: &Path,
    output_dir: &Path,
    selection: Option<&[String]>,
    overwrite: Overwrite,
    cancel: &CancellationToken,
    mut on_progress: F,
) -> Result<ExtractReport, ConvertError>
where
    F: FnMut(u64, u64),
{
    let started = Instant::now();
    let metadata = fs::metadata(input)?;
    if !metadata.is_file() {
        return Err(ConvertError::NotAFile(input.to_path_buf()));
    }
    let file_size = metadata.len();

    let info = inspect_executable(input)?.ok_or_else(|| {
        ConvertError::Executable("input is not a PE or ELF executable".to_owned())
    })?;

    let selected = select_sections(&info.sections, selection, file_size)?;
    if selected.is_empty() {
        return Err(ConvertError::Executable(
            "no non-empty sections to extract".to_owned(),
        ));
    }

    fs::create_dir_all(output_dir)?;
    let stem = input
        .file_stem()
        .filter(|stem| !stem.is_empty())
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".to_owned());

    let total_bytes: u64 = selected.iter().map(|(_, section)| section.data_size).sum();
    let mut used_names = HashSet::new();
    let mut planned = Vec::with_capacity(selected.len());
    for (index, section) in selected {
        let section_name =
            clean_name(&section.name).unwrap_or_else(|| format!("section{index:03}"));
        let mut file_name = format!("{stem}.{section_name}.bin");
        let mut duplicate = 2;
        while !used_names.insert(file_name.to_lowercase()) {
            file_name = format!("{stem}.{section_name}-{duplicate}.bin");
            duplicate += 1;
        }
        let target = resolve_target(&output_dir.join(file_name), overwrite)?;
        if same_file(input, &target) {
            return Err(ConvertError::SameFile(input.to_path_buf()));
        }
        planned.push((section, target, section_name));
    }

    let mut source = File::open(input)?;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut processed = 0_u64;
    let mut pending = Vec::with_capacity(planned.len());

    for (section, target, name) in planned {
        if cancel.is_cancelled() {
            return Err(ConvertError::Cancelled);
        }

        let mut temp = tempfile::Builder::new()
            .prefix(".bin-inator-")
            .suffix(".section.part")
            .tempfile_in(output_dir)?;
        source.seek(SeekFrom::Start(section.offset))?;

        let mut remaining = section.data_size;
        let mut sha = Sha256::new();
        while remaining > 0 {
            if cancel.is_cancelled() {
                return Err(ConvertError::Cancelled);
            }

            let to_read = remaining.min(CHUNK_SIZE as u64) as usize;
            let read = match source.read(&mut buffer[..to_read]) {
                Ok(0) => {
                    return Err(ConvertError::Executable(format!(
                        "section {} ended early",
                        name
                    )));
                }
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };

            temp.write_all(&buffer[..read])?;
            sha.update(&buffer[..read]);
            remaining -= read as u64;
            processed += read as u64;
            on_progress(processed, total_bytes);
        }

        temp.as_file().sync_all()?;
        pending.push(PendingSection {
            temp,
            target,
            name,
            offset: section.offset,
            bytes: section.data_size,
            sha256: hex(&sha.finalize()),
        });
    }

    if cancel.is_cancelled() {
        return Err(ConvertError::Cancelled);
    }

    let mut outputs = Vec::with_capacity(pending.len());
    for section in pending {
        persist_temp(section.temp, &section.target, overwrite)?;
        outputs.push(ExtractedSection {
            name: section.name,
            output: section.target.display().to_string(),
            offset: section.offset,
            bytes: section.bytes,
            sha256: section.sha256,
        });
    }

    Ok(ExtractReport {
        input: input.display().to_string(),
        output_dir: output_dir.display().to_string(),
        format: info.format,
        machine: info.machine,
        outputs,
        total_bytes,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

fn select_sections(
    sections: &[SectionInfo],
    selection: Option<&[String]>,
    file_size: u64,
) -> Result<Vec<(usize, SectionInfo)>, ConvertError> {
    let mut selected = Vec::new();

    if let Some(requested) = selection {
        for request in requested {
            let found = resolve_request(sections, request)
                .ok_or_else(|| ConvertError::Executable(format!("section not found: {request}")))?;
            validate_section(&found.1, file_size)?;
            if found.1.data_size == 0 {
                return Err(ConvertError::Executable(format!(
                    "section {} has no data in the file",
                    found.1.name
                )));
            }
            if !selected.iter().any(|(index, _)| *index == found.0) {
                selected.push(found);
            }
        }
    } else {
        for (index, section) in sections.iter().enumerate() {
            if section.data_size == 0 {
                continue;
            }
            validate_section(section, file_size)?;
            selected.push((index, section.clone()));
        }
    }

    Ok(selected)
}

fn resolve_request(sections: &[SectionInfo], request: &str) -> Option<(usize, SectionInfo)> {
    if let Ok(index) = request.parse::<usize>()
        && let Some(section) = sections.get(index)
    {
        return Some((index, section.clone()));
    }

    let trimmed = request.strip_prefix('.').unwrap_or(request);
    sections
        .iter()
        .enumerate()
        .find(|(_, section)| {
            section.name.eq_ignore_ascii_case(request)
                || section
                    .name
                    .strip_prefix('.')
                    .unwrap_or(&section.name)
                    .eq_ignore_ascii_case(trimmed)
        })
        .map(|(index, section)| (index, section.clone()))
}

fn validate_section(section: &SectionInfo, file_size: u64) -> Result<(), ConvertError> {
    let end = section
        .offset
        .checked_add(section.data_size)
        .ok_or_else(|| ConvertError::Executable("section range overflows".to_owned()))?;
    if end > file_size {
        return Err(ConvertError::Executable(format!(
            "section {} is outside the file (0x{:x}+0x{:x} > 0x{file_size:x})",
            section.name, section.offset, section.data_size
        )));
    }
    Ok(())
}

fn clean_name(name: &str) -> Option<String> {
    let trimmed = name.trim().trim_start_matches('.');
    if trimmed.is_empty() {
        return None;
    }

    let sanitized: String = trimmed
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0' => '_',
            other => other,
        })
        .collect();
    let sanitized = sanitized
        .trim_matches(|ch: char| ch == ' ' || ch == '.')
        .to_owned();
    (!sanitized.is_empty()).then_some(sanitized)
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

/// Write a JSON manifest for an extraction report.
pub fn write_extract_manifest(path: &Path, report: &ExtractReport) -> Result<(), ConvertError> {
    let json = serde_json::to_vec_pretty(report)?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, json)?;
    Ok(())
}

/// Default suffix for extraction manifests.
pub fn manifest_name(input: &Path) -> PathBuf {
    let mut name = input
        .file_stem()
        .map(|stem| stem.to_os_string())
        .unwrap_or_else(|| OsString::from("output"));
    name.push(".sections.json");
    PathBuf::from(name)
}

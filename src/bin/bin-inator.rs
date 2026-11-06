use std::{fs, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand, ValueEnum};

use bin_inator::core::{
    ByteSwap, CancellationToken, ConvertOptions, ImageMode, ImageOptions, LineEndings, Overwrite,
    PadByte, PixelFormat, RawOptions, TextEncoding, TextInputEncoding, TextOptions,
    collect_files_excluding, convert_file, extract_sections, hash_file, human_bytes, inspect_file,
    pack_container, unpack_container, write_extract_manifest,
};

#[derive(Debug, Parser)]
#[command(
    name = "bin-inator",
    version,
    about = "Convert anything into .bin files"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Convert inputs into .bin files.
    Convert {
        /// One or more input files.
        #[arg(required = true, num_args = 1..)]
        inputs: Vec<PathBuf>,

        /// Destination directory (created when missing).
        #[arg(short, long)]
        output: PathBuf,

        /// What to do when the output file already exists.
        #[arg(long, value_enum, default_value = "error")]
        overwrite: OverwriteArg,

        /// Re-encode text into this encoding. Omit to copy text bytes as-is.
        #[arg(long, value_enum)]
        text_encoding: Option<TextEncodingArg>,

        /// Input text encoding (default: auto-detect BOM, otherwise UTF-8).
        #[arg(long, value_enum, default_value = "auto")]
        text_input: TextInputArg,

        /// Prefix UTF-8/UTF-16 output with a BOM.
        #[arg(long)]
        bom: bool,

        /// Line ending policy for text output.
        #[arg(long, value_enum, default_value = "preserve")]
        line_endings: LineEndingsArg,

        /// Image handling: copy the original bytes or dump raw pixels.
        #[arg(long, value_enum, default_value = "bytes")]
        image_mode: ImageModeArg,

        /// Raw pixel format for `--image-mode pixels`.
        #[arg(long, value_enum, default_value = "rgb8")]
        pixel_format: PixelFormatArg,

        /// Split output into parts of this many bytes.
        #[arg(long)]
        split_bytes: Option<u64>,

        /// Pad the payload to a multiple of this many bytes.
        #[arg(long)]
        pad_to: Option<u64>,

        /// Byte used for padding.
        #[arg(long, value_enum, default_value = "zero")]
        pad_byte: PadByteArg,

        /// Strip trailing zero bytes from the source before conversion.
        #[arg(long)]
        trim: bool,

        /// Byte-swap 16/32-bit words.
        #[arg(long, value_enum, default_value = "none")]
        swap: ByteSwapArg,

        /// Reverse the bits in every byte.
        #[arg(long)]
        bit_reverse: bool,

        /// Write a `<output>.json` sidecar with parameters and hashes.
        #[arg(long)]
        sidecar: bool,

        /// Descend into directories and convert every file found.
        #[arg(long)]
        recursive: bool,

        /// Write a JSON manifest describing the whole batch.
        #[arg(long)]
        manifest: Option<PathBuf>,
    },

    /// Pack a file into a reversible BINATOR1 container.
    Pack {
        /// Input file.
        input: PathBuf,

        /// Container path to write (for example `disk.binator`).
        #[arg(short, long)]
        output: PathBuf,

        /// What to do when the output file already exists.
        #[arg(long, value_enum, default_value = "error")]
        overwrite: OverwriteArg,

        /// Optional note stored in the container metadata.
        #[arg(long)]
        note: Option<String>,
    },

    /// Unpack a BINATOR1 container back to its original bytes.
    Unpack {
        /// Container file.
        input: PathBuf,

        /// Destination directory (created when missing).
        #[arg(short, long)]
        output: PathBuf,

        /// What to do when the output file already exists.
        #[arg(long, value_enum, default_value = "error")]
        overwrite: OverwriteArg,
    },

    /// Print the detected type and size of one or more files.
    Inspect {
        #[arg(required = true, num_args = 1..)]
        inputs: Vec<PathBuf>,

        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,

        /// Also compute SHA-256 and CRC32 (reads the whole file).
        #[arg(long)]
        hashes: bool,
    },

    /// Extract PE/ELF sections into header-free .bin files.
    Extract {
        /// Input executable (PE or ELF).
        input: PathBuf,

        /// Destination directory (created when missing).
        #[arg(short, long)]
        output: PathBuf,

        /// Section name (with or without a leading dot) or index from `inspect`.
        /// Repeat to extract several sections; omit to extract every non-empty section.
        #[arg(long = "section", value_name = "NAME|INDEX")]
        sections: Vec<String>,

        /// What to do when an output file already exists.
        #[arg(long, value_enum, default_value = "error")]
        overwrite: OverwriteArg,

        /// Write a JSON manifest with offsets and SHA-256 of every section.
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OverwriteArg {
    Error,
    Suffix,
    Replace,
}

impl From<OverwriteArg> for Overwrite {
    fn from(value: OverwriteArg) -> Self {
        match value {
            OverwriteArg::Error => Self::Error,
            OverwriteArg::Suffix => Self::Suffix,
            OverwriteArg::Replace => Self::Replace,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TextEncodingArg {
    Utf8,
    Utf16le,
    Utf16be,
    Cp1251,
    Ascii,
}

impl From<TextEncodingArg> for TextEncoding {
    fn from(value: TextEncodingArg) -> Self {
        match value {
            TextEncodingArg::Utf8 => Self::Utf8,
            TextEncodingArg::Utf16le => Self::Utf16Le,
            TextEncodingArg::Utf16be => Self::Utf16Be,
            TextEncodingArg::Cp1251 => Self::Windows1251,
            TextEncodingArg::Ascii => Self::Ascii,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TextInputArg {
    Auto,
    Utf8,
    Utf16le,
    Utf16be,
    Cp1251,
    Ascii,
}

impl From<TextInputArg> for TextInputEncoding {
    fn from(value: TextInputArg) -> Self {
        match value {
            TextInputArg::Auto => Self::Auto,
            TextInputArg::Utf8 => Self::Utf8,
            TextInputArg::Utf16le => Self::Utf16Le,
            TextInputArg::Utf16be => Self::Utf16Be,
            TextInputArg::Cp1251 => Self::Windows1251,
            TextInputArg::Ascii => Self::Ascii,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LineEndingsArg {
    Preserve,
    Lf,
    Crlf,
}

impl From<LineEndingsArg> for LineEndings {
    fn from(value: LineEndingsArg) -> Self {
        match value {
            LineEndingsArg::Preserve => Self::Preserve,
            LineEndingsArg::Lf => Self::Lf,
            LineEndingsArg::Crlf => Self::Crlf,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ImageModeArg {
    Bytes,
    Pixels,
}

impl From<ImageModeArg> for ImageMode {
    fn from(value: ImageModeArg) -> Self {
        match value {
            ImageModeArg::Bytes => Self::Bytes,
            ImageModeArg::Pixels => Self::Pixels,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PixelFormatArg {
    Rgb8,
    Rgba8,
    Luma8,
}

impl From<PixelFormatArg> for PixelFormat {
    fn from(value: PixelFormatArg) -> Self {
        match value {
            PixelFormatArg::Rgb8 => Self::Rgb8,
            PixelFormatArg::Rgba8 => Self::Rgba8,
            PixelFormatArg::Luma8 => Self::Luma8,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PadByteArg {
    Zero,
    Ff,
}

impl From<PadByteArg> for PadByte {
    fn from(value: PadByteArg) -> Self {
        match value {
            PadByteArg::Zero => Self::Zero,
            PadByteArg::Ff => Self::Ones,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ByteSwapArg {
    None,
    #[value(name = "16")]
    Swap16,
    #[value(name = "32")]
    Swap32,
}

impl From<ByteSwapArg> for ByteSwap {
    fn from(value: ByteSwapArg) -> Self {
        match value {
            ByteSwapArg::None => Self::None,
            ByteSwapArg::Swap16 => Self::Swap16,
            ByteSwapArg::Swap32 => Self::Swap32,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Convert {
            inputs,
            output,
            overwrite,
            text_encoding,
            text_input,
            bom,
            line_endings,
            image_mode,
            pixel_format,
            split_bytes,
            pad_to,
            pad_byte,
            trim,
            swap,
            bit_reverse,
            sidecar,
            recursive,
            manifest,
        } => {
            let options = ConvertOptions {
                overwrite: overwrite.into(),
                text: TextOptions {
                    output_encoding: text_encoding.map(Into::into),
                    input_encoding: text_input.into(),
                    bom,
                    line_endings: line_endings.into(),
                },
                image: ImageOptions {
                    mode: image_mode.into(),
                    format: pixel_format.into(),
                },
                raw: RawOptions {
                    split_size: split_bytes,
                    pad_to,
                    pad_byte: pad_byte.into(),
                    trim_trailing_zeros: trim,
                    swap: swap.into(),
                    bit_reverse,
                },
                sidecar,
            };

            run_convert(inputs, output, options, recursive, manifest)
        }
        Command::Pack {
            input,
            output,
            overwrite,
            note,
        } => run_pack(input, output, overwrite.into(), note),
        Command::Unpack {
            input,
            output,
            overwrite,
        } => run_unpack(input, output, overwrite.into()),
        Command::Inspect {
            inputs,
            json,
            hashes,
        } => run_inspect(inputs, json, hashes),
        Command::Extract {
            input,
            output,
            sections,
            overwrite,
            manifest,
        } => run_extract(input, output, sections, overwrite.into(), manifest),
    }
}

fn run_pack(
    input: PathBuf,
    output: PathBuf,
    overwrite: Overwrite,
    note: Option<String>,
) -> ExitCode {
    let cancel = CancellationToken::new();
    match pack_container(&input, &output, overwrite, note, &cancel, |_, _| {}) {
        Ok(report) => {
            println!(
                "{} -> {} ({:.2}s)",
                input.display(),
                report.output.display(),
                report.elapsed.as_secs_f64()
            );
            println!("  payload: {}", human_bytes(report.payload_bytes));
            println!("  sha256:  {}", report.sha256);
            println!("  crc32:   {:08x}", report.crc32);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {}: {error}", input.display());
            ExitCode::FAILURE
        }
    }
}

fn run_unpack(input: PathBuf, output_dir: PathBuf, overwrite: Overwrite) -> ExitCode {
    let cancel = CancellationToken::new();
    match unpack_container(&input, &output_dir, overwrite, &cancel, |_, _| {}) {
        Ok(report) => {
            println!(
                "{} -> {} ({:.2}s)",
                input.display(),
                report.output.display(),
                report.elapsed.as_secs_f64()
            );
            println!("  bytes:  {}", human_bytes(report.bytes));
            println!("  sha256: {}", report.sha256);
            println!("  crc32:  {:08x}", report.crc32);
            if let Some(note) = &report.metadata.note {
                println!("  note:   {note}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {}: {error}", input.display());
            ExitCode::FAILURE
        }
    }
}

fn run_convert(
    inputs: Vec<PathBuf>,
    output_dir: PathBuf,
    options: ConvertOptions,
    recursive: bool,
    manifest: Option<PathBuf>,
) -> ExitCode {
    let cancel = CancellationToken::new();
    let mut failures = 0_usize;
    let mut files = Vec::new();

    for input in &inputs {
        match collect_files_excluding(input, recursive, Some(&output_dir)) {
            Ok(found) if found.is_empty() => {
                eprintln!("error: {}: no files found", input.display());
                failures += 1;
            }
            Ok(found) => files.extend(found),
            Err(error) => {
                eprintln!("error: {}: {error}", input.display());
                failures += 1;
            }
        }
    }
    files.sort();
    files.dedup();

    let mut entries = Vec::with_capacity(files.len());
    for input in &files {
        match convert_file(input, &output_dir, &options, &cancel, |_, _| {}) {
            Ok(report) => {
                println!(
                    "{} -> {} part(s), {} ({:.2}s)",
                    input.display(),
                    report.outputs.len(),
                    human_bytes(report.bytes),
                    report.elapsed.as_secs_f64()
                );
                for path in &report.outputs {
                    println!("  {}", path.display());
                }
                println!("  sha256: {}", report.sha256);
                println!("  crc32:  {:08x}", report.crc32);
                if let Some(sidecar) = &report.sidecar {
                    println!("  sidecar: {}", sidecar.display());
                }

                entries.push(serde_json::json!({
                    "input": input.display().to_string(),
                    "outputs": report.outputs.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                    "bytes": report.bytes,
                    "sha256": report.sha256,
                    "crc32": format!("{:08x}", report.crc32),
                    "sidecar": report.sidecar.as_ref().map(|path| path.display().to_string()),
                    "elapsed_ms": report.elapsed.as_millis() as u64,
                }));
            }
            Err(error) => {
                eprintln!("error: {}: {error}", input.display());
                failures += 1;
                entries.push(serde_json::json!({
                    "input": input.display().to_string(),
                    "error": error.to_string(),
                }));
            }
        }
    }

    if let Some(path) = manifest {
        let document = serde_json::json!({
            "tool": "bin-inator",
            "version": env!("CARGO_PKG_VERSION"),
            "inputs": inputs.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            "files": files.len(),
            "succeeded": files.len().saturating_sub(failures),
            "failed": failures,
            "results": entries,
        });
        match serde_json::to_vec_pretty(&document) {
            Ok(json) => {
                if let Err(error) = fs::write(&path, json) {
                    eprintln!("error: {}: {error}", path.display());
                    failures += 1;
                }
            }
            Err(error) => {
                eprintln!("error: manifest: {error}");
                failures += 1;
            }
        }
    }

    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_inspect(inputs: Vec<PathBuf>, json: bool, with_hashes: bool) -> ExitCode {
    let cancel = CancellationToken::new();
    let mut failures = 0_usize;

    for input in inputs {
        match inspect_file(&input) {
            Ok(inspection) => {
                let hashes = if with_hashes {
                    match hash_file(&input, &cancel, |_, _| {}) {
                        Ok(hashes) => Some(hashes),
                        Err(error) => {
                            eprintln!("error: {}: {error}", input.display());
                            failures += 1;
                            None
                        }
                    }
                } else {
                    None
                };

                if json {
                    let value = serde_json::json!({
                        "inspection": inspection,
                        "hashes": hashes,
                    });
                    match serde_json::to_string_pretty(&value) {
                        Ok(text) => println!("{text}"),
                        Err(error) => {
                            eprintln!("error: {}: {error}", input.display());
                            failures += 1;
                        }
                    }
                } else {
                    print_inspection(&inspection, hashes.as_ref());
                }
            }
            Err(error) => {
                eprintln!("error: {}: {error}", input.display());
                failures += 1;
            }
        }
    }

    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_extract(
    input: PathBuf,
    output_dir: PathBuf,
    sections: Vec<String>,
    overwrite: Overwrite,
    manifest: Option<PathBuf>,
) -> ExitCode {
    let cancel = CancellationToken::new();
    let selection = (!sections.is_empty()).then_some(sections.as_slice());
    let mut failures = 0_usize;

    match extract_sections(
        &input,
        &output_dir,
        selection,
        overwrite,
        &cancel,
        |_, _| {},
    ) {
        Ok(report) => {
            println!(
                "{} -> {} section(s), {}, {} ({:.2}s)",
                input.display(),
                report.outputs.len(),
                report.format,
                human_bytes(report.total_bytes),
                report.elapsed_ms as f64 / 1000.0
            );
            for section in &report.outputs {
                println!(
                    "  {:<12} 0x{:<8x} {} sha256 {}",
                    section.name,
                    section.offset,
                    human_bytes(section.bytes),
                    section.sha256
                );
                println!("    {}", section.output);
            }

            if let Some(path) = manifest
                && let Err(error) = write_extract_manifest(&path, &report)
            {
                eprintln!("error: {}: {error}", path.display());
                failures += 1;
            }
        }
        Err(error) => {
            eprintln!("error: {}: {error}", input.display());
            failures += 1;
        }
    }

    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_inspection(
    inspection: &bin_inator::core::Inspection,
    hashes: Option<&bin_inator::core::Hashes>,
) {
    println!("{}", inspection.path);
    println!("  size: {}", human_bytes(inspection.size));
    println!("  kind: {}", inspection.kind);
    if let Some(mime) = &inspection.mime {
        println!("  mime: {mime}");
    }
    if let Some(extension) = &inspection.magic_extension {
        println!("  magic extension: {extension}");
    }

    if let Some(text) = &inspection.text {
        println!("  text encoding: {}", text.encoding);
        if let Some(bom) = &text.bom {
            println!("  bom: {bom}");
        }
        println!(
            "  ascii: {} · utf8: {} · nul: {}",
            text.ascii, text.utf8, text.has_nul
        );
        println!("  line endings: {}", text.line_endings);
    }

    if let Some(image) = &inspection.image {
        println!(
            "  image: {}x{} {} ({})",
            image.width, image.height, image.format, image.mime
        );
    }

    if let Some(executable) = &inspection.executable {
        println!(
            "  executable: {} {}, {} bit, entry 0x{:x}, image base 0x{:x}",
            executable.format,
            executable.machine,
            executable.bits,
            executable.entry_point,
            executable.image_base
        );
        for section in &executable.sections {
            println!(
                "    {:<10} off 0x{:<8x} size 0x{:<8x} vaddr 0x{:<8x} {}",
                section.name, section.offset, section.size, section.virtual_address, section.flags
            );
        }
    }

    if let Some(container) = &inspection.container {
        println!(
            "  container version: {}",
            bin_inator::core::CONTAINER_VERSION
        );
        println!("  payload: {}", human_bytes(container.payload_len));
        println!("  original name: {}", container.metadata.source_name);
        println!(
            "  original size: {}",
            human_bytes(container.metadata.source_size)
        );
        println!("  created unix ms: {}", container.metadata.created_unix_ms);
        if let Some(note) = &container.metadata.note {
            println!("  note: {note}");
        }
    }

    if let Some(hashes) = hashes {
        println!("  sha256: {}", hashes.sha256);
        println!("  crc32:  {:08x}", hashes.crc32);
    }

    if !inspection.head_hex.is_empty() {
        println!("  head: {}", inspection.head_hex);
    }
}

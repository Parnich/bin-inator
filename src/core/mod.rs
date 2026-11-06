//! GUI-independent conversion engine.

pub mod container;
pub mod convert;
pub mod detect;
pub mod error;
pub mod executable;
pub mod extract;
pub mod formats;
pub mod inspect;
pub mod options;
pub mod pipeline;
pub mod progress;
pub mod scan;
pub mod util;

pub use container::{
    ContainerInfo, ContainerMetadata, PackReport, UnpackReport, VERSION as CONTAINER_VERSION,
    inspect as inspect_container, pack as pack_container, unpack as unpack_container,
};
pub use convert::{ConvertReport, convert_file, preview_output_name};
pub use detect::{Detected, InputKind, detect};
pub use error::ConvertError;
pub use executable::{ExecutableInfo, SectionInfo, inspect as inspect_executable};
pub use extract::{
    ExtractReport, ExtractedSection, extract_sections, manifest_name as extract_manifest_name,
    write_extract_manifest,
};
pub use inspect::{Hashes, ImageInfo, Inspection, TextInfo, hash_file, inspect_file};
pub use options::{
    ByteSwap, ConvertOptions, ImageMode, ImageOptions, LineEndings, Overwrite, PadByte,
    PixelFormat, RawOptions, TextEncoding, TextInputEncoding, TextOptions,
};
pub use progress::CancellationToken;
pub use scan::{collect_files, collect_files_excluding};
pub use util::human_bytes;

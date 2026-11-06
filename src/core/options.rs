use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Overwrite {
    /// Refuse to write when the destination already exists.
    #[default]
    Error,
    /// Add ` (1)`, ` (2)`, ... before the extension.
    Suffix,
    /// Atomically replace the destination.
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextEncoding {
    #[default]
    Utf8,
    Utf16Le,
    Utf16Be,
    Windows1251,
    Ascii,
}

impl TextEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
            Self::Windows1251 => "windows-1251",
            Self::Ascii => "ascii",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextInputEncoding {
    #[default]
    Auto,
    Utf8,
    Utf16Le,
    Utf16Be,
    Windows1251,
    Ascii,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineEndings {
    #[default]
    Preserve,
    Lf,
    Crlf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TextOptions {
    /// `None` copies the original bytes instead of transcoding.
    pub output_encoding: Option<TextEncoding>,
    pub input_encoding: TextInputEncoding,
    pub bom: bool,
    pub line_endings: LineEndings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageMode {
    #[default]
    Bytes,
    Pixels,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PixelFormat {
    #[default]
    Rgb8,
    Rgba8,
    Luma8,
}

impl PixelFormat {
    pub fn channels(self) -> u8 {
        match self {
            Self::Rgb8 => 3,
            Self::Rgba8 => 4,
            Self::Luma8 => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rgb8 => "rgb8",
            Self::Rgba8 => "rgba8",
            Self::Luma8 => "luma8",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ImageOptions {
    pub mode: ImageMode,
    pub format: PixelFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteSwap {
    #[default]
    None,
    Swap16,
    Swap32,
}

impl ByteSwap {
    pub fn word_size(self) -> Option<usize> {
        match self {
            Self::None => None,
            Self::Swap16 => Some(2),
            Self::Swap32 => Some(4),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PadByte {
    #[default]
    Zero,
    Ones,
}

impl PadByte {
    pub fn value(self) -> u8 {
        match self {
            Self::Zero => 0x00,
            Self::Ones => 0xFF,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default)]
pub struct RawOptions {
    /// Split output into parts of this many bytes. `None` keeps one file.
    pub split_size: Option<u64>,
    /// Pad the whole payload to a multiple of this many bytes.
    pub pad_to: Option<u64>,
    pub pad_byte: PadByte,
    pub trim_trailing_zeros: bool,
    pub swap: ByteSwap,
    pub bit_reverse: bool,
}

impl Default for RawOptions {
    fn default() -> Self {
        Self {
            split_size: None,
            pad_to: None,
            pad_byte: PadByte::Zero,
            trim_trailing_zeros: false,
            swap: ByteSwap::None,
            bit_reverse: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ConvertOptions {
    pub overwrite: Overwrite,
    pub text: TextOptions,
    pub image: ImageOptions,
    pub raw: RawOptions,
    pub sidecar: bool,
}

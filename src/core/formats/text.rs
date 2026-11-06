use std::{borrow::Cow, fs, path::Path};

use encoding_rs::{Encoding, UTF_8, UTF_16BE, UTF_16LE, WINDOWS_1251};

use crate::core::{
    error::ConvertError,
    options::{LineEndings, TextEncoding, TextInputEncoding, TextOptions},
};

/// Decode, normalize and re-encode a text file.
///
/// Text is processed in memory because transcoding requires a complete decoded
/// string. This is intended for documents and logs, not multi-gigabyte captures.
pub fn transcode(path: &Path, options: &TextOptions) -> Result<Vec<u8>, ConvertError> {
    let Some(output_encoding) = options.output_encoding else {
        return Ok(fs::read(path)?);
    };

    let source = fs::read(path)?;
    if matches!(options.input_encoding, TextInputEncoding::Ascii) && !source.is_ascii() {
        return Err(ConvertError::Text(
            "input contains bytes outside ASCII".to_owned(),
        ));
    }

    let encoding = input_encoding(options.input_encoding, &source);
    let (decoded, _, had_errors) = encoding.decode(&source);
    if had_errors {
        return Err(ConvertError::Text(format!(
            "input is not valid {}",
            encoding.name()
        )));
    }

    let normalized = normalize_newlines(&decoded, options.line_endings);
    let encoded = encode(&normalized, output_encoding, options.bom)?;
    Ok(encoded)
}

fn input_encoding(encoding: TextInputEncoding, source: &[u8]) -> &'static Encoding {
    match encoding {
        TextInputEncoding::Auto => Encoding::for_bom(source)
            .map(|(encoding, _)| encoding)
            .unwrap_or(UTF_8),
        TextInputEncoding::Utf8 | TextInputEncoding::Ascii => UTF_8,
        TextInputEncoding::Utf16Le => UTF_16LE,
        TextInputEncoding::Utf16Be => UTF_16BE,
        TextInputEncoding::Windows1251 => WINDOWS_1251,
    }
}

fn encode(text: &str, encoding: TextEncoding, with_bom: bool) -> Result<Vec<u8>, ConvertError> {
    if encoding == TextEncoding::Ascii && !text.is_ascii() {
        return Err(ConvertError::Text(
            "text contains characters outside ASCII".to_owned(),
        ));
    }

    let bytes: Vec<u8> = match encoding {
        TextEncoding::Utf8 | TextEncoding::Ascii => text.as_bytes().to_vec(),
        TextEncoding::Utf16Le => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        TextEncoding::Utf16Be => text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        TextEncoding::Windows1251 => {
            let (bytes, _, had_unmappable) = WINDOWS_1251.encode(text);
            if had_unmappable {
                return Err(ConvertError::Text(format!(
                    "text cannot be represented as {}",
                    encoding.as_str()
                )));
            }
            bytes.into_owned()
        }
    };

    let bom: &[u8] = if with_bom {
        match encoding {
            TextEncoding::Utf8 => &[0xEF, 0xBB, 0xBF],
            TextEncoding::Utf16Le => &[0xFF, 0xFE],
            TextEncoding::Utf16Be => &[0xFE, 0xFF],
            TextEncoding::Windows1251 | TextEncoding::Ascii => &[],
        }
    } else {
        &[]
    };

    let mut output = Vec::with_capacity(bom.len() + bytes.len());
    output.extend_from_slice(bom);
    output.extend_from_slice(&bytes);
    Ok(output)
}

fn normalize_newlines(text: &str, mode: LineEndings) -> Cow<'_, str> {
    match mode {
        LineEndings::Preserve => Cow::Borrowed(text),
        LineEndings::Lf => {
            if text.contains('\r') {
                Cow::Owned(text.replace("\r\n", "\n").replace('\r', "\n"))
            } else {
                Cow::Borrowed(text)
            }
        }
        LineEndings::Crlf => {
            let lf = if text.contains('\r') {
                text.replace("\r\n", "\n").replace('\r', "\n")
            } else {
                text.to_owned()
            };
            Cow::Owned(lf.replace('\n', "\r\n"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_line_endings() {
        assert_eq!(
            normalize_newlines("a\r\nb\rc\n", LineEndings::Lf),
            "a\nb\nc\n"
        );
        assert_eq!(
            normalize_newlines("a\nb\n", LineEndings::Crlf),
            "a\r\nb\r\n"
        );
    }

    #[test]
    fn encodes_utf16_with_bom() {
        let bytes = encode("hi", TextEncoding::Utf16Le, true).unwrap();
        assert_eq!(bytes, [0xFF, 0xFE, b'h', 0, b'i', 0]);
    }
}

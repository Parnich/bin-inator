use std::path::Path;

use serde::Serialize;

use crate::core::{error::ConvertError, options::PixelFormat};

#[derive(Debug, Clone, Serialize)]
pub struct ImageMetadata {
    pub width: u32,
    pub height: u32,
    pub channels: u8,
    pub format: &'static str,
    pub row_order: &'static str,
}

pub struct ImagePayload {
    pub bytes: Vec<u8>,
    pub metadata: ImageMetadata,
}

/// Decode an image and produce a headerless raw pixel buffer.
pub fn dump_pixels(path: &Path, format: PixelFormat) -> Result<ImagePayload, ConvertError> {
    let image = image::open(path).map_err(|error| ConvertError::Image(error.to_string()))?;

    let (bytes, width, height) = match format {
        PixelFormat::Rgb8 => {
            let buffer = image.to_rgb8();
            let (width, height) = buffer.dimensions();
            (buffer.into_raw(), width, height)
        }
        PixelFormat::Rgba8 => {
            let buffer = image.to_rgba8();
            let (width, height) = buffer.dimensions();
            (buffer.into_raw(), width, height)
        }
        PixelFormat::Luma8 => {
            let buffer = image.to_luma8();
            let (width, height) = buffer.dimensions();
            (buffer.into_raw(), width, height)
        }
    };

    Ok(ImagePayload {
        bytes,
        metadata: ImageMetadata {
            width,
            height,
            channels: format.channels(),
            format: format.as_str(),
            row_order: "top_to_bottom",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumps_rgba_pixels_in_row_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pixels.png");

        let image = image::RgbaImage::from_raw(
            2,
            2,
            vec![
                255, 0, 0, 255, // top-left red
                0, 255, 0, 255, // top-right green
                0, 0, 255, 255, // bottom-left blue
                255, 255, 255, 255, // bottom-right white
            ],
        )
        .unwrap();
        image.save(&path).unwrap();

        let payload = dump_pixels(&path, PixelFormat::Rgba8).unwrap();
        assert_eq!(payload.metadata.width, 2);
        assert_eq!(payload.metadata.height, 2);
        assert_eq!(payload.metadata.channels, 4);
        assert_eq!(payload.metadata.format, "rgba8");
        assert_eq!(
            payload.bytes,
            vec![
                255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255
            ]
        );
    }
}

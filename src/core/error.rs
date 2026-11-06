use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConvertError {
    #[error("input is not a regular file: {}", .0.display())]
    NotAFile(PathBuf),
    #[error("output already exists: {}", .0.display())]
    OutputExists(PathBuf),
    #[error("refusing to overwrite the input file: {}", .0.display())]
    SameFile(PathBuf),
    #[error("conversion cancelled")]
    Cancelled,
    #[error("invalid option: {0}")]
    InvalidOptions(String),
    #[error("image conversion failed: {0}")]
    Image(String),
    #[error("text conversion failed: {0}")]
    Text(String),
    #[error("container error: {0}")]
    Container(String),
    #[error("executable error: {0}")]
    Executable(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

use std::fs;

use bin_inator::core::{
    CancellationToken, ConvertError, InputKind, Overwrite, detect, inspect_container,
    pack_container, unpack_container,
};
use crc32fast::Hasher as Crc32;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

#[test]
fn packs_and_unpacks_byte_identical() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("disk.img");
    let data = payload(2 * 1024 * 1024 + 777);
    fs::write(&input, &data).unwrap();

    let container = dir.path().join("disk.binator");
    let report = pack_container(
        &input,
        &container,
        Overwrite::Error,
        Some("round trip".to_owned()),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(report.payload_bytes, data.len() as u64);
    let expected_sha: String = Sha256::digest(&data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(report.sha256, expected_sha);

    let info = inspect_container(&container).unwrap();
    assert_eq!(info.metadata.source_name, "disk.img");
    assert_eq!(info.metadata.source_size, data.len() as u64);
    assert_eq!(info.metadata.note.as_deref(), Some("round trip"));
    assert_eq!(info.metadata.kind, "disk_image");

    let output_dir = dir.path().join("unpacked");
    let unpacked = unpack_container(
        &container,
        &output_dir,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(unpacked.output, output_dir.join("disk.img"));
    assert_eq!(unpacked.bytes, data.len() as u64);
    assert_eq!(fs::read(&unpacked.output).unwrap(), data);
}

#[test]
fn unpacks_empty_payload() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("empty.dat");
    fs::write(&input, b"").unwrap();
    let container = dir.path().join("empty.binator");

    let report = pack_container(
        &input,
        &container,
        Overwrite::Error,
        None,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(report.payload_bytes, 0);
    assert_eq!(
        report.sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let unpacked = unpack_container(
        &container,
        &dir.path().join("out"),
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(fs::read(unpacked.output).unwrap(), b"");
}

#[test]
fn container_is_detected_by_magic() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, b"hello").unwrap();
    let container = dir.path().join("sample.data");
    pack_container(
        &input,
        &container,
        Overwrite::Error,
        None,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(detect(&container).unwrap().kind, InputKind::Container);
}

#[test]
fn refuses_existing_container_and_supports_suffix() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, b"hello").unwrap();
    let container = dir.path().join("sample.binator");

    pack_container(
        &input,
        &container,
        Overwrite::Error,
        None,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    let error = pack_container(
        &input,
        &container,
        Overwrite::Error,
        None,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(error, ConvertError::OutputExists(_)));

    let report = pack_container(
        &input,
        &container,
        Overwrite::Suffix,
        None,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(report.output, dir.path().join("sample (1).binator"));
}

#[test]
fn unpack_honours_overwrite_policy() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, b"first").unwrap();
    let container = dir.path().join("sample.binator");
    pack_container(
        &input,
        &container,
        Overwrite::Error,
        None,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    let output_dir = dir.path().join("out");
    fs::create_dir_all(&output_dir).unwrap();
    fs::write(output_dir.join("sample.dat"), b"existing").unwrap();

    let error = unpack_container(
        &container,
        &output_dir,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(error, ConvertError::OutputExists(_)));

    let report = unpack_container(
        &container,
        &output_dir,
        Overwrite::Suffix,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(report.output, output_dir.join("sample (1).dat"));
}

#[test]
fn detects_corrupted_payload() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, payload(4096)).unwrap();
    let container = dir.path().join("sample.binator");
    pack_container(
        &input,
        &container,
        Overwrite::Error,
        None,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    let info = inspect_container(&container).unwrap();
    let mut bytes = fs::read(&container).unwrap();
    let index = info.payload_offset as usize + 100;
    bytes[index] ^= 0xFF;
    fs::write(&container, &bytes).unwrap();

    let output_dir = dir.path().join("out");
    let error = unpack_container(
        &container,
        &output_dir,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(error, ConvertError::Container(message) if message.contains("checksum")));
    assert_eq!(fs::read_dir(&output_dir).unwrap().count(), 0);
}

#[test]
fn rejects_truncated_container() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, b"hello").unwrap();
    let container = dir.path().join("sample.binator");
    pack_container(
        &input,
        &container,
        Overwrite::Error,
        None,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    let mut bytes = fs::read(&container).unwrap();
    bytes.pop();
    fs::write(&container, &bytes).unwrap();

    let output_dir = dir.path().join("out");
    let error = unpack_container(
        &container,
        &output_dir,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(error, ConvertError::Container(_)));
    assert!(!output_dir.exists() || fs::read_dir(&output_dir).unwrap().next().is_none());
}

#[test]
fn cancellation_leaves_no_container() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, payload(4096)).unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();

    let output_dir = dir.path().join("out");
    let error = pack_container(
        &input,
        &output_dir.join("sample.binator"),
        Overwrite::Error,
        None,
        &cancel,
        |_, _| {},
    )
    .unwrap_err();

    assert!(matches!(error, ConvertError::Cancelled));
    assert_eq!(fs::read_dir(&output_dir).unwrap().count(), 0);
}

#[test]
fn sanitizes_metadata_file_name_on_unpack() {
    let dir = tempdir().unwrap();
    let container = dir.path().join("evil.binator");
    let metadata = serde_json::json!({
        "source_name": "../../evil.bin",
        "source_size": 1,
        "kind": "binary",
        "mime": null,
        "note": null,
        "created_unix_ms": 0,
        "tool": "test",
        "tool_version": "0"
    });
    fs::write(&container, build_container(&metadata, b"x")).unwrap();

    let output_dir = dir.path().join("out");
    let report = unpack_container(
        &container,
        &output_dir,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(report.output, output_dir.join("evil.bin"));
    assert_eq!(fs::read(report.output).unwrap(), b"x");
}

fn build_container(metadata: &serde_json::Value, payload: &[u8]) -> Vec<u8> {
    let metadata = serde_json::to_vec(metadata).unwrap();
    let payload_offset = 64 + metadata.len() as u64;

    let mut header = [0_u8; 64];
    header[..8].copy_from_slice(b"BINATOR1");
    header[8..10].copy_from_slice(&1_u16.to_le_bytes());
    header[12..16].copy_from_slice(&64_u32.to_le_bytes());
    header[16..24].copy_from_slice(&payload_offset.to_le_bytes());
    header[24..32].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    header[32..36].copy_from_slice(&(metadata.len() as u32).to_le_bytes());

    let mut crc = Crc32::new();
    crc.update(&header[..36]);
    header[36..40].copy_from_slice(&crc.finalize().to_le_bytes());

    let mut output = Vec::new();
    output.extend_from_slice(&header);
    output.extend_from_slice(&metadata);
    output.extend_from_slice(payload);

    let mut payload_crc = Crc32::new();
    payload_crc.update(payload);
    output.extend_from_slice(&payload_crc.finalize().to_le_bytes());
    output.extend_from_slice(&Sha256::digest(payload));
    output
}

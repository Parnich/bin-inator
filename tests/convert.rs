use std::fs;

use bin_inator::core::{
    CancellationToken, ConvertError, ConvertOptions, InputKind, LineEndings, Overwrite, PadByte,
    TextEncoding, convert_file, detect,
};
use tempfile::tempdir;

fn options(overwrite: Overwrite) -> ConvertOptions {
    ConvertOptions {
        overwrite,
        ..Default::default()
    }
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

#[test]
fn copies_bytes_to_bin() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    let data = payload(2 * 1024 * 1024 + 123);
    fs::write(&input, &data).unwrap();

    let output_dir = dir.path().join("out");
    let report = convert_file(
        &input,
        &output_dir,
        &options(Overwrite::Error),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(report.outputs, vec![output_dir.join("sample.bin")]);
    assert_eq!(report.bytes, data.len() as u64);
    assert_eq!(fs::read(report.primary_output()).unwrap(), data);
}

#[test]
fn reports_sha256_and_crc32() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("hello.bin-source");
    fs::write(&input, b"hello").unwrap();

    let report = convert_file(
        &input,
        &dir.path().join("out"),
        &options(Overwrite::Error),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(
        report.sha256,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(report.crc32, 0x3610_a686);
}

#[test]
fn refuses_existing_output() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, b"hello").unwrap();
    let output_dir = dir.path().join("out");

    convert_file(
        &input,
        &output_dir,
        &options(Overwrite::Error),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    let error = convert_file(
        &input,
        &output_dir,
        &options(Overwrite::Error),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap_err();

    assert!(matches!(error, ConvertError::OutputExists(path) if path.ends_with("sample.bin")));
}

#[test]
fn adds_suffix_for_existing_output() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, b"hello").unwrap();
    let output_dir = dir.path().join("out");

    convert_file(
        &input,
        &output_dir,
        &options(Overwrite::Suffix),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    let report = convert_file(
        &input,
        &output_dir,
        &options(Overwrite::Suffix),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(report.outputs, vec![output_dir.join("sample (1).bin")]);
}

#[test]
fn replaces_existing_output() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    let output_dir = dir.path().join("out");
    fs::write(&input, b"first").unwrap();

    convert_file(
        &input,
        &output_dir,
        &options(Overwrite::Replace),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    fs::write(&input, b"second").unwrap();
    let report = convert_file(
        &input,
        &output_dir,
        &options(Overwrite::Replace),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(fs::read(report.primary_output()).unwrap(), b"second");
}

#[test]
fn refuses_to_overwrite_input_file() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("same.bin");
    fs::write(&input, b"keep me").unwrap();

    let error = convert_file(
        &input,
        dir.path(),
        &options(Overwrite::Replace),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap_err();

    assert!(matches!(error, ConvertError::SameFile(_)));
    assert_eq!(fs::read(input).unwrap(), b"keep me");
}

#[test]
fn cancellation_writes_nothing() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, payload(4096)).unwrap();
    let output_dir = dir.path().join("out");
    let cancel = CancellationToken::new();
    cancel.cancel();

    let error = convert_file(
        &input,
        &output_dir,
        &options(Overwrite::Error),
        &cancel,
        |_, _| {},
    )
    .unwrap_err();

    assert!(matches!(error, ConvertError::Cancelled));
    assert_eq!(fs::read_dir(output_dir).unwrap().count(), 0);
}

#[test]
fn splits_payload_into_numbered_parts() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, b"abcdefghij").unwrap();
    let output_dir = dir.path().join("out");

    let mut options = options(Overwrite::Error);
    options.raw.split_size = Some(4);
    let report = convert_file(
        &input,
        &output_dir,
        &options,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(
        report.outputs,
        vec![
            output_dir.join("sample.part001.bin"),
            output_dir.join("sample.part002.bin"),
            output_dir.join("sample.part003.bin"),
        ]
    );
    assert_eq!(fs::read(&report.outputs[0]).unwrap(), b"abcd");
    assert_eq!(fs::read(&report.outputs[1]).unwrap(), b"efgh");
    assert_eq!(fs::read(&report.outputs[2]).unwrap(), b"ij");
    assert_eq!(report.bytes, 10);
}

#[test]
fn pads_payload_and_hashes_padding() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, b"abcde").unwrap();

    let mut options = options(Overwrite::Error);
    options.raw.pad_to = Some(8);
    options.raw.pad_byte = PadByte::Ones;
    let report = convert_file(
        &input,
        &dir.path().join("out"),
        &options,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(report.bytes, 8);
    assert_eq!(
        fs::read(report.primary_output()).unwrap(),
        b"abcde\xff\xff\xff"
    );
}

#[test]
fn trims_trailing_zero_bytes() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, [1_u8, 2, 3, 0, 0, 0]).unwrap();

    let mut options = options(Overwrite::Error);
    options.raw.trim_trailing_zeros = true;
    let report = convert_file(
        &input,
        &dir.path().join("out"),
        &options,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(report.bytes, 3);
    assert_eq!(fs::read(report.primary_output()).unwrap(), [1, 2, 3]);
}

#[test]
fn swaps_words_and_reverses_bits() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, [0b0000_0001, 0b0000_0010, 0b0000_0011, 0b0000_0100]).unwrap();

    let mut options = options(Overwrite::Error);
    options.raw.swap = bin_inator::core::ByteSwap::Swap16;
    let report = convert_file(
        &input,
        &dir.path().join("swap"),
        &options,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(
        fs::read(report.primary_output()).unwrap(),
        [0b0000_0010, 0b0000_0001, 0b0000_0100, 0b0000_0011]
    );

    options.raw.swap = bin_inator::core::ByteSwap::None;
    options.raw.bit_reverse = true;
    let report = convert_file(
        &input,
        &dir.path().join("bits"),
        &options,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(
        fs::read(report.primary_output()).unwrap(),
        [0b1000_0000, 0b0100_0000, 0b1100_0000, 0b0010_0000]
    );
}

#[test]
fn transcodes_text_to_utf16_with_bom() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("hello.txt");
    fs::write(&input, "hi\r\n").unwrap();

    let mut options = options(Overwrite::Error);
    options.text.output_encoding = Some(TextEncoding::Utf16Le);
    options.text.line_endings = LineEndings::Lf;
    options.text.bom = true;

    let report = convert_file(
        &input,
        &dir.path().join("out"),
        &options,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(
        fs::read(report.primary_output()).unwrap(),
        [0xFF, 0xFE, b'h', 0, b'i', 0, b'\n', 0]
    );
}

#[test]
fn writes_json_sidecar() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.dat");
    fs::write(&input, b"hello").unwrap();

    let mut options = options(Overwrite::Error);
    options.sidecar = true;
    let report = convert_file(
        &input,
        &dir.path().join("out"),
        &options,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    let sidecar_path = report.sidecar.expect("sidecar path");
    let sidecar: serde_json::Value =
        serde_json::from_slice(&fs::read(sidecar_path).unwrap()).unwrap();
    assert_eq!(sidecar["sha256"].as_str().unwrap(), report.sha256);
    assert_eq!(
        sidecar["crc32"].as_str().unwrap(),
        format!("{:08x}", report.crc32)
    );
    assert_eq!(sidecar["parts"][0].as_str().unwrap(), "sample.bin");
}

#[test]
fn detects_text_image_and_binary() {
    let dir = tempdir().unwrap();

    let text = dir.path().join("notes.txt");
    fs::write(&text, "привет, bin-inator").unwrap();
    assert_eq!(detect(&text).unwrap().kind, InputKind::Text);

    let image = dir.path().join("pixel.png");
    fs::write(
        &image,
        [
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, b'I', b'H',
            b'D', b'R',
        ],
    )
    .unwrap();
    assert_eq!(detect(&image).unwrap().kind, InputKind::Image);

    let binary = dir.path().join("blob.dat");
    fs::write(&binary, [0_u8, 1, 2, 3, 4, 5]).unwrap();
    assert_eq!(detect(&binary).unwrap().kind, InputKind::Binary);
}

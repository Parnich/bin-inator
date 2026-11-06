use std::fs;

use bin_inator::core::{CancellationToken, Overwrite, hash_file, inspect_file, pack_container};
use tempfile::tempdir;

#[test]
fn inspects_text_details() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("notes.txt");
    fs::write(&path, b"hello\r\nworld\r\n").unwrap();

    let inspection = inspect_file(&path).unwrap();
    assert_eq!(inspection.kind, "text");
    let text = inspection.text.unwrap();
    assert_eq!(text.encoding, "ascii");
    assert!(text.ascii);
    assert!(text.utf8);
    assert!(!text.has_nul);
    assert_eq!(text.line_endings, "crlf");
    assert_eq!(text.bom, None);
    assert!(inspection.head_hex.starts_with("68656c6c6f"));
}

#[test]
fn detects_utf16_bom() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wide.txt");
    fs::write(&path, [0xFF, 0xFE, b'h', 0, b'i', 0]).unwrap();

    let inspection = inspect_file(&path).unwrap();
    let text = inspection.text.unwrap();
    assert_eq!(text.encoding, "utf-16le");
    assert_eq!(text.bom.as_deref(), Some("utf-16le"));
}

#[test]
fn inspects_image_dimensions() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pixels.png");
    let image = image::RgbImage::from_pixel(3, 2, image::Rgb([10, 20, 30]));
    image.save(&path).unwrap();

    let inspection = inspect_file(&path).unwrap();
    assert_eq!(inspection.kind, "image");
    let image = inspection.image.unwrap();
    assert_eq!(image.width, 3);
    assert_eq!(image.height, 2);
    assert_eq!(image.format, "png");
    assert_eq!(image.mime, "image/png");
}

#[test]
fn computes_hashes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hello.dat");
    fs::write(&path, b"hello").unwrap();

    let hashes = hash_file(&path, &CancellationToken::new(), |_, _| {}).unwrap();
    assert_eq!(
        hashes.sha256,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(hashes.crc32, 0x3610_a686);
}

#[test]
fn inspects_container_metadata() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("payload.dat");
    fs::write(&input, b"hello").unwrap();
    let container = dir.path().join("payload.binator");
    pack_container(
        &input,
        &container,
        Overwrite::Error,
        Some("inspect me".to_owned()),
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    let inspection = inspect_file(&container).unwrap();
    assert_eq!(inspection.kind, "container");
    let info = inspection.container.unwrap();
    assert_eq!(info.metadata.source_name, "payload.dat");
    assert_eq!(info.payload_len, 5);
    assert_eq!(info.metadata.note.as_deref(), Some("inspect me"));
}

#[test]
fn inspects_pe_headers() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sample.exe");
    fs::write(&path, build_pe()).unwrap();

    let inspection = inspect_file(&path).unwrap();
    let executable = inspection.executable.expect("PE headers");
    assert_eq!(executable.format, "PE32+");
    assert_eq!(executable.machine, "x86-64");
    assert_eq!(executable.bits, 64);
    assert_eq!(executable.entry_point, 0x1000);
    assert_eq!(executable.image_base, 0x1_4000_0000);
    assert_eq!(executable.sections.len(), 1);
    assert_eq!(executable.sections[0].name, ".text");
    assert_eq!(executable.sections[0].offset, 0x400);
    assert_eq!(executable.sections[0].size, 0x200);
    assert_eq!(executable.sections[0].data_size, 0x200);
    assert_eq!(executable.sections[0].flags, "R-X");
}

#[test]
fn inspects_elf_headers() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sample.elf");
    fs::write(&path, build_elf64()).unwrap();

    let inspection = inspect_file(&path).unwrap();
    let executable = inspection.executable.expect("ELF headers");
    assert_eq!(executable.format, "ELF64");
    assert_eq!(executable.machine, "x86-64");
    assert_eq!(executable.bits, 64);
    assert_eq!(executable.entry_point, 0x401000);
    let names: Vec<&str> = executable
        .sections
        .iter()
        .map(|section| section.name.as_str())
        .collect();
    assert_eq!(names, vec![".text", ".shstrtab"]);
    assert_eq!(executable.sections[0].offset, 0x100);
    assert_eq!(executable.sections[0].size, 4);
    assert_eq!(executable.sections[0].data_size, 4);
    assert_eq!(executable.sections[0].flags, "R-X");
}

fn build_pe() -> Vec<u8> {
    let mut data = vec![0_u8; 0x600];
    data[..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&0x40_u32.to_le_bytes());

    data[0x40..0x44].copy_from_slice(b"PE\0\0");
    data[0x44..0x46].copy_from_slice(&0x8664_u16.to_le_bytes());
    data[0x46..0x48].copy_from_slice(&1_u16.to_le_bytes());
    data[0x54..0x56].copy_from_slice(&0xF0_u16.to_le_bytes());

    let optional = 0x58;
    data[optional..optional + 2].copy_from_slice(&0x20B_u16.to_le_bytes());
    data[optional + 16..optional + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
    data[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());

    let section = optional + 0xF0;
    data[section..section + 5].copy_from_slice(b".text");
    data[section + 8..section + 12].copy_from_slice(&0x100_u32.to_le_bytes());
    data[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
    data[section + 16..section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
    data[section + 20..section + 24].copy_from_slice(&0x400_u32.to_le_bytes());
    data[section + 36..section + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());

    data
}

fn build_elf64() -> Vec<u8> {
    let mut data = vec![0_u8; 0x3C0];
    data[..4].copy_from_slice(b"\x7FELF");
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    data[16..18].copy_from_slice(&2_u16.to_le_bytes());
    data[18..20].copy_from_slice(&0x3E_u16.to_le_bytes());
    data[20..24].copy_from_slice(&1_u32.to_le_bytes());
    data[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
    data[40..48].copy_from_slice(&0x300_u64.to_le_bytes());
    data[52..54].copy_from_slice(&64_u16.to_le_bytes());
    data[58..60].copy_from_slice(&64_u16.to_le_bytes());
    data[60..62].copy_from_slice(&3_u16.to_le_bytes());
    data[62..64].copy_from_slice(&2_u16.to_le_bytes());

    data[0x100..0x104].copy_from_slice(&[0x90, 0x90, 0xC3, 0x00]);
    data[0x200..0x211].copy_from_slice(b"\0.text\0.shstrtab\0");

    let text = 0x340;
    data[text..text + 4].copy_from_slice(&1_u32.to_le_bytes());
    data[text + 4..text + 8].copy_from_slice(&1_u32.to_le_bytes());
    data[text + 8..text + 16].copy_from_slice(&0x6_u64.to_le_bytes());
    data[text + 16..text + 24].copy_from_slice(&0x401000_u64.to_le_bytes());
    data[text + 24..text + 32].copy_from_slice(&0x100_u64.to_le_bytes());
    data[text + 32..text + 40].copy_from_slice(&4_u64.to_le_bytes());
    data[text + 48..text + 56].copy_from_slice(&1_u64.to_le_bytes());

    let strings = 0x380;
    data[strings..strings + 4].copy_from_slice(&7_u32.to_le_bytes());
    data[strings + 4..strings + 8].copy_from_slice(&3_u32.to_le_bytes());
    data[strings + 24..strings + 32].copy_from_slice(&0x200_u64.to_le_bytes());
    data[strings + 32..strings + 40].copy_from_slice(&17_u64.to_le_bytes());
    data[strings + 48..strings + 56].copy_from_slice(&1_u64.to_le_bytes());

    data
}

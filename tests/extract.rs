use std::fs;

use bin_inator::core::{
    CancellationToken, ConvertError, Overwrite, extract_sections, write_extract_manifest,
};
use tempfile::tempdir;

struct PeSection {
    name: &'static str,
    offset: u32,
    size: u32,
    virtual_size: u32,
    characteristics: u32,
}

impl PeSection {
    fn new(name: &'static str, offset: u32, data: &[u8]) -> Self {
        Self {
            name,
            offset,
            size: data.len() as u32,
            virtual_size: data.len() as u32,
            characteristics: 0x6000_0020,
        }
    }

    fn bss(name: &'static str, virtual_size: u32) -> Self {
        Self {
            name,
            offset: 0,
            size: 0,
            virtual_size,
            characteristics: 0xC000_0080,
        }
    }
}

fn build_pe(sections: &[PeSection], data: &[(u32, &[u8])], file_size: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; file_size];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&0x40_u32.to_le_bytes());

    bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
    bytes[0x44..0x46].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[0x46..0x48].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    bytes[0x54..0x56].copy_from_slice(&0xF0_u16.to_le_bytes());

    let optional = 0x58;
    bytes[optional..optional + 2].copy_from_slice(&0x20B_u16.to_le_bytes());
    bytes[optional + 16..optional + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());

    let table = optional + 0xF0;
    for (index, section) in sections.iter().enumerate() {
        let entry = table + index * 40;
        let name = section.name.as_bytes();
        bytes[entry..entry + name.len()].copy_from_slice(name);
        bytes[entry + 8..entry + 12].copy_from_slice(&section.virtual_size.to_le_bytes());
        bytes[entry + 12..entry + 16]
            .copy_from_slice(&(0x1000 + index as u32 * 0x1000).to_le_bytes());
        bytes[entry + 16..entry + 20].copy_from_slice(&section.size.to_le_bytes());
        bytes[entry + 20..entry + 24].copy_from_slice(&section.offset.to_le_bytes());
        bytes[entry + 36..entry + 40].copy_from_slice(&section.characteristics.to_le_bytes());
    }

    for (offset, content) in data {
        let start = *offset as usize;
        bytes[start..start + content.len()].copy_from_slice(content);
    }

    bytes
}

fn write_pe(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn build_simple_pe() -> Vec<u8> {
    build_pe(
        &[
            PeSection::new(".text", 0x400, &[1, 2, 3, 4]),
            PeSection::new(".data", 0x500, &[9, 8, 7]),
        ],
        &[(0x400, &[1, 2, 3, 4]), (0x500, &[9, 8, 7])],
        0x600,
    )
}

fn build_elf64() -> Vec<u8> {
    let mut data = vec![0_u8; 0x400];
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
    data[60..62].copy_from_slice(&4_u16.to_le_bytes());
    data[62..64].copy_from_slice(&3_u16.to_le_bytes());

    data[0x100..0x104].copy_from_slice(&[0x90, 0x90, 0xC3, 0x42]);

    let names = b"\0.text\0.bss\0.shstrtab\0";
    data[0x200..0x200 + names.len()].copy_from_slice(names);

    let table = 0x300;
    let text = table + 64;
    data[text..text + 4].copy_from_slice(&1_u32.to_le_bytes());
    data[text + 4..text + 8].copy_from_slice(&1_u32.to_le_bytes());
    data[text + 8..text + 16].copy_from_slice(&0x6_u64.to_le_bytes());
    data[text + 16..text + 24].copy_from_slice(&0x401000_u64.to_le_bytes());
    data[text + 24..text + 32].copy_from_slice(&0x100_u64.to_le_bytes());
    data[text + 32..text + 40].copy_from_slice(&4_u64.to_le_bytes());

    let bss = table + 128;
    data[bss..bss + 4].copy_from_slice(&7_u32.to_le_bytes());
    data[bss + 4..bss + 8].copy_from_slice(&8_u32.to_le_bytes());
    data[bss + 8..bss + 16].copy_from_slice(&0x3_u64.to_le_bytes());
    data[bss + 16..bss + 24].copy_from_slice(&0x402000_u64.to_le_bytes());
    data[bss + 24..bss + 32].copy_from_slice(&0x200_u64.to_le_bytes());
    data[bss + 32..bss + 40].copy_from_slice(&8_u64.to_le_bytes());

    let strings = table + 192;
    data[strings..strings + 4].copy_from_slice(&12_u32.to_le_bytes());
    data[strings + 4..strings + 8].copy_from_slice(&3_u32.to_le_bytes());
    data[strings + 24..strings + 32].copy_from_slice(&0x200_u64.to_le_bytes());
    data[strings + 32..strings + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());

    data
}

fn output_names(report: &bin_inator::core::ExtractReport) -> Vec<String> {
    report
        .outputs
        .iter()
        .map(|section| {
            std::path::Path::new(&section.output)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

#[test]
fn extracts_all_pe_sections() {
    let dir = tempdir().unwrap();
    let input = write_pe(dir.path(), "app.exe", &build_simple_pe());
    let output = dir.path().join("out");

    let report = extract_sections(
        &input,
        &output,
        None,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(report.format, "PE32+");
    assert_eq!(report.machine, "x86-64");
    assert_eq!(report.total_bytes, 7);
    assert_eq!(output_names(&report), vec!["app.text.bin", "app.data.bin"]);
    assert_eq!(fs::read(output.join("app.text.bin")).unwrap(), [1, 2, 3, 4]);
    assert_eq!(fs::read(output.join("app.data.bin")).unwrap(), [9, 8, 7]);
    assert_eq!(report.outputs[0].bytes, 4);
    assert_eq!(
        report.outputs[0].sha256,
        "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a"
    );
}

#[test]
fn extracts_selected_sections_by_name_and_index() {
    let dir = tempdir().unwrap();
    let input = write_pe(dir.path(), "app.exe", &build_simple_pe());
    let cancel = CancellationToken::new();

    let by_name = extract_sections(
        &input,
        &dir.path().join("by-name"),
        Some(&["data".to_owned()]),
        Overwrite::Error,
        &cancel,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(output_names(&by_name), vec!["app.data.bin"]);

    let by_index = extract_sections(
        &input,
        &dir.path().join("by-index"),
        Some(&["0".to_owned()]),
        Overwrite::Error,
        &cancel,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(output_names(&by_index), vec!["app.text.bin"]);
    assert_eq!(by_index.outputs[0].offset, 0x400);

    let duplicate = extract_sections(
        &input,
        &dir.path().join("duplicate"),
        Some(&[".text".to_owned(), "text".to_owned(), "0".to_owned()]),
        Overwrite::Error,
        &cancel,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(output_names(&duplicate), vec!["app.text.bin"]);
}

#[test]
fn extracts_elf_sections_and_skips_nobits() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("sample.elf");
    fs::write(&input, build_elf64()).unwrap();

    let report = extract_sections(
        &input,
        &dir.path().join("out"),
        None,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    assert_eq!(report.format, "ELF64");
    let names = output_names(&report);
    assert!(names.contains(&"sample.text.bin".to_owned()));
    assert!(names.contains(&"sample.shstrtab.bin".to_owned()));
    assert!(!names.contains(&"sample.bss.bin".to_owned()));
    assert_eq!(
        fs::read(dir.path().join("out/sample.text.bin")).unwrap(),
        [0x90, 0x90, 0xC3, 0x42]
    );
}

#[test]
fn rejects_missing_and_nobits_sections() {
    let dir = tempdir().unwrap();
    let elf = dir.path().join("sample.elf");
    fs::write(&elf, build_elf64()).unwrap();
    let cancel = CancellationToken::new();

    let missing = extract_sections(
        &elf,
        &dir.path().join("missing"),
        Some(&[".nope".to_owned()]),
        Overwrite::Error,
        &cancel,
        |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(missing, ConvertError::Executable(message) if message.contains("not found")));

    let nobits = extract_sections(
        &elf,
        &dir.path().join("bss"),
        Some(&[".bss".to_owned()]),
        Overwrite::Error,
        &cancel,
        |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(nobits, ConvertError::Executable(message) if message.contains("no data")));
}

#[test]
fn suffix_overwrite_keeps_both_runs() {
    let dir = tempdir().unwrap();
    let input = write_pe(dir.path(), "app.exe", &build_simple_pe());
    let output = dir.path().join("out");
    let cancel = CancellationToken::new();

    let first =
        extract_sections(&input, &output, None, Overwrite::Error, &cancel, |_, _| {}).unwrap();
    assert_eq!(first.outputs.len(), 2);

    let second =
        extract_sections(&input, &output, None, Overwrite::Suffix, &cancel, |_, _| {}).unwrap();
    assert_eq!(second.outputs.len(), 2);
    let names = output_names(&second);
    assert_eq!(names, vec!["app.text (1).bin", "app.data (1).bin"]);
    assert_eq!(fs::read(output.join("app.text.bin")).unwrap(), [1, 2, 3, 4]);
    assert_eq!(
        fs::read(output.join("app.text (1).bin")).unwrap(),
        [1, 2, 3, 4]
    );
}

#[test]
fn replace_overwrites_existing_sections() {
    let dir = tempdir().unwrap();
    let input = write_pe(dir.path(), "app.exe", &build_simple_pe());
    let output = dir.path().join("out");
    let cancel = CancellationToken::new();

    extract_sections(&input, &output, None, Overwrite::Error, &cancel, |_, _| {}).unwrap();
    fs::write(output.join("app.text.bin"), b"stale").unwrap();

    extract_sections(
        &input,
        &output,
        None,
        Overwrite::Replace,
        &cancel,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(fs::read(output.join("app.text.bin")).unwrap(), [1, 2, 3, 4]);
}

#[test]
fn cancellation_leaves_no_output_files() {
    let dir = tempdir().unwrap();
    let input = write_pe(dir.path(), "app.exe", &build_simple_pe());
    let output = dir.path().join("out");
    let cancel = CancellationToken::new();
    cancel.cancel();

    let error =
        extract_sections(&input, &output, None, Overwrite::Error, &cancel, |_, _| {}).unwrap_err();
    assert!(matches!(error, ConvertError::Cancelled));
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
}

#[test]
fn rejects_sections_outside_the_file() {
    let dir = tempdir().unwrap();
    let section = PeSection {
        name: ".evil",
        offset: 0x500,
        size: 0x400,
        virtual_size: 0x400,
        characteristics: 0x4000_0040,
    };
    let input = write_pe(dir.path(), "evil.exe", &build_pe(&[section], &[], 0x600));
    let output = dir.path().join("out");

    let error = extract_sections(
        &input,
        &output,
        None,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(error, ConvertError::Executable(message) if message.contains("outside")));
    assert!(!output.exists());
}

#[test]
fn deduplicates_repeated_section_names() {
    let dir = tempdir().unwrap();
    let input = write_pe(
        dir.path(),
        "dup.exe",
        &build_pe(
            &[
                PeSection::new(".text", 0x400, &[1, 2]),
                PeSection::new(".text", 0x500, &[3, 4]),
            ],
            &[(0x400, &[1, 2]), (0x500, &[3, 4])],
            0x600,
        ),
    );

    let report = extract_sections(
        &input,
        &dir.path().join("out"),
        None,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(
        output_names(&report),
        vec!["dup.text.bin", "dup.text-2.bin"]
    );
}

#[test]
fn loads_data_size_for_virtual_sections() {
    let dir = tempdir().unwrap();
    let input = write_pe(
        dir.path(),
        "bss.exe",
        &build_pe(
            &[
                PeSection::new(".data", 0x400, &[1, 2, 3]),
                PeSection::bss(".bss", 0x1000),
            ],
            &[(0x400, &[1, 2, 3])],
            0x500,
        ),
    );

    let report = extract_sections(
        &input,
        &dir.path().join("out"),
        None,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(output_names(&report), vec!["bss.data.bin"]);
}

#[test]
fn sanitizes_section_names() {
    let dir = tempdir().unwrap();
    let input = write_pe(
        dir.path(),
        "weird.exe",
        &build_pe(
            &[
                PeSection::new("..text..", 0x400, &[1]),
                PeSection::new("bad/name", 0x500, &[2]),
            ],
            &[(0x400, &[1]), (0x500, &[2])],
            0x600,
        ),
    );

    let report = extract_sections(
        &input,
        &dir.path().join("out"),
        None,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(
        output_names(&report),
        vec!["weird.text.bin", "weird.bad_name.bin"]
    );
}

#[test]
fn writes_extract_manifest() {
    let dir = tempdir().unwrap();
    let input = write_pe(dir.path(), "app.exe", &build_simple_pe());
    let output = dir.path().join("out");
    let report = extract_sections(
        &input,
        &output,
        None,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap();

    let manifest = dir.path().join("reports/app.sections.json");
    write_extract_manifest(&manifest, &report).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(value["format"], "PE32+");
    assert_eq!(value["total_bytes"], 7);
    assert_eq!(value["outputs"].as_array().unwrap().len(), 2);
    assert_eq!(value["outputs"][0]["sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn rejects_non_executable_inputs() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("notes.txt");
    fs::write(&input, b"just text").unwrap();

    let error = extract_sections(
        &input,
        &dir.path().join("out"),
        None,
        Overwrite::Error,
        &CancellationToken::new(),
        |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(error, ConvertError::Executable(_)));
}

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

use serde::Serialize;

use crate::core::error::ConvertError;

const MAX_SECTIONS: usize = 4096;
const MAX_STRING_TABLE: u64 = 16 * 1024 * 1024;
const MAX_NAME_LEN: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub offset: u64,
    /// Size shown in listings; for PE this falls back to the virtual size.
    pub size: u64,
    /// Bytes that actually exist in the file. Zero for `.bss`/`SHT_NOBITS`.
    pub data_size: u64,
    pub virtual_address: u64,
    pub flags: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecutableInfo {
    /// `PE32`, `PE32+` or `ELF32`/`ELF64`.
    pub format: String,
    pub machine: String,
    pub bits: u16,
    pub entry_point: u64,
    pub image_base: u64,
    pub sections: Vec<SectionInfo>,
}

/// Parse PE or ELF headers. Returns `Ok(None)` for other files.
pub fn inspect(path: &Path) -> Result<Option<ExecutableInfo>, ConvertError> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();

    let mut magic = [0_u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return Ok(None);
    }

    match magic {
        [b'M', b'Z', _, _] => parse_pe(&mut file, file_size).map(Some),
        [0x7F, b'E', b'L', b'F'] => parse_elf(&mut file, file_size).map(Some),
        _ => Ok(None),
    }
}

fn parse_pe(file: &mut File, file_size: u64) -> Result<ExecutableInfo, ConvertError> {
    let mut dos = [0_u8; 0x40];
    read_at(file, 0, &mut dos)?;
    let pe_offset = u32::from_le_bytes(dos[0x3C..0x40].try_into().expect("four bytes")) as u64;

    let mut signature = [0_u8; 4];
    read_at(file, pe_offset, &mut signature)?;
    if &signature != b"PE\0\0" {
        return Err(ConvertError::Executable("missing PE signature".to_owned()));
    }

    let mut coff = [0_u8; 20];
    read_at(file, pe_offset + 4, &mut coff)?;
    let machine = u16::from_le_bytes(coff[..2].try_into().expect("two bytes"));
    let section_count = u16::from_le_bytes(coff[2..4].try_into().expect("two bytes")) as usize;
    let optional_size = u16::from_le_bytes(coff[16..18].try_into().expect("two bytes")) as u64;

    if section_count > 96 {
        return Err(ConvertError::Executable(format!(
            "PE section count {section_count} is above the format limit"
        )));
    }

    let optional_offset = pe_offset + 24;
    let mut optional = [0_u8; 32];
    let optional_read = optional_size.min(optional.len() as u64) as usize;
    read_at(file, optional_offset, &mut optional[..optional_read])?;

    let magic = u16::from_le_bytes(optional[..2].try_into().expect("two bytes"));
    let (bits, image_base) = match magic {
        0x10B => (
            32,
            u32::from_le_bytes(optional[28..32].try_into().expect("four bytes")) as u64,
        ),
        0x20B => {
            let mut base = [0_u8; 8];
            read_at(file, optional_offset + 24, &mut base)?;
            (64, u64::from_le_bytes(base))
        }
        other => {
            return Err(ConvertError::Executable(format!(
                "unknown PE optional header magic 0x{other:04x}"
            )));
        }
    };

    let entry_point = u32::from_le_bytes(optional[16..20].try_into().expect("four bytes")) as u64;

    let section_table = optional_offset + optional_size;
    let table_size = section_count as u64 * 40;
    if section_table + table_size > file_size {
        return Err(ConvertError::Executable(
            "PE section table is outside the file".to_owned(),
        ));
    }

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let mut header = [0_u8; 40];
        read_at(file, section_table + index as u64 * 40, &mut header)?;

        let name_end = header[..8].iter().position(|byte| *byte == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&header[..name_end]).into_owned();
        let virtual_size = u32::from_le_bytes(header[8..12].try_into().expect("four bytes")) as u64;
        let virtual_address =
            u32::from_le_bytes(header[12..16].try_into().expect("four bytes")) as u64;
        let raw_size = u32::from_le_bytes(header[16..20].try_into().expect("four bytes")) as u64;
        let raw_offset = u32::from_le_bytes(header[20..24].try_into().expect("four bytes")) as u64;
        let characteristics = u32::from_le_bytes(header[36..40].try_into().expect("four bytes"));

        sections.push(SectionInfo {
            name,
            offset: raw_offset,
            size: if raw_size > 0 { raw_size } else { virtual_size },
            data_size: raw_size,
            virtual_address,
            flags: pe_flags(characteristics),
        });
    }

    Ok(ExecutableInfo {
        format: if bits == 64 { "PE32+" } else { "PE32" }.to_owned(),
        machine: pe_machine(machine).to_owned(),
        bits,
        entry_point,
        image_base,
        sections,
    })
}

fn parse_elf(file: &mut File, file_size: u64) -> Result<ExecutableInfo, ConvertError> {
    file.seek(SeekFrom::Start(0))?;
    let header_len = file_size.min(64) as usize;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header[..header_len])?;
    if header_len < 16 {
        return Err(ConvertError::Executable("truncated ELF header".to_owned()));
    }

    let (bits, little_endian) = match (header[4], header[5]) {
        (1, 1) => (32_u16, true),
        (1, 2) => (32, false),
        (2, 1) => (64, true),
        (2, 2) => (64, false),
        (class, data) => {
            return Err(ConvertError::Executable(format!(
                "unsupported ELF class {class} or data encoding {data}"
            )));
        }
    };
    let endian = Endian {
        little: little_endian,
    };

    let (machine, entry, section_offset, section_entry_size, section_count, name_index) =
        if bits == 32 {
            if header_len < 52 {
                return Err(ConvertError::Executable(
                    "truncated ELF32 header".to_owned(),
                ));
            }
            (
                endian.u16(&header[18..20]),
                endian.u32(&header[24..28]) as u64,
                endian.u32(&header[32..36]) as u64,
                endian.u16(&header[46..48]) as u64,
                endian.u16(&header[48..50]) as u64,
                endian.u16(&header[50..52]) as u64,
            )
        } else {
            if header_len < 64 {
                return Err(ConvertError::Executable(
                    "truncated ELF64 header".to_owned(),
                ));
            }
            (
                endian.u16(&header[18..20]),
                endian.u64(&header[24..32]),
                endian.u64(&header[40..48]),
                endian.u16(&header[58..60]) as u64,
                endian.u16(&header[60..62]) as u64,
                endian.u16(&header[62..64]) as u64,
            )
        };

    if section_offset == 0 || section_count == 0 {
        return Ok(ExecutableInfo {
            format: format!("ELF{bits}"),
            machine: elf_machine(machine).to_owned(),
            bits,
            entry_point: entry,
            image_base: 0,
            sections: Vec::new(),
        });
    }

    if section_count as usize > MAX_SECTIONS {
        return Err(ConvertError::Executable(format!(
            "ELF section count {section_count} exceeds the limit"
        )));
    }
    if section_entry_size < if bits == 32 { 40 } else { 64 } {
        return Err(ConvertError::Executable(
            "ELF section entry is too small".to_owned(),
        ));
    }
    if section_offset + section_count * section_entry_size > file_size {
        return Err(ConvertError::Executable(
            "ELF section table is outside the file".to_owned(),
        ));
    }

    let mut headers = Vec::with_capacity(section_count as usize);
    let mut entry_buffer = vec![0_u8; section_entry_size as usize];
    for index in 0..section_count {
        read_at(
            file,
            section_offset + index * section_entry_size,
            &mut entry_buffer,
        )?;
        headers.push(parse_elf_section(&entry_buffer, bits, endian));
    }

    let names = if name_index < section_count {
        let string_section = &headers[name_index as usize];
        if string_section.size > MAX_STRING_TABLE
            || string_section.offset + string_section.size > file_size
        {
            Vec::new()
        } else {
            let mut data = vec![0_u8; string_section.size as usize];
            read_at(file, string_section.offset, &mut data)?;
            data
        }
    } else {
        Vec::new()
    };

    let sections = headers
        .iter()
        .filter(|section| section.section_type != 0)
        .map(|section| SectionInfo {
            name: section_name(&names, section.name_offset),
            offset: section.offset,
            size: section.size,
            data_size: if section.section_type == 8 {
                0
            } else {
                section.size
            },
            virtual_address: section.address,
            flags: elf_flags(section.flags),
        })
        .collect();

    Ok(ExecutableInfo {
        format: format!("ELF{bits}"),
        machine: elf_machine(machine).to_owned(),
        bits,
        entry_point: entry,
        image_base: 0,
        sections,
    })
}

struct ElfSection {
    name_offset: u32,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
}

fn parse_elf_section(data: &[u8], bits: u16, endian: Endian) -> ElfSection {
    if bits == 32 {
        ElfSection {
            name_offset: endian.u32(&data[0..4]),
            section_type: endian.u32(&data[4..8]),
            flags: endian.u32(&data[8..12]) as u64,
            address: endian.u32(&data[12..16]) as u64,
            offset: endian.u32(&data[16..20]) as u64,
            size: endian.u32(&data[20..24]) as u64,
        }
    } else {
        ElfSection {
            name_offset: endian.u32(&data[0..4]),
            section_type: endian.u32(&data[4..8]),
            flags: endian.u64(&data[8..16]),
            address: endian.u64(&data[16..24]),
            offset: endian.u64(&data[24..32]),
            size: endian.u64(&data[32..40]),
        }
    }
}

fn section_name(table: &[u8], offset: u32) -> String {
    let start = offset as usize;
    if start >= table.len() {
        return String::new();
    }
    let end = table[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|length| start + length.min(MAX_NAME_LEN))
        .unwrap_or(table.len());
    String::from_utf8_lossy(&table[start..end]).into_owned()
}

fn pe_flags(characteristics: u32) -> String {
    let read = characteristics & 0x4000_0000 != 0;
    let write = characteristics & 0x8000_0000 != 0;
    let execute = characteristics & 0x2000_0000 != 0;
    flag_string(read, write, execute)
}

fn elf_flags(flags: u64) -> String {
    let write = flags & 0x1 != 0;
    let allocate = flags & 0x2 != 0;
    let execute = flags & 0x4 != 0;
    flag_string(allocate || flags == 0, write, execute)
}

fn flag_string(read: bool, write: bool, execute: bool) -> String {
    let mut flags = String::with_capacity(3);
    flags.push(if read { 'R' } else { '-' });
    flags.push(if write { 'W' } else { '-' });
    flags.push(if execute { 'X' } else { '-' });
    flags
}

fn pe_machine(machine: u16) -> &'static str {
    match machine {
        0x014C => "x86",
        0x8664 => "x86-64",
        0x01C0 | 0x01C2 | 0x01C4 => "ARM",
        0xAA64 => "ARM64",
        0x0200 => "Itanium",
        0x5032 => "RISC-V 32",
        0x5064 => "RISC-V 64",
        _ => "unknown",
    }
}

fn elf_machine(machine: u16) -> &'static str {
    match machine {
        0x03 => "x86",
        0x3E => "x86-64",
        0x28 => "ARM",
        0xB7 => "AArch64",
        0x08 => "MIPS",
        0x14 => "PowerPC",
        0x15 => "PowerPC64",
        0x02 => "SPARC",
        0xF3 => "RISC-V",
        _ => "unknown",
    }
}

fn read_at(file: &mut File, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buffer)
}

#[derive(Clone, Copy)]
struct Endian {
    little: bool,
}

impl Endian {
    fn u16(&self, bytes: &[u8]) -> u16 {
        let value = [bytes[0], bytes[1]];
        if self.little {
            u16::from_le_bytes(value)
        } else {
            u16::from_be_bytes(value)
        }
    }

    fn u32(&self, bytes: &[u8]) -> u32 {
        let value = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if self.little {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        }
    }

    fn u64(&self, bytes: &[u8]) -> u64 {
        let value = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];
        if self.little {
            u64::from_le_bytes(value)
        } else {
            u64::from_be_bytes(value)
        }
    }
}

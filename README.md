# bin-inator

Converts anything into `.bin`: text, images, executables, dumps, disk images, and arbitrary data.

## Status

M0–M4: the raw pipeline, transforms, container, inspector, batch mode, and PE/ELF section extraction.

- streaming raw copies into `.bin` in 1 MiB chunks;
- type detection by magic bytes and file extension;
- drag-and-drop and a batch queue in the GUI;
- progress and cancellation that leave no temporary files behind;
- atomic writes through temporary files;
- text transcoding (UTF-8, UTF-16 LE/BE, Windows-1251, ASCII), BOM, and line endings;
- raw image pixel dumps (RGB8, RGBA8, Luma8);
- splitting into parts, padding, trailing-zero trimming, 16/32-bit byte swapping, and bit reversal;
- SHA-256 and CRC32 for every result;
- an optional JSON sidecar with parameters, hashes, and image metadata;
- the `BINATOR1` container (`pack`/`unpack`) with metadata, CRC32, SHA-256, and a byte-identical payload;
- inspection of type, MIME, text traits, image dimensions, PE/ELF headers and sections, container metadata, a head hex dump, and SHA-256/CRC32;
- batch mode: recursive folder traversal in the GUI and CLI, plus a JSON batch manifest;
- PE/ELF section extraction into separate `.bin` files with bounds checks, SHA-256, and a JSON manifest;
- the `convert`, `pack`, `unpack`, `inspect`, and `extract` CLI commands;
- settings in `%APPDATA%\bin-inator\settings.json`.

Container specification: [`docs/FORMAT.md`](docs/FORMAT.md).

## Running

```bash
cargo run --bin bin-inator-gui
```

```bash
cargo run --bin bin-inator -- inspect photo.png
cargo run --bin bin-inator -- inspect app.exe --hashes
cargo run --bin bin-inator -- convert photo.png -o out
cargo run --bin bin-inator -- convert disk.img -o out --overwrite suffix

# Batch-process a folder and write a manifest
cargo run --bin bin-inator -- convert samples -o out --recursive --sidecar --manifest out/batch.json
```

Section extraction:

```bash
# Every non-empty PE/ELF section
cargo run --bin bin-inator -- extract app.exe -o sections

# Selected sections (name with or without a leading dot, or an index from inspect)
cargo run --bin bin-inator -- extract app.exe -o sections --section .text --section 2 --overwrite suffix

# JSON manifest with offsets and SHA-256
cargo run --bin bin-inator -- extract app.exe -o sections --manifest sections/app.sections.json
```

M1 examples:

```bash
# Transcode text to UTF-16 LE with a BOM and LF line endings
cargo run --bin bin-inator -- convert notes.txt -o out --text-encoding utf16le --bom --line-endings lf

# Raw RGBA8 pixels
cargo run --bin bin-inator -- convert photo.png -o out --image-mode pixels --pixel-format rgba8

# Split a disk image into 4 MiB parts, pad it, and write a sidecar
cargo run --bin bin-inator -- convert disk.img -o out --split-bytes 4194304 --pad-to 4096 --sidecar

# Swap byte order and trim trailing zeros
cargo run --bin bin-inator -- convert dump.bin -o out --swap 16 --trim
```

Container:

```bash
# Pack a file without changing its bytes
cargo run --bin bin-inator -- pack disk.img -o out/disk.binator --note "original image"

# Show container metadata and hashes
cargo run --bin bin-inator -- inspect out/disk.binator --json

# Unpack it back (the file name comes from metadata)
cargo run --bin bin-inator -- unpack out/disk.binator -o restored
```

In the GUI, enable the pack checkbox to create `.binator` files, or add
containers to the list and use the unpack action.

The Inspect tab shows PE/ELF headers, sections, text traits, image dimensions,
container metadata, and hashes. The Add folder action in the queue starts
recursive batch mode. The Extract sections action saves PE/ELF sections to a
selected folder with progress and cancellation.

## Output naming

- without splitting: `<stem>.bin`;
- with splitting: `<stem>.part001.bin`, `<stem>.part002.bin`, …;
- sidecar: `<first_output_file>.json`;
- sections: `<stem>.<section>.bin`; duplicate names get `-2`, `-3`, ….

## Release

```powershell
# PowerShell 7+
pwsh scripts/package.ps1

# Windows PowerShell 5.1
powershell -ExecutionPolicy Bypass -File scripts/package.ps1
```

The script builds with `--release --bins` and writes
`dist/bin-inator-<version>-windows-x64.zip` containing `bin-inator.exe`,
`bin-inator-gui.exe`, the README, `docs/FORMAT.md`, and `VERSION.txt`.
To repackage without rebuilding, pass `-SkipBuild`.

## Checks

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

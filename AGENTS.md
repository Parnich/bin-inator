# AGENTS.md

## Current state

- M0–M4 are implemented: streaming raw `.bin` conversion, type detection, GUI, CLI, progress/cancel, settings, text transcoding, image pixel dumps, split/pad/trim/byte-swap/bit-reverse, SHA-256/CRC32, JSON sidecars, the reversible `BINATOR1` container, the Inspect tab with PE/ELF headers, recursive batch mode with JSON manifests, PE/ELF section extraction, and the release packaging script.
- Not implemented yet: anything beyond M4 (for example code signing or installers).
- Container format is specified in `docs/FORMAT.md`; keep it in sync with `src/core/container.rs`.
- The directory is not a git repository. Do not assume git history or branches.
- `Cargo.lock` and `Cargo.toml` are the source of truth for dependency versions (eframe 0.37, edition 2024).

## Commands

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test <test_name>
cargo run --bin bin-inator-gui
cargo run --bin bin-inator -- inspect <file> [--json] [--hashes]
cargo run --bin bin-inator -- convert <input>... -o <dir> [--overwrite error|suffix|replace] [--recursive] [--manifest <file>]
cargo run --bin bin-inator -- convert <input> -o <dir> [--text-encoding utf16le] [--image-mode pixels] [--split-bytes N] [--pad-to N] [--sidecar]
cargo run --bin bin-inator -- pack <input> -o <file.binator> [--note TEXT]
cargo run --bin bin-inator -- unpack <file.binator> -o <dir>
cargo run --bin bin-inator -- extract <input.exe|input.elf> -o <dir> [--section NAME|INDEX]... [--overwrite error|suffix|replace] [--manifest <file>]
cargo build --release --bin bin-inator-gui
pwsh scripts/package.ps1 [-SkipBuild]   # or: powershell -ExecutionPolicy Bypass -File scripts/package.ps1
```

The first GUI build compiles the whole eframe/wgpu stack and is slow. `default-run = "bin-inator-gui"`, so bare `cargo run` opens the GUI.

## egui/eframe 0.37 API quirks

- `eframe::App` implements `fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame)`, not `update(&mut self, ctx, frame)`.
- Use `egui::Panel::top/bottom/right(...).show(ui, ...)`. `SidePanel` and `TopBottomPanel` no longer exist in this version. Add `CentralPanel` last.
- `Context::style_mut` no longer exists; use `style_mut_of(Theme::Dark, ...)` and `set_theme`.
- Dropped files are `Arc<dyn DroppedFile>` and expose `path()` as a method returning `&Path`; there is no `path` field.
- The GUI binary is the only one with `windows_subsystem = "windows"`; keep console-friendly CLI behavior.

## Architecture

```
src/core/                 GUI-independent engine
  convert.rs              orchestration, report, JSON sidecar
  container.rs            BINATOR1 pack/unpack/inspect, header and checksums
  inspect.rs              type-specific inspection and streaming hashes
  executable.rs           PE/ELF header and section parsing
  extract.rs              PE/ELF section extraction, manifest
  scan.rs                 recursive file collection for batch mode
  pipeline.rs             streaming transforms, hashes, split/pad, atomic output
  options.rs              conversion option enums and structs (serde)
  formats/text.rs         decode, newline normalization, re-encode, BOM
  formats/raster.rs       image decode and raw pixel dump
  detect.rs               magic + extension detection, output naming
  error.rs                ConvertError
  progress.rs             cancellation token
  util.rs                 human-readable byte sizes
src/gui/app.rs            single-window egui app and worker thread
src/bin/bin-inator.rs     CLI (clap)
src/bin/bin-inator-gui.rs GUI entrypoint
tests/convert.rs          integration tests
```

`src/core` must not import `eframe`, `rfd`, or Windows APIs. The GUI owns the worker thread and communicates via `std::sync::mpsc`.

## Invariants

- Stream in 1 MiB chunks; never read an entire disk image into memory. Text transcoding and image pixel dumps are explicit opt-in exceptions.
- Write into a `tempfile` in the target directory, flush + `sync_all`, then `persist`/`persist_noclobber`. Tests rely on cancellation leaving no files behind.
- Keep raw output header-free. Do not silently add metadata inside `.bin`; use a sidecar when that feature is added.
- Raw output is the source bytes unless an option is explicitly enabled. Text transcoding only runs when `output_encoding` is `Some`.
- Hashes and padding cover the final payload bytes, including padding, and span all split parts.
- Split naming is `<stem>.partNNN.bin`; unsplit is `<stem>.bin`; the sidecar is `<primary_output>.json`.
- Refuse to overwrite the input file, including `Replace` mode (`ConvertError::SameFile`).
- Detection uses magic bytes first (including `BINATOR1`), extension second, then UTF-8/NUL sampling.
- Container packing never transforms payload bytes; unpack must verify CRC32 and SHA-256 before publishing output.
- Container metadata is UTF-8 JSON and may be extended; readers ignore unknown fields.
- Unpacked names come from metadata but must be reduced to a sanitized file name (no traversal).
- Inspection is read-only; hashes stream in 1 MiB chunks and respect cancellation.
- PE/ELF parsing must bounds-check every offset against the file size and cap section counts.
- `SectionInfo::data_size` is the file-backed byte count; `.bss`/`SHT_NOBITS` have `data_size == 0` and must never be extracted from an offset.
- Extraction stages every section in temporary files and publishes them only after all sections are read; cancellation leaves no outputs.
- Extracted section names are sanitized; output is `<stem>.<section>.bin` and duplicate names get `-2`, `-3`, ….
- Batch scanning returns sorted, deduplicated regular files and guards against directory cycles.
- Settings live in `%APPDATA%\bin-inator\settings.json`.
- Russian UI strings are in `src/gui/app.rs`; core and CLI messages stay English.

## Testing notes

- `tests/convert.rs`, `tests/container.rs`, `tests/inspect.rs`, and `tests/extract.rs` use `tempfile`; no external services or fixtures are needed.
- Cover overwrite modes, same-file rejection, cancellation cleanup, and detection when changing the pipeline.
- Container tests cover byte-identical round trip, empty payload, suffix/replace, corruption, truncation, cancellation, and path traversal in metadata.
- Inspect tests build synthetic PE and ELF headers; keep them valid when changing `executable.rs`.
- Extract tests cover all/named/indexed sections, `.bss`/`SHT_NOBITS` skipping, overwrite modes, cancellation cleanup, bounds rejection, duplicate names, and manifests.
- Batch scan tests cover top-level vs recursive collection.
- `docs/FORMAT.md` must stay in sync with `src/core/container.rs`.

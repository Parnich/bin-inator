use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
    time::Duration,
};

use directories::{ProjectDirs, UserDirs};
use eframe::egui::{self, Align, Color32, Layout, RichText};
use serde::{Deserialize, Serialize};

use crate::core::{
    ByteSwap, CancellationToken, ConvertError, ConvertOptions, ConvertReport, Detected,
    ExtractReport, Hashes, ImageMode, InputKind, Inspection, LineEndings, Overwrite, PackReport,
    PadByte, PixelFormat, TextEncoding, TextInputEncoding, UnpackReport, collect_files_excluding,
    convert_file, detect, extract_sections, hash_file, human_bytes, inspect_file, pack_container,
    preview_output_name, unpack_container,
};

const BG: Color32 = Color32::from_rgb(17, 19, 24);
const PANEL_BG: Color32 = Color32::from_rgb(22, 25, 31);
const ACCENT: Color32 = Color32::from_rgb(90, 145, 255);
const OK: Color32 = Color32::from_rgb(104, 203, 138);
const WARN: Color32 = Color32::from_rgb(255, 184, 92);
const ERROR: Color32 = Color32::from_rgb(255, 112, 112);
const MUTED: Color32 = Color32::from_rgb(145, 153, 170);

#[derive(Debug, Clone)]
struct FileEntry {
    path: PathBuf,
    detected: Detected,
}

impl FileEntry {
    fn name(&self) -> String {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.display().to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunState {
    Idle,
    Running,
}

#[derive(Debug, Clone, Copy)]
enum LogLevel {
    Info,
    Ok,
    Error,
}

struct LogEntry {
    level: LogLevel,
    text: String,
}

enum JobOutcome {
    Converted(ConvertReport),
    Packed(PackReport),
    Unpacked(UnpackReport),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobKind {
    Convert,
    Unpack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Convert,
    Inspect,
}

enum InspectEvent {
    Ready(Box<Inspection>),
    Hashes(Hashes),
    Progress { processed: u64, total: u64 },
    Failed(String),
}

enum ExtractEvent {
    Progress { processed: u64, total: u64 },
    Finished(Box<ExtractReport>),
    Failed(String),
    Cancelled,
}

struct ExtractState {
    running: bool,
    processed: u64,
    total: u64,
    error: Option<String>,
    last: Option<ExtractReport>,
    rx: Option<Receiver<ExtractEvent>>,
    cancel: CancellationToken,
}

impl Default for ExtractState {
    fn default() -> Self {
        Self {
            running: false,
            processed: 0,
            total: 0,
            error: None,
            last: None,
            rx: None,
            cancel: CancellationToken::new(),
        }
    }
}

struct InspectState {
    path: Option<PathBuf>,
    inspection: Option<Inspection>,
    hashes: Option<Hashes>,
    error: Option<String>,
    processed: u64,
    total: u64,
    running: bool,
    rx: Option<Receiver<InspectEvent>>,
    cancel: CancellationToken,
    extract: ExtractState,
}

impl Default for InspectState {
    fn default() -> Self {
        Self {
            path: None,
            inspection: None,
            hashes: None,
            error: None,
            processed: 0,
            total: 0,
            running: false,
            rx: None,
            cancel: CancellationToken::new(),
            extract: ExtractState::default(),
        }
    }
}

enum WorkerEvent {
    Started {
        index: usize,
    },
    Progress {
        index: usize,
        processed: u64,
        total: u64,
    },
    Finished {
        index: usize,
        outcome: Box<JobOutcome>,
    },
    Failed {
        index: usize,
        message: String,
    },
    AllFinished {
        succeeded: usize,
        failed: usize,
        cancelled: bool,
    },
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    output_dir: Option<PathBuf>,
    options: ConvertOptions,
    pack_container: bool,
}

pub struct BinInatorApp {
    files: Vec<FileEntry>,
    output_dir: String,
    options: ConvertOptions,
    pack_container: bool,
    tab: Tab,
    inspect: InspectState,
    log: Vec<LogEntry>,
    run_state: RunState,
    cancel: CancellationToken,
    rx: Option<Receiver<WorkerEvent>>,
    current: Option<usize>,
    processed: u64,
    total: u64,
    succeeded: usize,
    failed: usize,
    hovering_files: bool,
}

impl BinInatorApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_theme(egui::Theme::Dark);
        cc.egui_ctx
            .set_visuals_of(egui::Theme::Dark, egui::Visuals::dark());
        cc.egui_ctx.style_mut_of(egui::Theme::Dark, |style| {
            style.spacing.item_spacing = egui::vec2(8.0, 8.0);
            style.spacing.button_padding = egui::vec2(10.0, 6.0);
            style.visuals.panel_fill = BG;
            style.visuals.window_fill = PANEL_BG;
            style.visuals.faint_bg_color = PANEL_BG;
            style.visuals.selection.bg_fill = ACCENT;
        });

        let settings = load_settings();
        let output_dir = settings
            .output_dir
            .or_else(default_output_dir)
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
            .display()
            .to_string();

        let mut app = Self {
            files: Vec::new(),
            output_dir,
            options: settings.options,
            pack_container: settings.pack_container,
            tab: Tab::Convert,
            inspect: InspectState::default(),
            log: Vec::new(),
            run_state: RunState::Idle,
            cancel: CancellationToken::new(),
            rx: None,
            current: None,
            processed: 0,
            total: 0,
            succeeded: 0,
            failed: 0,
            hovering_files: false,
        };
        app.log_info("Добавьте файлы и нажмите «Конвертировать».");
        app
    }

    fn log_info(&mut self, text: impl Into<String>) {
        self.push_log(LogLevel::Info, text);
    }

    fn log_ok(&mut self, text: impl Into<String>) {
        self.push_log(LogLevel::Ok, text);
    }

    fn log_error(&mut self, text: impl Into<String>) {
        self.push_log(LogLevel::Error, text);
    }

    fn push_log(&mut self, level: LogLevel, text: impl Into<String>) {
        self.log.push(LogEntry {
            level,
            text: text.into(),
        });
        if self.log.len() > 500 {
            self.log.remove(0);
        }
    }

    fn add_path(&mut self, path: PathBuf) {
        if fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
            self.add_folder(path);
            return;
        }

        if self.files.iter().any(|entry| entry.path == path) {
            self.log_info(format!("Уже в списке: {}", path.display()));
            return;
        }

        match detect(&path) {
            Ok(detected) => {
                self.log_info(format!(
                    "Добавлен: {} ({})",
                    path.display(),
                    kind_label(detected.kind)
                ));
                self.files.push(FileEntry { path, detected });
            }
            Err(error) => self.log_error(format!("{}: {error}", path.display())),
        }
    }

    fn add_folder(&mut self, folder: PathBuf) {
        let output_dir = PathBuf::from(self.output_dir.trim());
        let exclude = (!output_dir.as_os_str().is_empty()).then_some(output_dir.as_path());
        match collect_files_excluding(&folder, true, exclude) {
            Ok(files) if files.is_empty() => {
                self.log_info(format!("В папке нет файлов: {}", folder.display()));
            }
            Ok(files) => {
                let total = files.len();
                for file in files {
                    self.add_path(file);
                }
                self.log_ok(format!("Из папки добавлено файлов: {total}"));
            }
            Err(error) => self.log_error(format!("{}: {error}", folder.display())),
        }
    }

    fn pick_files(&mut self) {
        if let Some(paths) = rfd::FileDialog::new()
            .set_title("Выберите файлы для конвертации")
            .pick_files()
        {
            for path in paths {
                self.add_path(path);
            }
        }
    }

    fn pick_folder(&mut self) {
        if let Some(folder) = rfd::FileDialog::new()
            .set_title("Добавить папку для пакетной обработки")
            .pick_folder()
        {
            self.add_folder(folder);
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let (dropped, hovering) = ctx.input(|input| {
            (
                input.raw.dropped_files.clone(),
                !input.raw.hovered_files.is_empty(),
            )
        });
        self.hovering_files = hovering;

        for file in dropped {
            let path = file.path().to_path_buf();
            if self.tab == Tab::Inspect {
                self.start_inspect(path);
            } else {
                self.add_path(path);
            }
        }
    }

    fn poll_worker(&mut self, ctx: &egui::Context) {
        let Some(rx) = self.rx.take() else {
            return;
        };

        let mut finished = false;
        loop {
            match rx.try_recv() {
                Ok(WorkerEvent::Started { index }) => {
                    self.current = Some(index);
                    self.processed = 0;
                    self.total = self
                        .files
                        .get(index)
                        .map(|entry| entry.detected.size)
                        .unwrap_or(0);
                    if let Some(entry) = self.files.get(index) {
                        self.log_info(format!("Обработка: {}", entry.name()));
                    }
                }
                Ok(WorkerEvent::Progress {
                    index,
                    processed,
                    total,
                }) => {
                    if self.current == Some(index) {
                        self.processed = processed;
                        self.total = total;
                    }
                }
                Ok(WorkerEvent::Finished { index, outcome }) => {
                    let name = self
                        .files
                        .get(index)
                        .map(FileEntry::name)
                        .unwrap_or_else(|| format!("#{index}"));

                    match *outcome {
                        JobOutcome::Converted(report) => {
                            let parts = if report.outputs.len() == 1 {
                                String::new()
                            } else {
                                format!(", {} частей", report.outputs.len())
                            };
                            let hash = report.sha256.get(..16).unwrap_or(&report.sha256);
                            self.log_ok(format!(
                                "{name} → {}{parts} ({}, sha256 {hash}…, {:.2} с)",
                                report.primary_output().display(),
                                human_bytes(report.bytes),
                                report.elapsed.as_secs_f64()
                            ));
                        }
                        JobOutcome::Packed(report) => {
                            let hash = report.sha256.get(..16).unwrap_or(&report.sha256);
                            self.log_ok(format!(
                                "{name} → {} (контейнер, {}, sha256 {hash}…, {:.2} с)",
                                report.output.display(),
                                human_bytes(report.payload_bytes),
                                report.elapsed.as_secs_f64()
                            ));
                        }
                        JobOutcome::Unpacked(report) => {
                            let hash = report.sha256.get(..16).unwrap_or(&report.sha256);
                            self.log_ok(format!(
                                "{name} → {} (распаковано, {}, sha256 {hash}…)",
                                report.output.display(),
                                human_bytes(report.bytes)
                            ));
                        }
                    }
                }
                Ok(WorkerEvent::Failed { index, message }) => {
                    let name = self
                        .files
                        .get(index)
                        .map(FileEntry::name)
                        .unwrap_or_else(|| format!("#{index}"));
                    self.log_error(format!("{name}: {message}"));
                }
                Ok(WorkerEvent::AllFinished {
                    succeeded,
                    failed,
                    cancelled,
                }) => {
                    self.succeeded = succeeded;
                    self.failed = failed;
                    self.run_state = RunState::Idle;
                    self.current = None;
                    finished = true;

                    if cancelled {
                        self.log_info(format!("Отменено. Успешно: {succeeded}, ошибок: {failed}."));
                    } else if failed == 0 {
                        self.log_ok(format!("Готово: {succeeded} файл(ов)."));
                    } else {
                        self.log_error(format!(
                            "Завершено с ошибками: успешно {succeeded}, ошибок {failed}."
                        ));
                    }
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.run_state = RunState::Idle;
                    self.current = None;
                    self.log_error("Фоновый обработчик неожиданно завершился.");
                    finished = true;
                    break;
                }
            }
        }

        if !finished {
            self.rx = Some(rx);
        } else {
            ctx.request_repaint();
        }
    }

    fn start_inspect(&mut self, path: PathBuf) {
        if !path.is_file() {
            self.inspect.error = Some(format!("Не файл: {}", path.display()));
            self.log_error(format!("Инспектор: не файл {}", path.display()));
            return;
        }

        self.inspect.cancel.cancel();
        self.inspect.extract.cancel.cancel();
        self.inspect = InspectState::default();
        self.inspect.path = Some(path.clone());
        self.inspect.running = true;

        let cancel = CancellationToken::new();
        self.inspect.cancel = cancel.clone();
        let (tx, rx) = mpsc::channel();
        self.inspect.rx = Some(rx);
        self.log_info(format!("Инспекция: {}", path.display()));

        thread::spawn(move || {
            match inspect_file(&path) {
                Ok(inspection) => {
                    if tx.send(InspectEvent::Ready(Box::new(inspection))).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = tx.send(InspectEvent::Failed(error.to_string()));
                    return;
                }
            }

            match hash_file(&path, &cancel, |processed, total| {
                let _ = tx.send(InspectEvent::Progress { processed, total });
            }) {
                Ok(hashes) => {
                    let _ = tx.send(InspectEvent::Hashes(hashes));
                }
                Err(ConvertError::Cancelled) => {}
                Err(error) => {
                    let _ = tx.send(InspectEvent::Failed(error.to_string()));
                }
            }
        });
    }

    fn poll_inspect(&mut self, ctx: &egui::Context) {
        let Some(rx) = self.inspect.rx.take() else {
            return;
        };

        let mut finished = false;
        loop {
            match rx.try_recv() {
                Ok(InspectEvent::Ready(inspection)) => {
                    self.inspect.inspection = Some(*inspection);
                }
                Ok(InspectEvent::Hashes(hashes)) => {
                    self.inspect.hashes = Some(hashes);
                    self.inspect.running = false;
                    finished = true;
                }
                Ok(InspectEvent::Progress { processed, total }) => {
                    self.inspect.processed = processed;
                    self.inspect.total = total;
                }
                Ok(InspectEvent::Failed(message)) => {
                    self.inspect.error = Some(message.clone());
                    self.inspect.running = false;
                    self.log_error(format!("Инспектор: {message}"));
                    finished = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.inspect.running {
                        self.inspect.running = false;
                    }
                    finished = true;
                    break;
                }
            }
        }

        if !finished {
            self.inspect.rx = Some(rx);
        } else {
            ctx.request_repaint();
        }
    }

    fn start_extract(&mut self, input: PathBuf, output_dir: PathBuf) {
        if self.inspect.extract.running {
            return;
        }

        let cancel = CancellationToken::new();
        let (tx, rx) = mpsc::channel();
        self.inspect.extract = ExtractState {
            running: true,
            cancel: cancel.clone(),
            rx: Some(rx),
            ..ExtractState::default()
        };
        self.log_info(format!(
            "Извлечение секций: {} -> {}",
            input.display(),
            output_dir.display()
        ));

        let overwrite = self.options.overwrite;
        thread::spawn(move || {
            match extract_sections(
                &input,
                &output_dir,
                None,
                overwrite,
                &cancel,
                |processed, total| {
                    let _ = tx.send(ExtractEvent::Progress { processed, total });
                },
            ) {
                Ok(report) => {
                    let _ = tx.send(ExtractEvent::Finished(Box::new(report)));
                }
                Err(ConvertError::Cancelled) => {
                    let _ = tx.send(ExtractEvent::Cancelled);
                }
                Err(error) => {
                    let _ = tx.send(ExtractEvent::Failed(error.to_string()));
                }
            }
        });
    }

    fn poll_extract(&mut self, ctx: &egui::Context) {
        let Some(rx) = self.inspect.extract.rx.take() else {
            return;
        };

        let mut finished = false;
        loop {
            match rx.try_recv() {
                Ok(ExtractEvent::Progress { processed, total }) => {
                    self.inspect.extract.processed = processed;
                    self.inspect.extract.total = total;
                }
                Ok(ExtractEvent::Finished(report)) => {
                    self.inspect.extract.running = false;
                    self.log_ok(format!(
                        "Извлечено секций: {} ({})",
                        report.outputs.len(),
                        human_bytes(report.total_bytes)
                    ));
                    for section in &report.outputs {
                        self.log_info(format!(
                            "{} → {} ({} байт)",
                            section.name, section.output, section.bytes
                        ));
                    }
                    self.inspect.extract.last = Some(*report);
                    finished = true;
                }
                Ok(ExtractEvent::Failed(message)) => {
                    self.inspect.extract.error = Some(message.clone());
                    self.inspect.extract.running = false;
                    self.log_error(format!("Извлечение: {message}"));
                    finished = true;
                }
                Ok(ExtractEvent::Cancelled) => {
                    self.inspect.extract.running = false;
                    self.log_info("Извлечение отменено");
                    finished = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.inspect.extract.running = false;
                    finished = true;
                    break;
                }
            }
        }

        if !finished {
            self.inspect.extract.rx = Some(rx);
        } else {
            ctx.request_repaint();
        }
    }

    fn start_job(&mut self, kind: JobKind) {
        if self.run_state == RunState::Running {
            return;
        }

        let jobs: Vec<(usize, PathBuf)> = self
            .files
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                kind != JobKind::Unpack || entry.detected.kind == InputKind::Container
            })
            .map(|(index, entry)| (index, entry.path.clone()))
            .collect();

        if jobs.is_empty() {
            if kind == JobKind::Unpack {
                self.log_error("В списке нет контейнеров BINATOR1.");
            } else {
                self.log_error("Добавьте файлы для обработки.");
            }
            return;
        }

        let output_dir = PathBuf::from(self.output_dir.trim());
        if output_dir.as_os_str().is_empty() {
            self.log_error("Укажите папку назначения.");
            return;
        }

        let options = self.options.clone();
        let pack = self.pack_container;
        self.save_settings();

        self.run_state = RunState::Running;
        self.cancel = CancellationToken::new();
        let cancel = self.cancel.clone();
        self.current = None;
        self.processed = 0;
        self.total = 0;
        self.succeeded = 0;
        self.failed = 0;

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);

        let action = match kind {
            JobKind::Convert if pack => "Упаковка",
            JobKind::Convert => "Конвертация",
            JobKind::Unpack => "Распаковка",
        };
        self.log_info(format!(
            "{action}: {} файл(ов) → {}",
            jobs.len(),
            output_dir.display()
        ));

        thread::spawn(move || {
            let mut succeeded = 0_usize;
            let mut failed = 0_usize;

            for (index, path) in jobs {
                if cancel.is_cancelled() {
                    break;
                }
                if tx.send(WorkerEvent::Started { index }).is_err() {
                    return;
                }

                let result: Result<JobOutcome, ConvertError> = match kind {
                    JobKind::Convert if pack => {
                        let target = pack_target(&path, &output_dir);
                        pack_container(&path, &target, options.overwrite, None, &cancel, |p, t| {
                            let _ = tx.send(WorkerEvent::Progress {
                                index,
                                processed: p,
                                total: t,
                            });
                        })
                        .map(JobOutcome::Packed)
                    }
                    JobKind::Convert => {
                        convert_file(&path, &output_dir, &options, &cancel, |p, t| {
                            let _ = tx.send(WorkerEvent::Progress {
                                index,
                                processed: p,
                                total: t,
                            });
                        })
                        .map(JobOutcome::Converted)
                    }
                    JobKind::Unpack => {
                        unpack_container(&path, &output_dir, options.overwrite, &cancel, |p, t| {
                            let _ = tx.send(WorkerEvent::Progress {
                                index,
                                processed: p,
                                total: t,
                            });
                        })
                        .map(JobOutcome::Unpacked)
                    }
                };

                match result {
                    Ok(outcome) => {
                        succeeded += 1;
                        if tx
                            .send(WorkerEvent::Finished {
                                index,
                                outcome: Box::new(outcome),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(ConvertError::Cancelled) => break,
                    Err(error) => {
                        failed += 1;
                        if tx
                            .send(WorkerEvent::Failed {
                                index,
                                message: error.to_string(),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }

            let _ = tx.send(WorkerEvent::AllFinished {
                succeeded,
                failed,
                cancelled: cancel.is_cancelled(),
            });
        });
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("top_bar").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("bin-inator").size(26.0).strong());
                ui.label(RichText::new("всё в .bin").color(MUTED).size(14.0));
                ui.add_space(12.0);
                if ui
                    .selectable_label(self.tab == Tab::Convert, "Конвертация")
                    .clicked()
                {
                    self.tab = Tab::Convert;
                }
                if ui
                    .selectable_label(self.tab == Tab::Inspect, "Инспектор")
                    .clicked()
                {
                    self.tab = Tab::Inspect;
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(env!("CARGO_PKG_VERSION"))
                            .color(MUTED)
                            .small(),
                    );
                    let (text, color) = if self.inspect.running {
                        ("● Инспекция", WARN)
                    } else if self.run_state == RunState::Running {
                        ("● Конвертация", WARN)
                    } else {
                        ("● Готово", OK)
                    };
                    ui.label(RichText::new(text).color(color));
                    ui.label(RichText::new("RAW").color(ACCENT).small());
                });
            });
            ui.add_space(6.0);
        });
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        egui::Panel::right("settings_panel")
            .resizable(false)
            .default_size(360.0)
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.heading("Параметры");
                ui.separator();

                ui.label("Папка назначения");
                let width = ui.available_width();
                ui.add_sized(
                    [width, 24.0],
                    egui::TextEdit::singleline(&mut self.output_dir)
                        .hint_text("Куда сохранять .bin"),
                );
                if ui
                    .add_sized([width, 28.0], egui::Button::new("Выбрать папку…"))
                    .clicked()
                    && let Some(dir) = rfd::FileDialog::new()
                        .set_title("Папка назначения")
                        .pick_folder()
                {
                    self.output_dir = dir.display().to_string();
                }

                ui.add_space(8.0);
                egui::ComboBox::from_label("При совпадении")
                    .selected_text(overwrite_label(self.options.overwrite))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.options.overwrite,
                            Overwrite::Error,
                            overwrite_label(Overwrite::Error),
                        );
                        ui.selectable_value(
                            &mut self.options.overwrite,
                            Overwrite::Suffix,
                            overwrite_label(Overwrite::Suffix),
                        );
                        ui.selectable_value(
                            &mut self.options.overwrite,
                            Overwrite::Replace,
                            overwrite_label(Overwrite::Replace),
                        );
                    });
                ui.checkbox(
                    &mut self.options.sidecar,
                    "JSON-сайдкар с параметрами и хэшами",
                );
                ui.checkbox(
                    &mut self.pack_container,
                    "Упаковывать в контейнер BINATOR1 (.binator)",
                );
                if self.pack_container {
                    ui.label(
                        RichText::new(
                            "Байты сохраняются без изменений; преобразования ниже не применяются.",
                        )
                        .small()
                        .color(MUTED),
                    );
                }

                ui.add_space(8.0);
                ui.separator();
                ui.label(RichText::new("Преобразования").strong());
                ui.label(
                    RichText::new("Применяются ко всем файлам в очереди")
                        .small()
                        .color(MUTED),
                );

                egui::ScrollArea::vertical()
                    .max_height(280.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.transform_controls(ui));

                ui.add_space(6.0);
                ui.separator();
                self.action_buttons(ui);
                ui.add_space(10.0);
                self.progress_ui(ui);
            });
    }

    fn transform_controls(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Текст")
            .default_open(false)
            .show(ui, |ui| {
                egui::ComboBox::from_id_salt("text_output")
                    .selected_text(text_output_label(self.options.text.output_encoding))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.options.text.output_encoding,
                            None,
                            "Как есть (копия)",
                        );
                        ui.selectable_value(
                            &mut self.options.text.output_encoding,
                            Some(TextEncoding::Utf8),
                            "UTF-8",
                        );
                        ui.selectable_value(
                            &mut self.options.text.output_encoding,
                            Some(TextEncoding::Utf16Le),
                            "UTF-16 LE",
                        );
                        ui.selectable_value(
                            &mut self.options.text.output_encoding,
                            Some(TextEncoding::Utf16Be),
                            "UTF-16 BE",
                        );
                        ui.selectable_value(
                            &mut self.options.text.output_encoding,
                            Some(TextEncoding::Windows1251),
                            "Windows-1251",
                        );
                        ui.selectable_value(
                            &mut self.options.text.output_encoding,
                            Some(TextEncoding::Ascii),
                            "ASCII",
                        );
                    });

                ui.add_enabled_ui(self.options.text.output_encoding.is_some(), |ui| {
                    egui::ComboBox::from_id_salt("text_input")
                        .selected_text(text_input_label(self.options.text.input_encoding))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.options.text.input_encoding,
                                TextInputEncoding::Auto,
                                "Авто",
                            );
                            ui.selectable_value(
                                &mut self.options.text.input_encoding,
                                TextInputEncoding::Utf8,
                                "UTF-8",
                            );
                            ui.selectable_value(
                                &mut self.options.text.input_encoding,
                                TextInputEncoding::Utf16Le,
                                "UTF-16 LE",
                            );
                            ui.selectable_value(
                                &mut self.options.text.input_encoding,
                                TextInputEncoding::Utf16Be,
                                "UTF-16 BE",
                            );
                            ui.selectable_value(
                                &mut self.options.text.input_encoding,
                                TextInputEncoding::Windows1251,
                                "Windows-1251",
                            );
                            ui.selectable_value(
                                &mut self.options.text.input_encoding,
                                TextInputEncoding::Ascii,
                                "ASCII",
                            );
                        });
                    ui.checkbox(&mut self.options.text.bom, "Добавить BOM");
                    egui::ComboBox::from_id_salt("line_endings")
                        .selected_text(line_endings_label(self.options.text.line_endings))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.options.text.line_endings,
                                LineEndings::Preserve,
                                "Переводы строк: как есть",
                            );
                            ui.selectable_value(
                                &mut self.options.text.line_endings,
                                LineEndings::Lf,
                                "Переводы строк: LF",
                            );
                            ui.selectable_value(
                                &mut self.options.text.line_endings,
                                LineEndings::Crlf,
                                "Переводы строк: CRLF",
                            );
                        });
                });
            });

        egui::CollapsingHeader::new("Изображения")
            .default_open(false)
            .show(ui, |ui| {
                egui::ComboBox::from_id_salt("image_mode")
                    .selected_text(image_mode_label(self.options.image.mode))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.options.image.mode,
                            ImageMode::Bytes,
                            "Байты исходного файла",
                        );
                        ui.selectable_value(
                            &mut self.options.image.mode,
                            ImageMode::Pixels,
                            "Сырые пиксели",
                        );
                    });

                if self.options.image.mode == ImageMode::Pixels {
                    egui::ComboBox::from_id_salt("pixel_format")
                        .selected_text(pixel_format_label(self.options.image.format))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.options.image.format,
                                PixelFormat::Rgb8,
                                "RGB8 (3 байта)",
                            );
                            ui.selectable_value(
                                &mut self.options.image.format,
                                PixelFormat::Rgba8,
                                "RGBA8 (4 байта)",
                            );
                            ui.selectable_value(
                                &mut self.options.image.format,
                                PixelFormat::Luma8,
                                "Grayscale 8 (1 байт)",
                            );
                        });
                    ui.label(
                        RichText::new("Размеры и формат пикселей — в JSON-сайдкаре.")
                            .small()
                            .color(MUTED),
                    );
                }
            });

        egui::CollapsingHeader::new("Двоичные данные")
            .default_open(false)
            .show(ui, |ui| {
                egui::ComboBox::from_id_salt("split_size")
                    .selected_text(split_label(self.options.raw.split_size))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.options.raw.split_size, None, "Не разбивать");
                        ui.selectable_value(
                            &mut self.options.raw.split_size,
                            Some(64 * 1024),
                            "64 КиБ",
                        );
                        ui.selectable_value(
                            &mut self.options.raw.split_size,
                            Some(1024 * 1024),
                            "1 МиБ",
                        );
                        ui.selectable_value(
                            &mut self.options.raw.split_size,
                            Some(4 * 1024 * 1024),
                            "4 МиБ",
                        );
                        ui.selectable_value(
                            &mut self.options.raw.split_size,
                            Some(16 * 1024 * 1024),
                            "16 МиБ",
                        );
                    });

                let mut pad_enabled = self.options.raw.pad_to.is_some();
                if ui
                    .checkbox(&mut pad_enabled, "Добивать до кратности")
                    .changed()
                {
                    self.options.raw.pad_to = pad_enabled.then_some(4096);
                }
                if let Some(pad_to) = &mut self.options.raw.pad_to {
                    ui.add(
                        egui::DragValue::new(pad_to)
                            .range(2..=1_073_741_824)
                            .speed(64)
                            .suffix(" Б"),
                    );
                    egui::ComboBox::from_id_salt("pad_byte")
                        .selected_text(pad_byte_label(self.options.raw.pad_byte))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.options.raw.pad_byte,
                                PadByte::Zero,
                                "Заполнять 0x00",
                            );
                            ui.selectable_value(
                                &mut self.options.raw.pad_byte,
                                PadByte::Ones,
                                "Заполнять 0xFF",
                            );
                        });
                }

                ui.checkbox(
                    &mut self.options.raw.trim_trailing_zeros,
                    "Обрезать нули в конце",
                );
                egui::ComboBox::from_id_salt("swap")
                    .selected_text(byte_swap_label(self.options.raw.swap))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.options.raw.swap,
                            ByteSwap::None,
                            "Порядок байт: не менять",
                        );
                        ui.selectable_value(
                            &mut self.options.raw.swap,
                            ByteSwap::Swap16,
                            "Swap 16",
                        );
                        ui.selectable_value(
                            &mut self.options.raw.swap,
                            ByteSwap::Swap32,
                            "Swap 32",
                        );
                    });
                ui.checkbox(&mut self.options.raw.bit_reverse, "Инвертировать биты");
            });
    }

    fn action_buttons(&mut self, ui: &mut egui::Ui) {
        let running = self.run_state == RunState::Running;
        let can_start = !self.files.is_empty() && !self.output_dir.trim().is_empty();
        let has_containers = self
            .files
            .iter()
            .any(|entry| entry.detected.kind == InputKind::Container);
        let primary = if self.pack_container {
            "Упаковать"
        } else {
            "Конвертировать"
        };

        ui.horizontal_wrapped(|ui| {
            if running {
                if ui
                    .add_sized([150.0, 36.0], egui::Button::new("Отмена"))
                    .clicked()
                {
                    self.cancel.cancel();
                    self.log_info("Запрошена отмена…");
                }
            } else if ui
                .add_enabled(
                    can_start,
                    egui::Button::new(primary).min_size(egui::vec2(150.0, 36.0)),
                )
                .clicked()
            {
                self.start_job(JobKind::Convert);
            }

            if ui
                .add_enabled(
                    !running && has_containers && !self.output_dir.trim().is_empty(),
                    egui::Button::new("Распаковать контейнеры"),
                )
                .clicked()
            {
                self.start_job(JobKind::Unpack);
            }

            if ui
                .add_enabled(
                    !running && !self.files.is_empty(),
                    egui::Button::new("Очистить"),
                )
                .clicked()
            {
                self.files.clear();
                self.current = None;
                self.processed = 0;
                self.total = 0;
            }
        });
    }

    fn progress_ui(&mut self, ui: &mut egui::Ui) {
        ui.label("Прогресс");
        let fraction = if self.total > 0 {
            (self.processed as f32 / self.total as f32).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let progress_text = if self.total > 0 {
            format!(
                "{} / {}",
                human_bytes(self.processed),
                human_bytes(self.total)
            )
        } else {
            "—".to_owned()
        };

        ui.add(
            egui::ProgressBar::new(fraction)
                .show_percentage()
                .text(progress_text)
                .desired_width(ui.available_width()),
        );

        if let Some(index) = self.current
            && let Some(entry) = self.files.get(index)
        {
            ui.label(
                RichText::new(format!(
                    "Файл {} из {}: {}",
                    index + 1,
                    self.files.len(),
                    entry.name()
                ))
                .small()
                .color(MUTED),
            );
        }

        if self.succeeded > 0 || self.failed > 0 {
            ui.label(
                RichText::new(format!(
                    "Успешно: {} · ошибок: {}",
                    self.succeeded, self.failed
                ))
                .small()
                .color(MUTED),
            );
        }
    }

    fn files_panel(&mut self, ui: &mut egui::Ui) {
        let total_bytes: u64 = self.files.iter().map(|entry| entry.detected.size).sum();

        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading("Файлы");
                ui.label(
                    RichText::new(format!(
                        "{} · {}",
                        self.files.len(),
                        human_bytes(total_bytes)
                    ))
                    .color(MUTED),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let running = self.run_state == RunState::Running;
                    if ui
                        .add_enabled(!running, egui::Button::new("Добавить файлы"))
                        .clicked()
                    {
                        self.pick_files();
                    }
                    if ui
                        .add_enabled(!running, egui::Button::new("Добавить папку"))
                        .clicked()
                    {
                        self.pick_folder();
                    }
                    if ui
                        .add_enabled(
                            !running && !self.files.is_empty(),
                            egui::Button::new("Очистить список"),
                        )
                        .clicked()
                    {
                        self.files.clear();
                        self.current = None;
                        self.processed = 0;
                        self.total = 0;
                    }
                });
            });
            ui.separator();

            if self.files.is_empty() {
                self.empty_state(ui);
            } else {
                self.file_list(ui);
            }
        });
    }

    fn empty_state(&mut self, ui: &mut egui::Ui) {
        let border = if self.hovering_files {
            ACCENT
        } else {
            Color32::from_rgb(58, 64, 78)
        };
        let stroke_width = if self.hovering_files { 2.0 } else { 1.0 };

        ui.add_space(24.0);
        egui::Frame::default()
            .stroke(egui::Stroke::new(stroke_width, border))
            .corner_radius(14.0)
            .inner_margin(32.0)
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    let title = if self.hovering_files {
                        "Отпустите файлы"
                    } else {
                        "Перетащите файлы сюда"
                    };
                    ui.label(RichText::new(title).size(22.0).strong());
                    ui.label(
                        RichText::new(
                            "Картинки, текст, исполняемые файлы, дампы, образы дисков — что угодно",
                        )
                        .color(MUTED),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(
                                egui::Button::new("Выбрать файлы…")
                                    .min_size(egui::vec2(170.0, 34.0)),
                            )
                            .clicked()
                        {
                            self.pick_files();
                        }
                        if ui
                            .add(
                                egui::Button::new("Добавить папку…")
                                    .min_size(egui::vec2(170.0, 34.0)),
                            )
                            .clicked()
                        {
                            self.pick_folder();
                        }
                    });
                    ui.add_space(20.0);
                });
            });
    }

    fn file_list(&mut self, ui: &mut egui::Ui) {
        let split = self.options.raw.split_size.is_some();

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let mut remove = None;
                let row_width = ui.available_width();

                for (index, entry) in self.files.iter().enumerate() {
                    let fill = if self.current == Some(index) {
                        Color32::from_rgb(29, 44, 72)
                    } else {
                        PANEL_BG
                    };

                    egui::Frame::group(ui.style()).fill(fill).show(ui, |ui| {
                        ui.set_min_width((row_width - 24.0).max(120.0));
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.strong(entry.name());
                                ui.label(
                                    RichText::new(format!(
                                        "{} · {}",
                                        kind_label(entry.detected.kind),
                                        human_bytes(entry.detected.size)
                                    ))
                                    .small()
                                    .color(MUTED),
                                );
                                let preview = if entry.detected.kind == InputKind::Container {
                                    "распаковка по имени из метаданных".to_owned()
                                } else if self.pack_container {
                                    pack_file_name(&entry.path).display().to_string()
                                } else {
                                    preview_output_name(&entry.path, split)
                                        .display()
                                        .to_string()
                                };
                                ui.label(
                                    RichText::new(format!(
                                        "{}  →  {}",
                                        entry.path.display(),
                                        preview
                                    ))
                                    .small()
                                    .color(Color32::from_rgb(105, 113, 130)),
                                );
                            });

                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .add_enabled(
                                        self.run_state != RunState::Running,
                                        egui::Button::new("Удалить"),
                                    )
                                    .clicked()
                                {
                                    remove = Some(index);
                                }
                                if let Some(mime) = &entry.detected.mime {
                                    ui.label(RichText::new(mime).small().color(MUTED));
                                }
                            });
                        });
                    });
                    ui.add_space(6.0);
                }

                if let Some(index) = remove {
                    self.files.remove(index);
                }
            });
    }

    fn inspect_panel(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading("Инспектор");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Выбрать файл…").clicked()
                        && let Some(path) = rfd::FileDialog::new()
                            .set_title("Файл для инспекции")
                            .pick_file()
                    {
                        self.start_inspect(path);
                    }

                    if self.inspect.running {
                        if ui.button("Отмена").clicked() {
                            self.inspect.cancel.cancel();
                        }
                    } else if self.inspect.path.is_some()
                        && ui.button("Пересчитать").clicked()
                        && let Some(path) = self.inspect.path.clone()
                    {
                        self.start_inspect(path);
                    }
                });
            });
            ui.separator();

            if let Some(path) = &self.inspect.path {
                ui.add(
                    egui::Label::new(RichText::new(path.display().to_string()).monospace())
                        .selectable(true),
                );
            }

            if let Some(error) = &self.inspect.error {
                ui.label(RichText::new(error).color(ERROR));
            }

            if self.inspect.running {
                let fraction = if self.inspect.total > 0 {
                    (self.inspect.processed as f32 / self.inspect.total as f32).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                ui.add(
                    egui::ProgressBar::new(fraction)
                        .show_percentage()
                        .text(format!(
                            "{} / {}",
                            human_bytes(self.inspect.processed),
                            human_bytes(self.inspect.total)
                        ))
                        .desired_width(ui.available_width()),
                );
            }

            let has_executable = self
                .inspect
                .inspection
                .as_ref()
                .is_some_and(|inspection| inspection.executable.is_some());

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if self.inspect.extract.running {
                    if ui.button("Отмена извлечения").clicked() {
                        self.inspect.extract.cancel.cancel();
                    }
                    let fraction = if self.inspect.extract.total > 0 {
                        (self.inspect.extract.processed as f32 / self.inspect.extract.total as f32)
                            .clamp(0.0, 1.0)
                    } else {
                        0.0
                    };
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .show_percentage()
                            .text(format!(
                                "{} / {}",
                                human_bytes(self.inspect.extract.processed),
                                human_bytes(self.inspect.extract.total)
                            ))
                            .desired_width(280.0),
                    );
                } else if has_executable && ui.button("Извлечь секции…").clicked() {
                    let input = self.inspect.path.clone();
                    if let Some(input) = input {
                        let mut dialog =
                            rfd::FileDialog::new().set_title("Папка для извлечённых секций");
                        if let Some(parent) = input.parent() {
                            dialog = dialog.set_directory(parent);
                        }
                        if let Some(output_dir) = dialog.pick_folder() {
                            self.start_extract(input, output_dir);
                        }
                    }
                }
            });

            if let Some(error) = &self.inspect.extract.error {
                ui.label(RichText::new(error).color(ERROR));
            }

            if let Some(report) = &self.inspect.extract.last {
                ui.label(
                    RichText::new(format!(
                        "Извлечено секций: {} · {} → {}",
                        report.outputs.len(),
                        human_bytes(report.total_bytes),
                        report.output_dir
                    ))
                    .color(OK),
                );
            }

            let Some(inspection) = &self.inspect.inspection else {
                if self.inspect.path.is_none() {
                    self.inspect_empty(ui);
                }
                return;
            };

            let hashes = self.inspect.hashes.as_ref();
            let running = self.inspect.running;
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| render_inspection(ui, inspection, hashes, running));
        });
    }

    fn inspect_empty(&mut self, ui: &mut egui::Ui) {
        let border = if self.hovering_files {
            ACCENT
        } else {
            Color32::from_rgb(58, 64, 78)
        };
        let stroke_width = if self.hovering_files { 2.0 } else { 1.0 };

        ui.add_space(24.0);
        egui::Frame::default()
            .stroke(egui::Stroke::new(stroke_width, border))
            .corner_radius(14.0)
            .inner_margin(32.0)
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    let title = if self.hovering_files {
                        "Отпустите файл"
                    } else {
                        "Перетащите файл сюда"
                    };
                    ui.label(RichText::new(title).size(22.0).strong());
                    ui.label(
                        RichText::new(
                            "Тип, заголовки PE/ELF, секции, текст, изображение, контейнер и хэши",
                        )
                        .color(MUTED),
                    );
                    ui.add_space(12.0);
                    if ui
                        .add(egui::Button::new("Выбрать файл…").min_size(egui::vec2(180.0, 34.0)))
                        .clicked()
                        && let Some(path) = rfd::FileDialog::new()
                            .set_title("Файл для инспекции")
                            .pick_file()
                    {
                        self.start_inspect(path);
                    }
                    ui.add_space(20.0);
                });
            });
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("log_panel")
            .resizable(true)
            .default_size(160.0)
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.strong("Журнал");
                    if ui.small_button("Очистить").clicked() {
                        self.log.clear();
                    }
                });
                ui.separator();

                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.log.is_empty() {
                            ui.label(RichText::new("Пока пусто.").color(MUTED));
                        }
                        for entry in &self.log {
                            let color = match entry.level {
                                LogLevel::Info => MUTED,
                                LogLevel::Ok => OK,
                                LogLevel::Error => ERROR,
                            };
                            ui.label(
                                RichText::new(&entry.text)
                                    .monospace()
                                    .size(12.0)
                                    .color(color),
                            );
                        }
                    });
            });
    }

    fn save_settings(&self) {
        let Some(path) = settings_path() else {
            return;
        };
        if let Some(parent) = path.parent()
            && fs::create_dir_all(parent).is_err()
        {
            return;
        }

        let output_dir = PathBuf::from(self.output_dir.trim());
        let settings = Settings {
            output_dir: (!output_dir.as_os_str().is_empty()).then_some(output_dir),
            options: self.options.clone(),
            pack_container: self.pack_container,
        };

        if let Ok(json) = serde_json::to_string_pretty(&settings) {
            let _ = fs::write(path, json);
        }
    }
}

impl eframe::App for BinInatorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_worker(ui.ctx());
        self.poll_inspect(ui.ctx());
        self.poll_extract(ui.ctx());
        self.handle_dropped_files(ui.ctx());

        self.top_bar(ui);
        self.log_panel(ui);

        match self.tab {
            Tab::Convert => {
                self.settings_panel(ui);
                self.files_panel(ui);
            }
            Tab::Inspect => self.inspect_panel(ui),
        }

        if self.run_state == RunState::Running
            || self.inspect.running
            || self.inspect.extract.running
        {
            ui.ctx().request_repaint_after(Duration::from_millis(50));
        }
    }
}

impl Drop for BinInatorApp {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.inspect.cancel.cancel();
        self.inspect.extract.cancel.cancel();
        self.save_settings();
    }
}

fn render_inspection(
    ui: &mut egui::Ui,
    inspection: &Inspection,
    hashes: Option<&Hashes>,
    running: bool,
) {
    egui::Grid::new("inspection_summary")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            kv_text(ui, "Тип", kind_str_label(inspection.kind));
            kv_text(ui, "Размер", &human_bytes(inspection.size));
            if let Some(mime) = &inspection.mime {
                kv_text(ui, "MIME", mime);
            }
            if let Some(extension) = &inspection.magic_extension {
                kv_text(ui, "Magic", extension);
            }
        });

    if let Some(text) = &inspection.text {
        section_heading(ui, "Текст");
        egui::Grid::new("inspection_text")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                kv_text(ui, "Кодировка", &text.encoding);
                if let Some(bom) = &text.bom {
                    kv_text(ui, "BOM", bom);
                }
                kv_text(ui, "ASCII", if text.ascii { "да" } else { "нет" });
                kv_text(ui, "UTF-8", if text.utf8 { "да" } else { "нет" });
                kv_text(ui, "NUL", if text.has_nul { "есть" } else { "нет" });
                kv_text(ui, "Переводы строк", &text.line_endings);
            });
    }

    if let Some(image) = &inspection.image {
        section_heading(ui, "Изображение");
        egui::Grid::new("inspection_image")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                kv_text(ui, "Размер", &format!("{} × {}", image.width, image.height));
                kv_text(ui, "Формат", &image.format);
                kv_text(ui, "MIME", &image.mime);
            });
    }

    if let Some(executable) = &inspection.executable {
        section_heading(ui, "Исполняемый файл");
        egui::Grid::new("inspection_executable")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                kv_text(ui, "Формат", &executable.format);
                kv_text(ui, "Машина", &executable.machine);
                kv_text(ui, "Разрядность", &format!("{} бит", executable.bits));
                kv_text(
                    ui,
                    "Entry point",
                    &format!("0x{:x}", executable.entry_point),
                );
                kv_text(ui, "Image base", &format!("0x{:x}", executable.image_base));
            });

        if !executable.sections.is_empty() {
            egui::CollapsingHeader::new(format!("Секции ({})", executable.sections.len()))
                .default_open(true)
                .show(ui, |ui| {
                    egui::ScrollArea::horizontal().show(ui, |ui| {
                        egui::Grid::new("inspection_sections")
                            .num_columns(5)
                            .spacing([14.0, 4.0])
                            .show(ui, |ui| {
                                for header in ["Имя", "Offset", "Size", "Vaddr", "Flags"] {
                                    ui.label(RichText::new(header).strong());
                                }
                                ui.end_row();

                                for section in &executable.sections {
                                    let name = if section.name.is_empty() {
                                        "(без имени)"
                                    } else {
                                        &section.name
                                    };
                                    ui.label(RichText::new(name).monospace());
                                    ui.label(
                                        RichText::new(format!("0x{:x}", section.offset))
                                            .monospace(),
                                    );
                                    ui.label(
                                        RichText::new(format!("0x{:x}", section.size)).monospace(),
                                    );
                                    ui.label(
                                        RichText::new(format!("0x{:x}", section.virtual_address))
                                            .monospace(),
                                    );
                                    ui.label(RichText::new(&section.flags).monospace());
                                    ui.end_row();
                                }
                            });
                    });
                });
        }
    }

    if let Some(container) = &inspection.container {
        section_heading(ui, "Контейнер BINATOR1");
        egui::Grid::new("inspection_container")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                kv_text(ui, "Версия", &crate::core::CONTAINER_VERSION.to_string());
                kv_text(ui, "Payload", &human_bytes(container.payload_len));
                kv_text(ui, "Исходное имя", &container.metadata.source_name);
                kv_text(
                    ui,
                    "Исходный размер",
                    &human_bytes(container.metadata.source_size),
                );
                if let Some(note) = &container.metadata.note {
                    kv_text(ui, "Заметка", note);
                }
            });
    }

    section_heading(ui, "Хэши");
    if let Some(hashes) = hashes {
        egui::Grid::new("inspection_hashes")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label(RichText::new("SHA-256").color(MUTED));
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(RichText::new(&hashes.sha256).monospace().size(12.0))
                            .selectable(true),
                    );
                    if ui.small_button("Копировать").clicked() {
                        ui.ctx().copy_text(hashes.sha256.clone());
                    }
                });
                ui.end_row();

                ui.label(RichText::new("CRC32").color(MUTED));
                ui.label(RichText::new(format!("{:08x}", hashes.crc32)).monospace());
                ui.end_row();
            });
    } else {
        let text = if running {
            "Считаются…"
        } else {
            "Не рассчитаны"
        };
        ui.label(RichText::new(text).color(MUTED));
    }

    if !inspection.head_hex.is_empty() {
        egui::CollapsingHeader::new("Первые байты")
            .default_open(false)
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(format_hex_dump(&inspection.head_hex))
                            .monospace()
                            .size(12.0),
                    )
                    .selectable(true),
                );
            });
    }
}

fn kv_text(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.label(RichText::new(key).color(MUTED));
    ui.add(egui::Label::new(value).selectable(true));
    ui.end_row();
}

fn section_heading(ui: &mut egui::Ui, text: &str) {
    ui.add_space(10.0);
    ui.separator();
    ui.label(RichText::new(text).strong());
}

fn format_hex_dump(hex: &str) -> String {
    let mut output = String::new();
    for (line, chunk) in hex.as_bytes().chunks(32).enumerate() {
        output.push_str(&format!("{:08x}  ", line * 16));
        for pair in chunk.chunks(2) {
            if let Ok(text) = std::str::from_utf8(pair) {
                output.push_str(text);
            } else {
                output.push_str("??");
            }
            output.push(' ');
        }
        output.push('\n');
    }
    output
}

fn kind_str_label(kind: &str) -> &'static str {
    match kind {
        "text" => "Текст",
        "image" => "Изображение",
        "executable" => "Исполняемый файл",
        "disk_image" => "Образ диска",
        "container" => "Контейнер BINATOR1",
        "binary" => "Бинарные данные",
        _ => "Неизвестно",
    }
}

fn pack_file_name(source: &Path) -> PathBuf {
    let mut name = source
        .file_stem()
        .filter(|stem| !stem.is_empty())
        .map(|stem| stem.to_os_string())
        .unwrap_or_else(|| OsString::from("output"));
    name.push(".binator");
    PathBuf::from(name)
}

fn pack_target(source: &Path, output_dir: &Path) -> PathBuf {
    output_dir.join(pack_file_name(source))
}

fn kind_label(kind: InputKind) -> &'static str {
    match kind {
        InputKind::Text => "Текст",
        InputKind::Image => "Изображение",
        InputKind::Executable => "Исполняемый файл",
        InputKind::DiskImage => "Образ диска",
        InputKind::Container => "Контейнер BINATOR1",
        InputKind::Binary => "Бинарные данные",
        InputKind::Unknown => "Неизвестно",
    }
}

fn overwrite_label(overwrite: Overwrite) -> &'static str {
    match overwrite {
        Overwrite::Error => "Не перезаписывать",
        Overwrite::Suffix => "Добавить суффикс",
        Overwrite::Replace => "Перезаписать",
    }
}

fn text_output_label(encoding: Option<TextEncoding>) -> &'static str {
    match encoding {
        None => "Текст: как есть (копия)",
        Some(TextEncoding::Utf8) => "Текст: UTF-8",
        Some(TextEncoding::Utf16Le) => "Текст: UTF-16 LE",
        Some(TextEncoding::Utf16Be) => "Текст: UTF-16 BE",
        Some(TextEncoding::Windows1251) => "Текст: Windows-1251",
        Some(TextEncoding::Ascii) => "Текст: ASCII",
    }
}

fn text_input_label(encoding: TextInputEncoding) -> &'static str {
    match encoding {
        TextInputEncoding::Auto => "Вход: авто",
        TextInputEncoding::Utf8 => "Вход: UTF-8",
        TextInputEncoding::Utf16Le => "Вход: UTF-16 LE",
        TextInputEncoding::Utf16Be => "Вход: UTF-16 BE",
        TextInputEncoding::Windows1251 => "Вход: Windows-1251",
        TextInputEncoding::Ascii => "Вход: ASCII",
    }
}

fn line_endings_label(mode: LineEndings) -> &'static str {
    match mode {
        LineEndings::Preserve => "Переводы строк: как есть",
        LineEndings::Lf => "Переводы строк: LF",
        LineEndings::Crlf => "Переводы строк: CRLF",
    }
}

fn image_mode_label(mode: ImageMode) -> &'static str {
    match mode {
        ImageMode::Bytes => "Изображения: байты файла",
        ImageMode::Pixels => "Изображения: сырые пиксели",
    }
}

fn pixel_format_label(format: PixelFormat) -> &'static str {
    match format {
        PixelFormat::Rgb8 => "RGB8",
        PixelFormat::Rgba8 => "RGBA8",
        PixelFormat::Luma8 => "Grayscale 8",
    }
}

fn split_label(size: Option<u64>) -> &'static str {
    match size {
        None => "Части: не разбивать",
        Some(65_536) => "Части: 64 КиБ",
        Some(1_048_576) => "Части: 1 МиБ",
        Some(4_194_304) => "Части: 4 МиБ",
        Some(16_777_216) => "Части: 16 МиБ",
        Some(_) => "Части: другой размер",
    }
}

fn pad_byte_label(byte: PadByte) -> &'static str {
    match byte {
        PadByte::Zero => "Заполнять 0x00",
        PadByte::Ones => "Заполнять 0xFF",
    }
}

fn byte_swap_label(swap: ByteSwap) -> &'static str {
    match swap {
        ByteSwap::None => "Порядок байт: не менять",
        ByteSwap::Swap16 => "Порядок байт: Swap 16",
        ByteSwap::Swap32 => "Порядок байт: Swap 32",
    }
}

fn settings_path() -> Option<PathBuf> {
    ProjectDirs::from("", "", "bin-inator").map(|dirs| dirs.config_dir().join("settings.json"))
}

fn load_settings() -> Settings {
    let Some(path) = settings_path() else {
        return Settings::default();
    };
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn default_output_dir() -> Option<PathBuf> {
    UserDirs::new().and_then(|dirs| dirs.download_dir().map(|path| path.to_path_buf()))
}

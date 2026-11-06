# bin-inator

Превращает что угодно в `.bin`: текст, изображения, исполняемые файлы, дампы, образы дисков и произвольные данные.

## Статус

M0–M4: raw-конвейер, преобразования, контейнер, инспектор, пакетный режим и извлечение секций PE/ELF.

- потоковое raw-копирование в `.bin` чанками по 1 МиБ;
- определение типа по magic-байтам и расширению;
- drag&drop и пакетная очередь в GUI;
- прогресс и отмена без оставшихся временных файлов;
- атомарная запись через временный файл;
- перекодировка текста (UTF-8, UTF-16 LE/BE, Windows-1251, ASCII), BOM и переводы строк;
- дамп сырых пикселей изображений (RGB8, RGBA8, Luma8);
- разбиение на части, выравнивание/padding, обрезка хвостовых нулей, byte-swap 16/32 и bit-reverse;
- SHA-256 и CRC32 каждого результата;
- необязательный JSON-сайдкар с параметрами, хэшами и метаданными изображения;
- контейнер `BINATOR1` (`pack`/`unpack`) с метаданными, CRC32 и SHA-256, побайтово обратимым payload;
- инспектор: тип, MIME, текстовые признаки, размеры изображения, заголовки и секции PE/ELF, метаданные контейнера, hex-дамп начала, SHA-256/CRC32;
- пакетный режим: рекурсивный обход папок в GUI и CLI, JSON-манифест батча;
- извлечение секций PE/ELF в отдельные `.bin` с проверкой границ, SHA-256 и JSON-манифестом;
- CLI `convert`, `pack`, `unpack`, `inspect` и `extract`;
- настройки в `%APPDATA%\bin-inator\settings.json`.

Спецификация контейнера: [`docs/FORMAT.md`](docs/FORMAT.md).

## Запуск

```bash
cargo run --bin bin-inator-gui
```

```bash
cargo run --bin bin-inator -- inspect photo.png
cargo run --bin bin-inator -- inspect app.exe --hashes
cargo run --bin bin-inator -- convert photo.png -o out
cargo run --bin bin-inator -- convert disk.img -o out --overwrite suffix

# Пакетная обработка папки с манифестом
cargo run --bin bin-inator -- convert samples -o out --recursive --sidecar --manifest out/batch.json
```

Извлечение секций:

```bash
# Все непустые секции PE/ELF
cargo run --bin bin-inator -- extract app.exe -o sections

# Только выбранные секции (имя с точкой или без, либо индекс из inspect)
cargo run --bin bin-inator -- extract app.exe -o sections --section .text --section 2 --overwrite suffix

# JSON-манифест с offsets и SHA-256
cargo run --bin bin-inator -- extract app.exe -o sections --manifest sections/app.sections.json
```

Примеры M1:

```bash
# Перекодировать текст в UTF-16 LE с BOM и LF
cargo run --bin bin-inator -- convert notes.txt -o out --text-encoding utf16le --bom --line-endings lf

# Сырые пиксели RGBA8
cargo run --bin bin-inator -- convert photo.png -o out --image-mode pixels --pixel-format rgba8

# Разбить образ на части по 4 МиБ, выровнять и записать сайдкар
cargo run --bin bin-inator -- convert disk.img -o out --split-bytes 4194304 --pad-to 4096 --sidecar

# Поменять порядок байт и обрезать хвостовые нули
cargo run --bin bin-inator -- convert dump.bin -o out --swap 16 --trim
```

Контейнер:

```bash
# Упаковать файл без изменения байтов
cargo run --bin bin-inator -- pack disk.img -o out/disk.binator --note "исходный образ"

# Показать метаданные и хэши контейнера
cargo run --bin bin-inator -- inspect out/disk.binator --json

# Распаковать обратно (имя берётся из метаданных)
cargo run --bin bin-inator -- unpack out/disk.binator -o restored
```

В GUI включите «Упаковывать в контейнер BINATOR1», чтобы создавать `.binator`,
или добавьте контейнеры в список и нажмите «Распаковать контейнеры».

Вкладка «Инспектор» показывает заголовки PE/ELF, список секций, текстовые
признаки, размеры изображения, метаданные контейнера и хэши. Кнопка
«Добавить папку» в очереди запускает рекурсивный пакетный режим.
Кнопка «Извлечь секции…» сохраняет секции PE/ELF в выбранную папку с
прогрессом и отменой.

## Формат имён

- без разбиения: `<stem>.bin`;
- с разбиением: `<stem>.part001.bin`, `<stem>.part002.bin`, …;
- сайдкар: `<первый_выходной_файл>.json`;
- секции: `<stem>.<секция>.bin`, повторяющиеся имена получают `-2`, `-3`, ….

## Релиз

```powershell
# PowerShell 7+
pwsh scripts/package.ps1

# Windows PowerShell 5.1
powershell -ExecutionPolicy Bypass -File scripts/package.ps1
```

Скрипт собирает `--release --bins` и кладёт в `dist/`
`bin-inator-<версия>-windows-x64.zip` с `bin-inator.exe`,
`bin-inator-gui.exe`, README, `docs/FORMAT.md` и `VERSION.txt`.
Повторная упаковка без сборки: добавьте `-SkipBuild`.

## Проверка

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

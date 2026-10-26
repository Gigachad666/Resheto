# АС Решето

Решето проверяет локальные файлы и каталоги по SHA-256 и байтовым шаблонам. Доступны графическое окно, консоль и C++-библиотека для встраивания. Проверка работает без сети, не запускает и не изменяет проверяемые файлы. Результаты сохраняются в SQLite.

## Сборка

Нужны C++20, CMake 3.21+ и Qt 6.2–6.x: Core, Sql, Widgets, Test и драйвер QSQLITE. Проверены Windows 11 x64, Visual Studio 2022 и Qt 6.8.3 MSVC x64. Замените путь SDK на свой:

```powershell
$env:QT_ROOT='C:/Qt/6.8.3/msvc2022_64'
$env:PATH="$env:QT_ROOT/bin;$env:PATH"
cmake -S . -B build/windows -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$env:QT_ROOT"
cmake --build build/windows --config Release --parallel 4
$bin='./build/windows/Release'
```

Для локального SDK проекта путь Qt — `$PWD/.tools/qt/6.8.3/msvc2022_64`. Скрипты запуска поддерживают Windows PowerShell 5.1 и PowerShell 7.

## Запуск и использование

Команды выполняются из корня проекта:

```powershell
# Открыть GUI с рабочей базой, выбрать файл или каталог в окне:
.\scripts\start.ps1
# Сразу открыть обычный файл для проверки рабочей базой:
.\scripts\start.ps1 -Path .\README.md
# Подготовить безопасные примеры и открыть их с контрольной базой:
.\scripts\start.ps1 -Control
```

Нажмите «Начать». «Остановить» запрашивает отмену. Фильтры «Все / Совпадения / Не проверены», поиск по пути и сортировка работают по всему заданию. Полный путь и основание обнаружения можно скопировать; история доступна после перезапуска.

| Поле окна | Назначение |
| --- | --- |
| Объект | Файл или каталог, который нужно проверить |
| Сигнатуры | Одна выбранная база правил: рабочая `distribution/working/current.json` или контрольная `build/manual/control/signatures.db` |
| История проверок | Отдельная SQLite с результатами; по умолчанию у скрипта — `build/manual/results.db` |

Для CLI после сборки:

```powershell
New-Item -ItemType Directory -Force build/manual | Out-Null
& "$bin/resheto-cli.exe" --path README.md --db distribution/working/current.json --storage build/manual/results.db --json
& "$bin/resheto-cli.exe" --last --storage build/manual/results.db --json
```

`--json` выдаёт JSON Lines, `--non-recursive` отключает подкаталоги. Коды завершения: **0** — совпадений нет, **1** — найдены, **2** — ошибка или неполная проверка, **3** — отмена. Родительский каталог истории у CLI должен существовать.

## База сигнатур

В поставке **11 632 уникальных SHA-256** из [malicious-hash](https://github.com/romainmarcoux/malicious-hash) Romain MARCOUX, лицензия MIT. Используется закреплённый снимок: версия базы `malicious-hash-9e6be541abb33859`. Исходные данные, лицензия и сведения о происхождении сохранены в `distribution/source`.

`distribution/working/current.json` указывает на текущую SQLite. Рабочий источник содержит только HASH. Контрольная база для собственных безопасных файлов отдельно показывает HASH и PATTERN: точный поиск, маску, фиксированное смещение и переход между блоками.

Для подготовки другой рабочей версии есть офлайн-импорт:

```powershell
& "$bin/resheto-import.exe" --format sha256-lines --input distribution/source/full-hash-sha256-aa.txt --provenance distribution/source/provenance.json --repository build/new-working --version malicious-hash-9e6be541abb33859
```

Повторно получить исходный снимок: `./scripts/fetch-signatures.ps1 -Output build/new-source`; для другой ревизии укажите `-Revision <commit>`. Импорт проверяет данные до переключения версии; при ошибке прежняя база сохраняется. Начатое задание использует свой неизменяемый снимок. [Обновление, выбор и возврат версии](docs/signature_sources.md).

## Как проходит проверка

**Запрос → снимок правил → чтение и поиск → результат файла → история и сводка задания.** GUI запускает ядро в рабочем потоке; поиск, обход каталогов и SQL находятся в библиотеке.

Файл читается блоками: одновременно вычисляется SHA-256 и ищутся PATTERN. Хеш проверяется по индексу. Алгоритм Ахо–Корасик ищет опорные фрагменты множества шаблонов за один проход, затем проверяются полный шаблон, маска и ограничения. Хвост блока сохраняется для совпадений на границе. Ошибки и отмена отражаются в результате.

| Где смотреть | За что отвечает |
| --- | --- |
| `src/core/model.h` | Типы запроса, снимка правил, результата файла и задания |
| `src/core/controller.*`, `scanner.*` | Фоновый запуск, обход и проверка файлов |
| `src/core/signatures.*`, `search.*`, `file_access.*` | Загрузка правил, поиск и доступ к файлу |
| `src/core/database.*`, `import.*` | История SQLite и подготовка версий базы |
| `src/gui/`, `src/cli.cpp` | Графическая и консольная оболочки одного ядра |
| `tests/`, `scripts/`, `examples/consumer/` | Автотесты, сценарии запуска и пример встраивания |

[Подробнее об устройстве](docs/implementation.md). Публичная цель — `Resheto::Core`, заголовок — `<core/api.h>`; [пример подключения](docs/integration.md) собирается без Widgets и Qt Test.

## Проверки и показ

Полный набор и целевые проверки GUI, скриптов запуска и рабочей базы:

```powershell
ctest --test-dir build/windows -C Release --output-on-failure
ctest --test-dir build/windows -C Release -R '^(completion|gui|scripts-powershell51)$' --output-on-failure
& "$bin/resheto-completion-tests.exe" realFeedProvenance
```

`realFeedProvenance` сверяет источник, импорт и поиск известных SHA-256 в рабочей поставке без загрузки вредоносных образцов. Скрипты запуска можно отдельно проверить в обеих версиях PowerShell:

```powershell
powershell.exe -NoProfile -NonInteractive -File tests/powershell_scripts.ps1 -Bin build/windows/Release -WorkDir build/windows
pwsh -NoProfile -NonInteractive -File tests/powershell_scripts.ps1 -Bin build/windows/Release -WorkDir build/windows
```

Для наглядного показа (выходные каталоги должны быть новыми):

```powershell
.\scripts\demo.ps1 -Output build/show-new
.\scripts\demo-results.ps1 -Output build/show-many-new
```

Первый сценарий проверяет обе базы, ошибки, отмену и чтение истории. Второй сохраняет 2 101 результат с одним обнаружением для проверки фильтра. [Показ на 5–7 минут](docs/lab3_demo.md), [измерения производительности](docs/performance.md), [подробный отчёт проверок](docs/verification.md).

## Ограничения

Отсутствие совпадения не доказывает безопасность. HASH распознаёт точные байты известных файлов; источник не указывает семейство угрозы и происхождение каждого хеша. Архивы не распаковываются, ссылки и специальные файлы пропускаются. Служба, IPC, эвристика, наблюдение, анализ процессов и сети, карантин не реализованы.

Для Debug замените `Release` на `Debug`. Linux пока не проверен; команды для Ubuntu 22.04:

```bash
sudo apt install build-essential cmake ninja-build qt6-base-dev qt6-base-dev-tools libqt6sql6-sqlite qt6-qpa-plugins
cmake --preset release
cmake --build --preset release --parallel 4
ctest --preset release
```

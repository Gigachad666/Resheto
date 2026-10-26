# АС Решето

Локальная проверка файлов и каталогов по SHA-256 и байтовым шаблонам. C++20, Qt 6, SQLite. Есть GUI, консоль и библиотека для подключения к другому приложению. Сканирование работает без сети и административных прав.

## Что реализовано

- HASH и PATTERN: маски, фиксированное смещение, ограничения размера, совпадения между блоками.
- Обход каталогов, отмена, обработка ошибок и сохранение истории в SQLite.
- GUI: фильтры «Все / Совпадения / Не проверены», поиск по пути, сортировка, копирование пути и основания.
- Рабочая база: **11 632 уникальных SHA-256** из [malicious-hash](https://github.com/romainmarcoux/malicious-hash), MIT. Контрольные правила и синтетическая нагрузка хранятся отдельно.
- Публичная цель `Resheto::Core` и отдельный пример её подключения без GUI и Qt Test.

## Как устроено

Файл читается блоками: одновременно вычисляется SHA-256 и ищутся шаблоны. Для хешей используется индекс digest, для шаблонов — общий автомат Ахо–Корасик по значимым фрагментам с проверкой полного совпадения. Задание удерживает неизменяемый снимок базы. GUI вызывает ядро в рабочем потоке; SQL, поиск и обход находятся в библиотеке.

```text
src/core/          анализ, обход, сигнатуры, импорт, история, контроллер
src/gui/           окно Qt Widgets
src/cli.cpp        консоль; prepare/import_main/benchmark — утилиты
examples/consumer/ отдельный потребитель библиотеки
/tests, /scripts   проверки и воспроизводимые сценарии
/distribution      рабочая база, исходный снимок и лицензия
/data              собственные контрольные правила
/docs              подробности реализации и проверки
```

## Сборка

Нужны CMake 3.21+, C++20, Qt 6.2–6.x с Core/Sql, Widgets и Test, плагин QSQLITE. Проверено на Windows 11: MSVC 2022, Qt 6.8.3, Release и Debug. Для Windows установите Visual Studio с компонентами C++ и Qt MSVC 2022 x64; укажите свой путь Qt:

```powershell
$env:QT_ROOT='C:/Qt/6.8.3/msvc2022_64'
$env:PATH="$env:QT_ROOT/bin;$env:PATH"
cmake -S . -B build/windows -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$env:QT_ROOT"
cmake --build build/windows --config Release --parallel 4
ctest --test-dir build/windows -C Release --output-on-failure
```

Для Debug замените `Release` на `Debug`. Для одной библиотеки добавьте при конфигурации `-DRESHETO_BUILD_GUI=OFF -DRESHETO_BUILD_TOOLS=OFF -DBUILD_TESTING=OFF`: Widgets и Qt Test не нужны.

Ubuntu 22.04 — команды сохранены, **платформа пока не проверена**:

```bash
sudo apt install build-essential cmake ninja-build qt6-base-dev qt6-base-dev-tools libqt6sql6-sqlite qt6-qpa-plugins
cmake --preset release
cmake --build --preset release --parallel 4
ctest --preset release
```

## Запуск и работа

Из корня проекта, PowerShell. Подготовка создаёт безопасные файлы в новом каталоге:

```powershell
$bin='./build/windows/Release'
& "$bin/resheto-prepare.exe" --source data/demo_signatures.json --output build/check
& "$bin/resheto.exe" --path build/check/fixtures --db distribution/working/current.json --storage build/check/results.db
```

В GUI выберите файл или каталог, базу и нажмите «Начать». «Остановить» запрашивает отмену; история остаётся после перезапуска. Фильтры и сортировка работают по всему заданию, таблица показывает по 200 строк. Поиск пути учитывает регистр. Во время сканирования обновляется первая страница.

Рабочая база на этих безопасных файлах не даёт совпадений. Для наглядной проверки выберите `build/check/signatures.db`: тем же модулем будут найдены **5 совпадений в 11 файлах**. Через консоль:

```powershell
& "$bin/resheto-cli.exe" --path build/check/fixtures --db build/check/signatures.db --storage build/check/results.db --json
& "$bin/resheto-cli.exe" --last --storage build/check/results.db --json
```

Коды CLI: **0** — совпадений нет, **1** — есть, **2** — ошибка/неполная проверка, **3** — отмена. Приоритет: ошибка → отмена → обнаружение. `--non-recursive` отключает подкаталоги; `--json` выдаёт JSON Lines. На Linux исполняемые файлы находятся в `build/release`, без `.exe`.

## Рабочая база и обновление

Текущий выбор — `distribution/working/current.json`. Рядом с выбранной SQLite лежат checksum, manifest и исходный снимок. Закреплена ревизия `9e6be541abb33859f49c06d66cf7c97e54ab2bc4`: 11 636 строк, четыре дубля, **11 632 HASH, 0 PATTERN**. Лицензия и сведения об источнике — в `distribution/source`.

Офлайн-импорт готового снимка:

```powershell
& "$bin/resheto-import.exe" --format sha256-lines --input distribution/source/full-hash-sha256-aa.txt --provenance distribution/source/provenance.json --repository build/new-working --version malicious-hash-9e6be541abb33859
```

Для замены повторите импорт в тот же repository с новым снимком/версией, затем используйте его `current.json`. При ошибке прежняя база сохраняется; начатое задание заканчивает со старым снимком. Получение метаданных запускается отдельно: `./scripts/fetch-signatures.ps1 -Output build/new-source`. [Формат, происхождение, замена и возврат](docs/signature_sources.md).

## Проверки и ограничения

Новые Release/Debug: **5/5 групп CTest**, внешний потребитель и нативные GUI-тесты прошли. Обычный symlink пропущен из-за прав ОС; junction проверен. Профиль **100 000 HASH + 1 000 PATTERN**: 64 МиБ при блоке 64 КиБ — 1,049 с, загрузка — 2,097 с, пик процесса — 89,4 MiB. Это один синтетический прогон, не оценка покрытия угроз.

Отсутствие совпадения не доказывает безопасность. Рабочий источник даёт только хеши, без семейств и первоисточника каждого файла. Архивы не распаковываются; служба, IPC, эвристика, наблюдение, процессы, сеть и карантин не реализованы. Linux, настоящий NTFS ACL/заполненный диск и перенос без SDK отдельно не проверены.

Подробности: [устройство](docs/implementation.md), [подключение библиотеки](docs/integration.md), [проверки](docs/verification.md), [замеры](docs/performance.md), [показ на 5–7 минут](docs/lab3_demo.md), [ручной EICAR](docs/eicar_manual.md).

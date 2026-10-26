# АС Решето

Локальная проверка файлов и каталогов по SHA-256 и байтовым шаблонам. C++20, Qt 6, SQLite. Есть GUI, консоль и библиотека для подключения к другому приложению. Сканирование работает без сети и административных прав.

## Что реализовано

- HASH и PATTERN: маски, фиксированное смещение, ограничения размера, совпадения между блоками.
- Обход каталогов, отмена, обработка ошибок и сохранение истории в SQLite.
- GUI: фильтры «Все / Совпадения / Не проверены», поиск по пути, сортировка, копирование пути и основания.
- Рабочая база: **11 632 уникальных SHA-256** из [malicious-hash](https://github.com/romainmarcoux/malicious-hash), MIT. Контрольные правила и нагрузка отделены от неё.
- Публичная цель `Resheto::Core` и отдельный пример её подключения без GUI и Qt Test.

## Запуск

Из корня проекта в обычном Windows PowerShell 5.1 или PowerShell 7, после сборки:

```powershell
.\scripts\start.ps1 -Control
```

Скрипт сам подключит локальный Qt, один раз подготовит безопасные файлы в `build/manual/control` и откроет GUI с заполненными полями. Нажмите «Начать»: ожидается **11 проверенных файлов и 5 совпадений**. При повторном запуске данные не пересоздаются. Если сборка в другом каталоге, добавьте `-Bin build/final-20261025/Release`.

Для проверки своих файлов с рабочей базой:

```powershell
.\scripts\start.ps1
```

Выберите объект кнопкой «Файл…»/«Каталог…» и нажмите «Начать». В этом режиме используется рабочая база из `distribution/working/current.json`.

| Поле GUI | Что в нём |
| --- | --- |
| Объект | Файл или каталог для проверки; в контроле — `build/manual/control/fixtures` |
| Сигнатуры | **Одна** база правил: `build/manual/control/signatures.db` для контроля либо `distribution/working/current.json` для работы |
| История проверок | Файл результатов `build/manual/results.db`; он и каталог создаются автоматически |

История сохраняется после перезапуска. Фильтры и сортировка применяются ко всему заданию, таблица показывает по 200 строк. Поиск пути учитывает регистр. Во время сканирования обновляется первая страница.

`demo-run` и `demo-check` — оставшиеся одинаковые контрольные копии предыдущих проверок. Для запуска они не нужны. Папки внутри `build` также содержат результаты отдельных тестов, не дополнительные обязательные базы. `current.json` — указатель на выбранную рабочую версию; перечислять все signatures.db в GUI не нужно.

## Как устроено

Файл читается блоками: одновременно вычисляется SHA-256 и ищутся шаблоны. Для хешей используется индекс digest, для шаблонов — общий автомат Ахо–Корасик с проверкой полного кандидата. Задание удерживает неизменяемый снимок базы. GUI вызывает ядро в рабочем потоке; SQL, поиск и обход находятся в библиотеке.

```text
src/core/          анализ, обход, сигнатуры, импорт, история, контроллер
src/gui/           окно Qt Widgets
src/cli.cpp        консоль; prepare/import_main/benchmark — утилиты
examples/consumer/ отдельный потребитель библиотеки
tests/, scripts/   проверки, подготовка и запуск
distribution/      рабочая база, исходный снимок и лицензия
data/, docs/       контрольные правила и документация
```

## Сборка и проверки

Нужны CMake 3.21+, C++20, Qt 6.2–6.x (Core/Sql, Widgets, Test), QSQLITE. На Windows проверены MSVC 2022 и Qt 6.8.3. Укажите путь своего SDK; здесь локально установлен `$PWD/.tools/qt/6.8.3/msvc2022_64`:

```powershell
$env:QT_ROOT="$PWD/.tools/qt/6.8.3/msvc2022_64"
cmake -S . -B build/windows -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$env:QT_ROOT"
cmake --build build/windows --config Release --parallel 4
$env:PATH="$env:QT_ROOT/bin;$env:PATH"
ctest --test-dir build/windows -C Release --output-on-failure
```

Для Debug замените `Release` на `Debug`. Для одной библиотеки: `-DRESHETO_BUILD_GUI=OFF -DRESHETO_BUILD_TOOLS=OFF -DBUILD_TESTING=OFF`.

Ubuntu 22.04 пока не проверена: установите `build-essential cmake ninja-build qt6-base-dev qt6-base-dev-tools libqt6sql6-sqlite qt6-qpa-plugins`, затем выполните `cmake --preset release`, `cmake --build --preset release --parallel 4`, `ctest --preset release`.

Автоматический показ с проверкой обеих баз, ошибок, отмены и истории:

```powershell
.\scripts\demo.ps1 -Output build/show-new
.\scripts\demo-results.ps1 -Output build/show-many-new
```

Выходные каталоги этих двух проверок должны отсутствовать. Второй сценарий сохраняет 2101 результат с одним совпадением для показа глобального фильтра. Скрипты содержат UTF-8 BOM для PowerShell 5.1; политика выполнения ОС не меняется.

CLI: `resheto-cli.exe --path <объект> --db <база> --storage <история> --json`; `--last --storage <история> --json` читает сохранённое задание. Родительский каталог явного `--storage` у CLI должен существовать. Коды: **0** — совпадений нет, **1** — есть, **2** — ошибка/неполная проверка, **3** — отмена. Приоритет: ошибка → отмена → обнаружение.

## Рабочая база и ограничения

В `distribution/source` сохранены источник и MIT-лицензия. Ревизия `9e6be541abb33859f49c06d66cf7c97e54ab2bc4`: 11 636 строк, четыре дубля, **11 632 HASH, 0 PATTERN**. Офлайн-импорт и замена:

```powershell
./build/windows/Release/resheto-import.exe --format sha256-lines --input distribution/source/full-hash-sha256-aa.txt --provenance distribution/source/provenance.json --repository build/new-working --version malicious-hash-9e6be541abb33859
```

При ошибке прежняя версия сохраняется, текущее задание использует свой снимок. Сетевое получение метаданных запускается отдельно: `./scripts/fetch-signatures.ps1 -Output build/new-source`. [Подробности источника и возврата](docs/signature_sources.md).

Отсутствие совпадения не доказывает безопасность. Рабочая база распознаёт точные хеши, источник не предоставляет семейства и первоисточник каждого файла. Архивы, служба, IPC, эвристика, наблюдение, процессы, сеть и карантин не реализованы. Linux, настоящий NTFS ACL/заполненный диск и перенос без SDK отдельно не проверены.

Подробности: [устройство](docs/implementation.md), [встраивание](docs/integration.md), [проверки](docs/verification.md), [замеры](docs/performance.md), [показ](docs/lab3_demo.md), [ручной EICAR](docs/eicar_manual.md). Измерения 100000 HASH + 1000 PATTERN относятся к синтетическому профилю, не к покрытию угроз.

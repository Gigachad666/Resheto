# АС Решето

Локальная сигнатурная проверка файлов и каталогов: SHA-256 и двоичные шаблоны из SQLite, CLI и Qt Widgets GUI. Реализован объём этапа 3 из `TASK_LAB3.md`. Проверка работает без сети и административных прав. Все поставляемые сигнатуры — **тестовые**, для собственных безопасных данных; это не база реальных угроз.

Для объяснения на защите: [как устроена программа, карта файлов, роль технологий и проверка](docs/lab3_defense.md).

## Зависимости

C++20, CMake 3.21+, Qt **6.2–6.x** (Core, Sql, Widgets, Test), драйвер **QSQLITE** из qtbase. Внешняя SQLite не требуется: используется поставляемая Qt версия. Проверено 19.10.2026: Windows 11 x64, MSVC 19.44.35228, Qt 6.8.3, SQLite 3.49.1, CMake 3.31.6. Совместимость других Qt в указанном диапазоне и Ubuntu 22.04 пока требует отдельного запуска тестов. Vulkan не используется; сообщение CMake об отсутствии его заголовков допустимо.

Справка: [сборка Qt/CMake](https://doc.qt.io/qt-6/cmake-get-started.html), [QSQLITE](https://doc.qt.io/qt-6/sql-driver.html#qsqlite), [потоковый SHA-256](https://doc.qt.io/qt-6/qcryptographichash.html).

## Windows 10/11, x64

Установите Visual Studio 2022 Build Tools/Community с «Desktop development with C++», Windows SDK, CMake; Qt 6.8.3 **MSVC 2022 64-bit** с qtbase через Qt Online Installer. Исходники UTF-8. Команды PowerShell из корня проекта (путь Qt адаптируйте к установке):

```powershell
$env:QT_ROOT = 'C:/Qt/6.8.3/msvc2022_64'
$env:PATH = "$env:QT_ROOT/bin;$env:PATH"
cmake -S . -B build/windows -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$env:QT_ROOT"
cmake --build build/windows --config Release --parallel 4
ctest --test-dir build/windows -C Release --output-on-failure
# Обычная Debug-конфигурация того же проекта:
cmake --build build/windows --config Debug --parallel 4
ctest --test-dir build/windows -C Debug --output-on-failure
```

В качестве альтернативы Qt SDK можно загрузить локально без изменения системного PATH (Python используется **только для установки SDK**, программа и генератор данных написаны на C++):

```powershell
python -m pip install --target .tools/python aqtinstall==3.3.0 cmake==3.31.6 ninja==1.11.1.4
$env:PYTHONPATH = "$PWD/.tools/python"
python -m aqt install-qt windows desktop 6.8.3 win64_msvc2022_64 -O .tools/qt --archives qtbase
$env:QT_ROOT = "$PWD/.tools/qt/6.8.3/msvc2022_64"
$env:PATH = "$PWD/.tools/python/cmake/data/bin;$env:QT_ROOT/bin;$env:PATH"
# Далее команды cmake выше.
```

Запуск и воспроизводимая проверка всех кодов завершения:

```powershell
./build/windows/Release/resheto-prepare.exe --source data/demo_signatures.json --output demo-run
./build/windows/Release/resheto-cli.exe --path demo-run/fixtures --db demo-run/signatures.db --storage demo-run/resheto.db --json
# Код 1 здесь ожидаем: 5 совпадений, 11 проверенных файлов.
./build/windows/Release/resheto-cli.exe --last --storage demo-run/resheto.db --json
./build/windows/Release/resheto.exe --path demo-run/fixtures --db demo-run/signatures.db --storage demo-run/resheto.db
# Или полная автоматическая демонстрация в НОВОМ каталоге:
./scripts/demo.ps1 -Bin build/windows/Release -Output demo-script
```

Утилита подготовки отказывается писать в существующий каталог. Выбирайте новый `--output`; она ничего не скачивает. Для большой безопасной фикстуры: `--large-mib 512` (0..4096). Для своей базы из JSON без демонстрационных файлов: `--database-only`.

Для переноса исполняемых файлов на другую машину разместите их в отдельном новом каталоге и выполните `windeployqt --release --no-translations resheto.exe` из той же версии Qt. Сохраните плагины `platforms/qwindows.dll`, `sqldrivers/qsqlite.dll`, необходимые Qt DLL и MSVC runtime; отдельно проверьте CLI и GUI на целевой машине. Установщик/служба на этом этапе не создаются.

## Ubuntu 22.04 LTS, x86-64

Ниже воспроизводимые команды для штатного Qt 6.2.4; **на этой ОС в текущей работе не выполнялись**:

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build qt6-base-dev qt6-base-dev-tools libqt6sql6-sqlite qt6-qpa-plugins
cmake --preset release
cmake --build --preset release --parallel 4
ctest --preset release
./build/release/resheto-prepare --source data/demo_signatures.json --output demo-run
./build/release/resheto-cli --path demo-run/fixtures --db demo-run/signatures.db --storage demo-run/resheto.db --json
# Ожидается exit 1, пять совпадений.
./build/release/resheto-cli --last --storage demo-run/resheto.db --json
./build/release/resheto --path demo-run/fixtures --db demo-run/signatures.db --storage demo-run/resheto.db
```

`debug` preset аналогичен `release`. Для сборки без GUI: добавьте `-DRESHETO_BUILD_GUI=OFF`. CLI использует QCoreApplication и не требует графического сеанса; тест GUI использует платформу `offscreen`.

## Использование и результаты

GUI: выберите файл/каталог, базу `signatures.db` с соседним `signatures.db.sha256`, рекурсивность и нажмите «Начать». Состояние базы проверяется до начала; каждое задание повторно загружает валидный снимок. «Остановить» отменяет чтение и обход. Сводка содержит последнее обнаружение, ошибки и объяснимые пропуски. Таблица показывает до 200 строк на страницу; «Следующие 200», «С начала» и «Последнее задание» читают SQLite, включая после перезапуска. У пути, основания и причины есть полные всплывающие подсказки.

Без `--storage` рабочее хранилище создаётся в пользовательском каталоге `QStandardPaths::AppLocalDataLocation` (на Windows обычно `%LOCALAPPDATA%/Resheto/resheto.db`, Linux `~/.local/share/Resheto/resheto.db`). Фактический путь виден в GUI; конкретное расположение зависит от Qt/ОС. Явный `--storage` позволяет полностью изолировать показ. Родительский каталог явного пути должен существовать.

CLI: `--path`, `--db`, необязательные `--storage`, `--non-recursive`, `--json`, `--block-size 4096..4194304`; отмена через **Ctrl+C / SIGINT / SIGTERM** или `--cancel-after-ms N`. `--last` читает последнее задание. Вывод `--json` — UTF-8 JSON Lines: ноль или более объектов `{"type":"result","data":...}`, затем `{"type":"job","data":...,"exit_code":N}`. Ошибки аргументов/чтения истории дают объект `type=error` и код **2**, включая неизвестную опцию и отсутствие значения; `--help` завершается с кодом **0**. Счётчики, размеры и смещения — десятичные **строки**, сохраняющие 64-битную точность. Поле `offset=-1` означает отсутствие смещения (например, HASH).

Сохранённые Job/Result читаются со строгой проверкой обязательных полей, типов, диапазонов и согласованности. `--last` в одной read-only транзакции сверяет сводку с результатами; повреждённые данные дают явную ошибку, без молчаливой замены нулями. Это линейное чтение результатов задания с ограниченной памятью. GUI сохраняет ошибку чтения истории в отдельном сообщении; автоматическая остановка по этой причине отличается от пользовательской отмены. Сообщение остаётся после остановки; новое сканирование очищает его, «Последнее задание» позволяет повторить чтение.

Глубина корневого каталога — **0**. Сканируются каталоги глубины **0..256 включительно**; каталог глубины 257 даёт `not_checked/depth_limit`, задание завершается с ошибкой, доступные соседние ветви продолжают проверяться. Ограничения длины пути ОС могут помешать добраться до этой границы раньше; такая ситуация тоже отражается как ошибка доступа, а не успешная проверка.

| Код | Значение | Приоритет |
| --- | --- | --- |
| 0 | Завершено без совпадений; пропуски по политике указаны отдельно | Низший |
| 1 | Есть совпадение с сигнатурой | Выше 0 |
| 3 | Задание отменено | Выше обнаружения |
| 2 | Ошибка готовности, файла/каталога, неполная проверка либо ошибка хранения | Наивысший, в том числе вместе с обнаружением/отменой |

JSON сохраняет и обнаружения, и ошибки независимо от кода. Итоги файлов: «Совпадение с сигнатурой», «Совпадений не обнаружено», «Не проверен». `full` означает завершённый **сигнатурный маршрут**; отсутствие совпадения не доказывает безопасность. Ссылки/reparse points, специальные и собственные служебные файлы не читаются и считаются пропусками. Недоступный обычный файл — ошибка, остальные файлы продолжают проверяться.

Формат базы, компоненты, ограничения и точки расширения описаны в [docs/implementation.md](docs/implementation.md). Показ на 5–7 минут: [docs/lab3_demo.md](docs/lab3_demo.md). Фактические проверки: [docs/verification.md](docs/verification.md). Отдельная добровольная ручная проверка EICAR: [docs/eicar_manual.md](docs/eicar_manual.md). Эвристика, наблюдение, процессы, сеть, карантин, IPC и системная служба не реализованы.

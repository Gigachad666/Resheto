# Исправление запуска — 26.10.2026

Воспроизведена ошибка пользователя в штатном Windows PowerShell **5.1.26100.9711**: UTF-8 без BOM у demo.ps1 давал 4 ParserError, подготовка не выполнялась. Следующий запуск GUI получал несуществующий каталог истории и ошибку SQLite. В demo-results дополнительно использовалось неподдерживаемое в 5.1 имя кодировки utf8NoBOM. Прежняя проверка только в PowerShell 7 этого не обнаружила.

Исправления: UTF-8 BOM у всех PowerShell-скриптов; явное UTF-8 чтение stdout/stderr дочерних C++ программ без зависимости от кодовой страницы оболочки; запись JSON через .NET UTF8Encoding. Сценарии сохраняют проверки кодов и точное сравнение истории. Новый scripts/start.ps1 открывает рабочую конфигурацию либо (-Control) один раз готовит и переиспользует build/manual/control; история — build/manual/results.db. Обе старые базы demo-run/signatures.db и demo-check/signatures.db имеют одинаковый SHA-256 B663D8DEB4403B9A5CD7F9E398B2AE53E19CBB1BC2674CBCCF12532FE18F689E и для нового запуска не нужны; они не удалялись.

GUI нормализует отображаемые пути, поясняет три поля и одну выбранную базу сигнатур. Перед запуском проверяет существование объекта; новый родительский каталог истории создаётся через Store::preparePath. Store/CLI без такого явного вызова сохраняют прежнее поведение. Ошибки открытия содержат русское объяснение, путь и техническую причину SQLite. Схемы БД и алгоритмы обнаружения не менялись.

Проверено на Windows 11/Qt 6.8.3/MSVC 2022:

- До исправлений Parser::ParseFile в PowerShell 5.1: errors=4; после — errors=0 для всех scripts/*.ps1.
- tests/powershell_scripts.ps1 выполнен в Windows PowerShell 5.1 и PowerShell 7.6.5: безопасный показ 11/5, большой показ 2101/1, точный Unicode-путь в JSON, replay, отказ перезаписи; новый запуск -Control -NoLaunch и его повтор без переписи базы. Тест использует новые временные каталоги с кириллицей и пробелами.
- GUI: новый missingPreparedDataAndNewHistoryDirectory проверяет понятную ошибку отсутствующего объекта до создания истории, реальное обнаружение с новым вложенным каталогом истории и отказ вместо файла-каталога. Прежние GUI/история/отмена сохранены, GUI QtTest — 6 passed/0 failed.
- Сначала целевые gui/scripts-powershell51: 2/2; затем полная сборка build/windows Release и итоговый CTest: **6/6, 39,71 с**. В полном наборе старые core/audit/cli/completion проходят; создание обычного symlink по-прежнему пропущено ОС. Новый Debug-прогон на 26.10 не выполнялся; проверка Debug 25.10 описана ниже.
- build/manual/control подготовлен фактической командой start.ps1 -Control -NoLaunch. Новый CLI на тех же 11 безопасных файлах: контрольная база — 5 совпадений/0 ошибок; рабочая — 0 совпадений/0 ошибок. Проверочные истории — build/manual/control-check.db и working-check.db; пользовательские области не сканировались.
- Обновлённый интерфейс проверен QtTest offscreen, снимок build/windows/gui-preview.png визуально просмотрен. Нативный ручной показ человеком этого исправления отдельно не подтверждён.

Реальные команды (из корня; PATH содержит .tools/qt/6.8.3/msvc2022_64/bin):

```powershell
./.tools/python/cmake/data/bin/cmake.exe -S . -B build/windows -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$PWD/.tools/qt/6.8.3/msvc2022_64"
./.tools/python/cmake/data/bin/cmake.exe --build build/windows --config Release --parallel 4
./.tools/python/cmake/data/bin/ctest.exe --test-dir build/windows -C Release -R '^(gui|scripts-powershell51)$' --output-on-failure
./.tools/python/cmake/data/bin/ctest.exe --test-dir build/windows -C Release --output-on-failure
powershell.exe -NoProfile -NonInteractive -File tests/powershell_scripts.ps1 -Bin build/windows/Release -WorkDir build/windows
pwsh -NoProfile -NonInteractive -File tests/powershell_scripts.ps1 -Bin build/windows/Release -WorkDir build/windows
powershell.exe -NoProfile -NonInteractive -File scripts/start.ps1 -Control -NoLaunch
```

Выход из песочницы потребовался для MSVC/Windows PowerShell: внутри .ps1 получил AuthorizationManager check failed из-за недоступного чтения реестра. Политика выполнения/защитные настройки не менялись. Первый полный CTest обнаружил зависимость новой проверки от автозагрузки Get-FileHash в унаследованном окружении PowerShell; вместо неё тест сравнивает полные байты базы до/после. Целевая проверка и полный CTest затем прошли, прежний неуспешный отчёт не скрывается (LastTestsFailed.log может содержать предыдущий запуск). Скрипт measure.ps1 явно требует PowerShell 7; большой замер повторно не запускался, алгоритм поиска не менялся. Источник/рабочая БД не изменялись, данные не скачивались.

---
# Проверка реализации — 25.10.2026

Это новый запуск реализации актуального TASK_LAB3.md, а не прежнее обновление требований. Исходный пользовательский код/изменения сохранены; ТЗ/контекст не переписывались. Результаты ниже получены на Windows 11 x64, MSVC 19.44.35228, Qt 6.8.3, SQLite 3.49.1, CMake 3.31.6. Linux отложен пользователем.

## Сборка и полный CTest

Из корня, PowerShell, Qt bin в PATH. В этой среде использован локальный CMake `.tools/python/cmake/data/bin/cmake.exe`/ctest.exe; приведённые обычные команды эквивалентны. Итоговые сборки/прогоны MSVC выполнены с разрешённым выходом из песочницы.

```powershell
$env:QT_ROOT="$PWD/.tools/qt/6.8.3/msvc2022_64"
$env:PATH="$env:QT_ROOT/bin;$env:PATH"
cmake -S . -B build/final-20261025 -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$env:QT_ROOT"
cmake --build build/final-20261025 --config Release --parallel 4
ctest --test-dir build/final-20261025 -C Release --output-on-failure
cmake --build build/final-20261025 --config Debug --parallel 4
ctest --test-dir build/final-20261025 -C Debug --output-on-failure
```

Release собран с чистого каталога; Debug собран в этом же multi-config дереве. Итоговый полный повтор: **Release 5/5 CTest, 27,23 с; Debug 5/5, 38,46 с**. В каждой конфигурации QtTest: audit 85 passed, core 38 passed/1 skipped, cli 7 passed, completion 7 passed, gui 5 passed; failures=0. Эти количества включают init/cleanup и строки data-driven проверок, не равны числу независимых сценариев. Отчёты раздельно: `build/final-20261025/reports/Release`, `reports/Debug`, общий CTest LastTest.log. В core пропущен nativeLinks: ОС не разрешила создание обычного symlink; это не успех проверки symlink. Настоящий junction и sharing violation прошли.

До полной сборки запускались целевые completion/gui, затем completion/audit. Новые проверки: индексированный поиск против независимого побайтового oracle с 1000 шаблонов, масками/fixed offset/ограничениями и разными окнами; HASH-кандидаты/размер/id; внешний импорт/дубли/ошибки/происхождение/переключение; запрос 2102 строк до пагинации. GUI: одно обнаружение после 2000 обычных строк, фильтр/Unicode-путь/сортировка/копирование. Старые core/audit/cli/gui тесты не ослаблялись.

## Что подтверждено

| Область | Реальное выполнение |
| --- | --- |
| Байтовые механизмы | HASH и изменение байта; точный/маскированный PATTERN, offset/min/max, границы, длинный шаблон > блока, пустой/большой файл |
| Ошибки/отмена | Изменение/подмена файла через синхронный hook; чтение/каталог через инъекцию; настоящий Windows sharing denial; сохранённые результаты при отмене/ошибке записи |
| Обход | Unicode/пробелы, нерекурсивность, служебные исключения; настоящий junction без цикла; **глубина 0..256 и ошибка 257 с продолжением соседей теперь проходят** через extended-length paths, настройки ОС не менялись |
| История/CLI | Прежние строгие проверки Job/Result, повреждённые типы/поля/qint64/счётчики; JSON-ошибки аргументов и exit 2, help 0; приоритет 2 > 3 > 1 > 0; повторное чтение |
| GUI | Реальное ядро/асинхронность, постоянная причина ошибки истории, отмена и новый запуск; до 200 строк, глобальный запрос/сортировка, стабильный набор страниц, полные значения в буфере |
| Внешний импорт | Valid HSB/plain digest, MD5/SHA1 явно в статистике; bad hex/длина/размер/overflow, конфликт/пустой итог, отсутствие источника, checksum, отказ публикации; прежний выбор/БД не меняются |
| Публикация/снимок | Отдельная версия и одна атомарная current.json; активация/возврат; переключение в afterBlock реального runJob: старое задание со старым именем/версией, следующее с новой |
| Рабочий источник | Закреплённый локальный feed; 11636 строк, 4 дубля, **11632 активных HASH**; 3 независимых ожидаемых digest/номера строк сверены с source.txt, provenance SQL и индексом digest; PATTERN=0 |
| Масштаб | Реальный ограниченный профиль 100000 HASH+1000 PATTERN; 64/256 МиБ, три блока, 1000 файлов с проверкой каждого id/offset; дерево/SQLite/replay; docs/measurements |

Ошибка отсутствия места проверена управляемым ENOSPC-отказом перед публикацией проверенного каталога (ImportRequest::beforePublish). Также проверен реальный отказ публикации при current.json, занятом каталогом. Физическое заполнение диска/настоящий ACL denial не создавались; это не выдаётся за проверку ОС.

## Независимое встраивание

```powershell
cmake -S examples/consumer -B build/consumer -G "Visual Studio 17 2022" -A x64 -DRESHETO_SOURCE="$PWD" -DCMAKE_PREFIX_PATH="$env:QT_ROOT" -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Widgets=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Test=TRUE
cmake --build build/consumer --config Release --parallel 4
./build/consumer/Release/consumer.exe build/completion/control/signatures.db build/completion/control/fixtures/hash.bin build/completion/control/fixtures/empty build/consumer/consumer-results-final.db
```

**Код 0**, обнаружение/отсутствие совпадения/ошибка/отмена/повторное открытие подтверждены. К Qt Widgets/Test нет обращения при конфигурации; CMake сообщает, что запреты find_package не потребовались (переменные не использованы). GUI/tools/testing выключены самим отдельным проектом; компилируются ядро и consumer. Фикстуры подготовлены отдельно до запуска, генератор/CLI не вызываются потребителем. Public API/владение — в integration.md.

## Поставка, повторный импорт и показ

```powershell
./scripts/demo.ps1 -Bin build/final-20261025/Release -Output build/final-20261025/show
./scripts/demo-results.ps1 -Bin build/final-20261025/Release -Output build/final-20261025/show-many
./build/final-20261025/Release/resheto-import.exe --format sha256-lines --input distribution/source/full-hash-sha256-aa.txt --provenance distribution/source/provenance.json --repository build/final-20261025/reproduced --version malicious-hash-9e6be541abb33859
./scripts/measure.ps1 -Bin build/final-20261025/Release -Output build/final-20261025/measure
```

Все команды выполнены успешно. show: рабочая база — 11 checked/0 matches/0 errors, контрольная — 11/5/0. JSONL обоих сканирований совпали по SHA-256 с повторным чтением; подтверждены коды 0/1/2/3. В show-many — 2101 checked/1 match/0 errors. Файлы собственные и безопасные, пользовательские каталоги не обходились. Повторный офлайн-импорт даёт тот же SHA-256 SQLite **d2e4fff6ca3684bb41925457174fd5fe6176ac9bd05da62c8f43f9d7b4eec967**; UUID каталога и время manifest закономерно новые.

Поставка: `distribution/working/current.json`, выбранная SQLite, .sha256, manifest.json и source.txt; исходник/лицензия/provenance в distribution/source. Источник/условия и точная статистика — signature_sources.md. Ключ/образцы не нужны. Получение сети отделено от сканирования, сборки и CTest.

Нагрузка: подготовка 7,853 с, загрузка большого профиля 2,097/2,022 с, 64 МиБ при блоке 64 КиБ — 1,049 с, 256 МиБ — 4,092 с, пик 89,4/89,5 MiB. Тысяча файлов с загрузкой/хранением — 7,223/7,434 с. Бюджет 120 с на процесс выбран заранее; не превышен. Полные условия/малый набор/ограничения — performance.md. Это не измерение процента распознавания угроз.

## Нативный интерфейс и неуспешные промежуточные попытки

Дополнительно выполнено вне песочницы:

```powershell
./build/final-20261025/Release/resheto-gui-tests.exe -platform windows -o build/final-20261025/gui-native-unsandboxed.txt,txt -o -,txt
```

**5 passed, 0 failed**, включая копирование в настоящий буфер Windows. Нативные снимки сохранены как `gui-native-preview.png`/`gui-native-global-preview.png` в build/final-20261025; offscreen-снимки там же. Снимок глобального фильтра визуально проверен: одна строка доступна, русские подписи/кнопки помещаются. Это управляемая автоматизация QtTest собственного приложения, не заявление о ручном показе человеком. Готовый ручной сценарий — lab3_demo.md. Computer Use helper в этой среде не нашёл отдельное удерживаемое окно; отдельный показ через него не подтверждён.

Промежуточные проблемы не скрыты: полная сборка MSBuild внутри песочницы зависала; сборка завершена вне неё. Исправлены ошибки компиляции QByteArray::contains и конфликт Windows-макроса small в новой утилите. Первое новое ожидание 11636 уникальных было опровергнуто независимым Sort-Object -Unique: 11632 и 4 дубля; статистика/тест исправлены по фактам. Один промежуточный rebuild benchmark при работающем замере получил LNK1104; чистая итоговая сборка выполнялась после остановки процессов. Первый запуск measure не мог читать CIM в песочнице; итоговый запуск выполнен вне неё. Первый нативный GUI-тест в песочнице имел 2 failures (в том числе COM 0x80070005 при доступе к clipboard); тот же тест без изменения проверок прошёл вне песочницы. Основной offscreen CTest прошёл в обеих средах. Исторические/неуспешные прогоны не считаются успешной приёмкой.

## Непроверенное и пределы

- Ubuntu/Linux, Windows 10, другие Qt/компиляторы, статическая Qt и перенос на машину без SDK не проверены. Сохранены переносимый код и отдельные инструкции.
- Обычный symlink пропущен из-за разрешений ОС; junction проверен. Настоящий NTFS ACL denial, физический ENOSPC и аппаратное отключение питания не выполнялись.
- SIGINT/SIGTERM предусмотрены, интеграция проверяет отмену токеном/таймером; ручной Ctrl+C не подтверждён. Синхронный вызов ОС может задержать отмену.
- EICAR/вредоносные образцы не скачивались/не создавались/не запускались. Рабочие digest сверены с метаданными; реальный байтовый контроль доказан безопасными фикстурами через тот же модуль.
- Нет независимого подтверждения вредоносности каждой строки агрегатора, оценки ложных срабатываний/полноты, распаковки архивов, ADS, службы и последующих этапов. Предел 200000/2048 со всеми максимальными длинами отдельно не нагружался.

## Исторические отчёты

Ниже сохранены прежние сведения 19–20.10.2026 для истории. Их старые лимиты, статусы и числа не описывают новую поставку и не используются как доказательство актуальных требований.

# Проверка исправлений аудита — 19.10.2026

Доказательства проверки от 19.10.2026 находятся в **build/audit-fixes**. Материалы **build/audit-current** и историческая запись ниже не использовались как доказательство тех исправлений. На тот момент проверены сборки Windows 11 x64, MSVC 19.44, Qt 6.8.3/QSQLITE 3.49.1, CMake 3.31.6; Linux не запускался. Пользовательские базы и глобальные настройки ОС не менялись.

## Воспроизведение и исправления

Перед изменением поведения добавлены и запущены регрессионные тесты: исходный audit-набор дал 80 failures; интеграционные проверки получили прежние ошибочные коды 1 (разбор аргументов) и 0 (matches="not-a-number"); GUI-тест подтвердил потерю причины в том же tick. Исходные текстовые отчёты ядра/GUI сохранены как `baseline-audit.txt`, `baseline-gui.txt`. После исправлений эти сценарии проходят; дополнительные проверки охватывают все обязательные сериализуемые поля.

| Пункт | Исправление и новая проверка |
| --- | --- |
| P1 | `model.cpp`: обязательные поля/типы, десятичные строки и qint64 без молчаливого 0, диапазоны и логические сочетания. `database.cpp`: явная ошибка JSON, сверка Job со строками в одном read-only снимке, последовательное чтение без кеширования всех строк Qt. AuditTests проверяет нечисловые/отсутствующие/отрицательные/переполненные счётчики, неправильные типы всех полей, состояния, полноту, сведения о совпадении, размер −1 у not_checked, отмену и INT64_MAX без переполнения. Проверены несогласованная численно допустимая сводка, чужой id, повреждённая страница/JSON-массив и восстановление правильных данных. Integration::corruptedHistoryReturnsError воспроизводит ровно пять совпадений → порча matches → --last/type=error/код 2; затем восстановление → код 1; затем порча completeness результата → код 2. |
| P2 CLI | `cli.cpp`: parse вместо process, общая диагностика. Integration::argumentErrorsAndHelp запускает --json --unknown-option, --json --path, --unknown-option --json: код 2 и корректный JSON; обычная ошибка имеет stderr/код 2; --help имеет stdout/код 0. |
| P2 GUI | `mainwindow.cpp/.h`: отдельное постоянное сообщение первой ошибки истории, признак запроса остановки по этой причине, без автоматической лавины повторов. GuiTests::historyReadFailureDuringScanStaysVisible удерживает реальное задание promise-барьером, завершает настоящее ошибочное чтение отдельной повреждённой тестовой базы перед tick, проверяет сообщение одновременно с прогрессом и после отмены, затем успешный новый запуск очищает ошибку. Пользовательская отмена отдельно проверена без сообщения об ошибке. SQL в GUI не добавлен. |
| P3 | `scanner.cpp`: фактическая глубина хранится в кадре обхода, вычисляется до удаления родителя; корень 0, допустимы 0..256, каталог 257 сохраняется как depth_limit и не прерывает другие ветви. AuditTests::singleChildDepthIsIndependentOfIterators проверяет глубины 0..8 и соседнюю ветвь по наблюдению границы обхода. AuditTests::traversalDepthBoundary создаёт цепочку 257, проверяет файл на уровне 256, ошибку уровня 257 и доступную соседнюю ветвь — **в текущей Windows-среде пропущен** на предварительной проверке создания длинного пути. Это не считается успешной проверкой полной границы. |

## Реальные команды текущей проверки

Из корня проекта, с разрешением запуска MSVC/тестов вне песочницы:

```powershell
./.tools/python/cmake/data/bin/cmake.exe -S . -B build/audit-fixes -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$PWD/.tools/qt/6.8.3/msvc2022_64"
./.tools/python/cmake/data/bin/cmake.exe --build build/audit-fixes --config Debug --parallel 4
$env:PATH = "$PWD/.tools/qt/6.8.3/msvc2022_64/bin;$env:PATH"
# Целевые проверки сначала выполнялись до исправлений, затем после них:
Push-Location build/audit-fixes
./Debug/resheto-audit-tests.exe -o targeted-audit.txt,txt
./Debug/resheto-integration.exe ./Debug/resheto-cli.exe ./Debug/resheto-prepare.exe ../../data/demo_signatures.json argumentErrorsAndHelp corruptedHistoryReturnsError
./Debug/resheto-gui-tests.exe historyReadFailureDuringScanStaysVisible -platform offscreen -o targeted-gui.txt,txt
Pop-Location
# После целевых проверок — сборки и полный прогон:
./.tools/python/cmake/data/bin/cmake.exe --build build/audit-fixes --config Debug --parallel 4
./.tools/python/cmake/data/bin/cmake.exe --build build/audit-fixes --config Release --parallel 4
./.tools/python/cmake/data/bin/ctest.exe --test-dir build/audit-fixes -C Debug --output-on-failure --output-log build/audit-fixes/final-debug.log
./.tools/python/cmake/data/bin/ctest.exe --test-dir build/audit-fixes -C Release --output-on-failure --output-log build/audit-fixes/final-release.log
./scripts/demo.ps1 -Bin build/audit-fixes/Release -Output build/audit-fixes/demo-current
```

Итог: **Debug 4/4 CTest, Release 4/4 CTest**, проваленных наборов нет. Последние QtTest-отчёты в каталоге build/audit-fixes: `audit-results.txt` — **84 passed / 0 failed / 1 skipped**; `core-results.txt` — **38 / 0 / 1**; `cli-results.txt` — **7 / 0 / 0**; `gui-results.txt` — **4 / 0 / 0**. Числа QtTest включают init/cleanup и строки параметризованных проверок. Итоги обеих конфигураций сохранены отдельно в `final-debug.log`, `final-release.log`; текстовые отчёты наборов соответствуют последнему Release-прогону.

Сквозные сценарии повторены свежими дочерними CLI-процессами на собственных данных:

- каталог/обнаружения/отсутствие совпадения/отмена/повторное открытие — fixtureScanAndReplay и demo.ps1; сканирование 11 файлов даёт 5 совпадений, повторный --last идентичен;
- отказ одного файла — lockedFileDoesNotStopDirectory держит настоящий Windows handle с несовместимым sharing: 11 остальных файлов проверены, 5 совпадений, 1 ошибка и код 2;
- повреждённые сигнатуры — corruptedSignatureDatabase: сначала неправильный manifest, затем верный manifest физически повреждённого SQLite, в обоих случаях код 2;
- повреждённая история — corruptedHistoryReturnsError и AuditTests: явный отказ чтения/код 2, без вывода ложного успешного задания;
- управляемая отмена чтения/поиска, подмена файла, отказ записи и продолжение после ошибки каталога — заново пройденный core-набор, не старые отчёты.

## Пропуски и оставшиеся ограничения текущей проверки

Два явно указанных пропуска: обычный Windows symlink не разрешён ОС; фактическая граница глубины 256/257 недоступна через используемые API из-за длины пути. Реальные junction-цикл и sharing violation прошли. Глобальные настройки длинных путей и защиты не менялись. Проверки Linux, Windows 10, NTFS ACL, ручной Ctrl+C и нативный ручной GUI-сеанс не выполнялись; GUI проверен QtTest/offscreen. Для Linux оставшаяся команда из README — сборка release и `ctest --preset release`; в частности необходимо выполнить traversalDepthBoundary на поддерживающей эти пути файловой системе. В программе не добавлялись служба, IPC или этапы 4–6.

Строгое чтение выявляет структурные/логические повреждения, но не подтверждает криптографическую подлинность истории и не сверяет все поля отдельных таблиц Detection/events. Проверка сводки требует O(числа результатов задания) времени с ограниченной памятью и read-only транзакцией. Отмена ядра после ошибки истории сохраняется как cancelled; отдельная причина остаётся в текущем GUI до нового сканирования, но не добавляет нового вида задания/схемы. Ранее указанные ограничения файлового анализа сохраняются.

---

# Предыдущая проверка первоначальной реализации — историческая запись

Этот раздел описывает предыдущую работу; он не является доказательством исправлений аудита. Новые команды и результаты приведены выше.

## Среда и команды

Windows 11 x64 (Windows SDK 10.0.26100, host 10.0.26200), MSVC 19.44.35228, CMake 3.31.6, Qt 6.8.3 msvc2022_64, QSQLITE/SQLite **3.49.1** (версия получена запросом из теста). Qt SDK установлен в `.tools/qt`, инструменты подготовки — в `.tools/python`; системные настройки защиты не менялись. При первоначальном запуске MSBuild внутри песочницы работа остановилась до компиляции; сборка и окончательные проверки выполнены с разрешением вне песочницы. Рабочие/временные данные — только внутри проекта или временных тестовых подкаталогов сборки.

Реально выполненные команды из корня проекта:

```powershell
python -m pip install --target .tools/python aqtinstall==3.3.0 cmake==3.31.6 ninja==1.11.1.4
$env:PYTHONPATH = "$PWD/.tools/python"
python -m aqt install-qt windows desktop 6.8.3 win64_msvc2022_64 -O .tools/qt --archives qtbase
./.tools/python/cmake/data/bin/cmake.exe -S . -B build/core -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$PWD/.tools/qt/6.8.3/msvc2022_64" -DRESHETO_BUILD_GUI=OFF
./.tools/python/cmake/data/bin/cmake.exe --build build/core --config Debug --parallel 4
# Сначала прошли core и cli; после этого добавлен GUI:
./.tools/python/cmake/data/bin/cmake.exe -S . -B build/core -DRESHETO_BUILD_GUI=ON
./.tools/python/cmake/data/bin/cmake.exe --build build/core --config Debug --parallel 4
# Release был сконфигурирован в новом пустом каталоге:
./.tools/python/cmake/data/bin/cmake.exe -S . -B build/release-clean -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$PWD/.tools/qt/6.8.3/msvc2022_64"
./.tools/python/cmake/data/bin/cmake.exe --build build/release-clean --config Release --parallel 4
$env:PATH = "$PWD/.tools/qt/6.8.3/msvc2022_64/bin;$env:PATH"
./.tools/python/cmake/data/bin/ctest.exe --test-dir build/core -C Debug --output-on-failure
./.tools/python/cmake/data/bin/ctest.exe --test-dir build/release-clean -C Release --output-on-failure
./scripts/demo.ps1 -Bin build/release-clean/Release -Output demo-run
./scripts/demo.ps1 -Bin build/release-clean/Release -Output build/demo-final
```

## Итог тестов

Итоговый Debug: **3/3 CTest**, Release: **3/3 CTest**, без проваленных наборов. В каждом итоговом наборе ядра QtTest: **38 passed, 0 failed, 1 skipped** (включая init/cleanup и строки параметризованных проверок). CLI: 3 passed; GUI: 3 passed. Пропущен только `nativeLinks`: Windows не разрешила создание обычного symlink и после выхода из песочницы. Его нельзя считать пройденным. `nativeJunctionCycle` и `nativeSharingDenied` реально прошли вне песочницы.

Подробные текстовые отчёты генерируются CTest в каталоге сборки: `core-results.txt`, `cli-results.txt`, `gui-results.txt`; сводный — `Testing/Temporary/LastTest.log`. `gui-preview.png` — снимок самого Qt Widgets окна из GUI-теста, визуально просмотрен: русские строки читаются, элементы помещаются, состояния и результаты видны. Это in-process проверка QtTest с `offscreen`, **не утверждение о выполненном человеком ручном показе в отдельном графическом сеансе**. Ручной сценарий подготовлен в lab3_demo.md. Qt offscreen предупреждает об отсутствии штатного каталога шрифтов/propagateSizeHints; тест явно загружает системный Segoe UI, снимок читаем. Нативная платформа qwindows этим предупреждением не проверяется.

| Требование | Выполненная проверка и результат |
| --- | --- |
| SHA-256 и один изменённый байт | Реальные бинарные байты, исходный HASH совпал, изменённый нет |
| Точный PATTERN/маска | Нули внутри шаблона; похожий и значимо изменённый байт не совпадают; игнорируемый отличается |
| Блоки/длина | Шаблон 9000 байт при блоке 4096 найден с позиции 4094, изменение внутри отменяет совпадение; демонстрационный переход 65534→65536 |
| Offset/размер/конец | Фиксированная позиция и min=max соблюдаются, сдвиг/иной размер/короткий конец не совпадают |
| Пустой/большой | Пустой файл full/no_match; 12 МиБ прочитаны 3072 блоками по 4096 без загрузки целиком |
| Обход/Unicode | Вложенные каталоги и пути с пробелами/кириллицей, рекурсивный и нерекурсивный режим, учёт пропусков |
| Ссылки/цикл | Реальный junction указывает на родителя, проверен один обычный файл и один пропуск, без цикла; обычный symlink — SKIP |
| Ошибки | Внедрённый отказ чтения файла и каталога, остальные файлы проверяются; исчезновение и отсутствующий путь видны |
| Реальный отказ ОС | CreateFile с несовместимым sharing блокирует чтение: not_checked/file_io; настоящий отказ NTFS ACL отдельно **не проверен** |
| Изменение/подмена | afterBlock синхронно дописывает файл либо переименовывает открытый и создаёт новый по прежнему пути; not_checked/changed, без случайных задержек |
| Отмена | Отмена при чтении второго файла оставляет первый результат, останавливает обход; matcher отменяется во время длинных сравнений; отмена до обхода даёт cancelled |
| База | Несовместимая/отсутствующая таблица, неверный digest/hex/offset/маска, all-zero mask, дубликат id, повреждённый SQLite, неверная checksum, нет enabled; отклонены |
| Снимок | База/manifest изменяются из afterBlock уже начатого задания: старый результат/версия; следующее задание читает новое имя/версию |
| Хранение | Повторное открытие результатов/Detection/событий; SQLite trigger RAISE(FAIL) при записи: failed, checked не увеличен; недоступный родитель storage даёт ошибку |
| Защита баз/лимиты | Одинаковые storage/signatures отклонены до изменения; Store не инициализирует чужую базу; блоки вне диапазона отклонены |
| Очередь | Управляемо заблокированный рабочий поток, один ожидающий запрос принят, следующий отклонён; отмена обоих |
| CLI | Дочерние процессы prepare/cli; сверка каждого файла с expected.json, JSON/exit 0/1/2/3, полное совпадение вывода с повторно прочитанным |
| GUI | Кнопка запуска вызывает настоящее ядро; 205 сохранённых файлов, 200+5 строк без потерь; event-loop таймер срабатывает; отмена, история после пересоздания окна, ошибка готовности базы |

## Демонстрация и сохранение

`scripts/demo.ps1` прошёл оба запуска: в `demo-run` и `build/demo-final`. Итог полного сканирования — **11 проверенных файлов, 5 совпадений, 0 ошибок**. Повторное чтение `--last` даёт побайтово тот же JSONL после одинаковой записи PowerShell; скрипт проверяет SHA-256 обоих выводов. Отдельно подтверждены empty/no_match (код 0), missing/not_checked (код 2), предварительная отмена (код 3). После этих четырёх заданий SQLite содержит **4 задания, 13 результатов, 5 Detection и 14 событий**; количества дополнительно прочитаны из базы. Содержимое фикстур в events отсутствует.

## Найденное и исправленное

Первый запуск тестов не мог записать фикстуры в стандартный временный путь среды: тесты переведены на уникальные QTemporaryDir внутри каталога сборки с автоматическим удалением. В первом offscreen-снимке отсутствовал шрифт: тест рендера явно загружает Segoe UI. Release-прогон выявил конфликт DDL и записи сканера при чтении истории: введено настоящее read-only открытие читателей и инициализация схемы только для новой базы; повторные Debug/Release прошли, GUI получает все 205 результатов. Нормализованы Windows-разделители путей, чтобы служебные SQLite sidecars исключались и при изменении их наличия. Проваленные промежуточные запуски не считаются успешными проверками.

## Непроверенное и границы выводов

Ubuntu 22.04, Windows 10, иные версии Qt, перенос на машину без SDK и нативный ручной показ человеком не выполнялись. Команды оставшейся проверки находятся в README и lab3_demo.md; Linux-адаптер написан, но на Windows не компилируется/не исполняется. Не проверен настоящий NTFS ACL denial; для ошибок чтения/каталога использованы управляемые инъекции, дополнительно проверен настоящий sharing violation. SIGINT/SIGTERM кодом поддержаны, интеграционный тест отменяет таймером, ручной Ctrl+C не проверен. EICAR не создавался/не скачивался; отдельная инструкция в eicar_manual.md. Архивы, альтернативные потоки, эвристика, служба, сеть и карантин отсутствуют по границе этапа. Контроль идентичности выявляет наблюдаемые изменения, не обеспечивает атомарный снимок и не доказывает безопасность файлов. Производительность и точность антивируса не оценивались.

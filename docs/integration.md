# Подключение модулей Решета

`Resheto::Core` объединяет сигнатурный анализ, статическую эвристику и наблюдение через `MonitorRuntime`. Пример `examples/consumer` использует сигнатурный анализ, а `examples/lab4_consumer` также вызывает эвристику и наблюдение.

Публичная цель — `Resheto::Core` (реализация `resheto_core`), заголовок `<core/api.h>`. C++20, Qt 6.2–6.x Core/Sql, Threads и QSQLITE. Совместимость исходного API — в пределах этой версии; произвольный бинарный ABI между компиляторами не обещается. Установочный CMake package пока не предоставляется: используется `add_subdirectory`.

```cmake
set(RESHETO_BUILD_GUI OFF CACHE BOOL "" FORCE)
set(RESHETO_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(RESHETO_BUILD_NETWORK OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory(path/to/Resheto resheto)
target_link_libraries(my_dispatcher PRIVATE Resheto::Core)
```

Создайте один `QCoreApplication` до использования библиотеки. Нужен плагин `sqldrivers/qsqlite` той же сборки Qt, Qt Core/Sql DLL и MSVC runtime. Widgets, графический сеанс, Qt Test и утилита подготовки потребителю не нужны. При статической сборке Qt требуется отдельная настройка импорта плагина; здесь проверена динамическая Qt.

```cpp
#include <core/api.h>
resheto::Request request;
request.path = inputPath;                 // файл или каталог
request.signaturePath = selectionPath;    // *.db + *.db.sha256 либо current.json
request.storagePath = storagePath;        // отдельная SQLite, родитель уже существует
request.recursive = true;
auto token = request.cancel;              // shared_ptr<atomic_bool>, не null
auto job = resheto::runJob(request, [](const resheto::Job &progress) {
    // Вызывается в потоке runJob; только короткая обработка/передача состояния.
});
// Из другого потока: token->store(true).
resheto::Store history(storagePath, true);
auto restored = history.latest();         // строгая сверка сводки со всеми строками
resheto::ResultQuery query;
query.filter = resheto::ResultFilter::Matches;
auto page = history.query(job.id, query);
```

`runJob` синхронен; вызывающий диспетчер выбирает поток. `Controller` — готовая оболочка: один рабочий поток, один ожидающий запрос, `submit`, `cancel`, `busy`, `progress`; деструктор отменяет и присоединяет поток. Callback не обращается к Widgets. `Request` владеет токеном, каждый запуск `runJob` загружает и проверяет новый неизменяемый снимок. `scanFile` — низкоуровневый синхронный вызов, требует `request.snapshot=loadSignatures(...)` и корректный токен; он не сохраняет результат. `runJob` сохраняет результаты и события. `Result::basis` и поля сигнатуры объясняют одно выбранное совпадение.

`Store` и `Database` не копируются, SQLite-соединение создаётся/уничтожается в одном использующем потоке. Не передавайте объект между потоками. Ошибки подготовки/чтения истории выбрасывают `Error` с русским `message`; `runJob` возвращает failed Job, ошибки объектов остаются строками not_checked. Приоритет `Job::exitCode`: ошибка 2 > отмена 3 > совпадение 1 > отсутствие совпадений 0.

`Store::page` сохраняет прежний последовательный API. `query` фильтрует весь job до LIMIT/OFFSET, возвращает `total` и `upperRow`. Передавайте неизменный `upperRow` следующим страницам одного представления; изменили фильтр/сортировку — начинайте с offset=0. При равных ключах дополнительный порядок row_id. Прежний `query.path` — буквальная подстрока Unicode с учётом регистра; `%`/`_` не wildcard. Новый `query.text` ищет по пути, основанию, имени/id правила/сигнатуры, причине и PID связанного process event; SQLite lower нормализует регистр ASCII, полного Unicode case folding не заявляем. `query.object` выбирает All, Manual (без события), Files (файловое событие), Processes (файл процесса либо поведение). SQL остаётся в библиотеке.

`jobs(offset,limit)` возвращает до200 заголовков (обычно50), начиная с новых. `getJob(id)` строго проверяет выбранное задание, все его результаты, Detection и process_image связи; `latest()` использует ту же проверку. Для известного собственного активного задания допустим `getJob(id,false)`: он оставляет running. По умолчанию неподтверждённый running восстанавливается как failed с причиной. Отдельные потоки создают свои Store; подготовка схемы сериализована коротким process-local mutex до открытия SQLite, обычные операции имеют busy timeout3с и короткие транзакции.

## Независимый потребитель

`examples/consumer` — самостоятельный CMake-проект. Он не включает внутренние cpp, не запускает CLI, не требует Qt Test/Widgets и не создаёт базу при сканировании. Входные контрольные данные готовятся отдельно:

```powershell
./build/windows/Release/resheto-prepare.exe --source data/demo_signatures.json --output build/consumer-control
cmake -S examples/consumer -B build/consumer -G "Visual Studio 17 2022" -A x64 -DRESHETO_SOURCE="$PWD" -DCMAKE_PREFIX_PATH="$env:QT_ROOT" -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Widgets=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Test=TRUE
cmake --build build/consumer --config Release --parallel 4
./build/consumer/Release/consumer.exe build/consumer-control/signatures.db build/consumer-control/fixtures/hash.bin build/consumer-control/fixtures/empty build/consumer/results.db
```

Код 0 потребителя подтверждает реальное обнаружение безопасных байтов, отсутствие совпадения, ошибку отсутствующего объекта, предварительную отмену и чтение обнаружения после повторного открытия. Данные берутся из аргументов. Сам генератор не является частью его зависимости. На Linux аналогично, с Ninja и исполняемым файлом без `.exe`; эта платформа в текущей работе не проверена.

Будущий диспетчер службы должен передать пути, токен и адаптер прогресса этому же API. Привилегии, IPC и жизненный цикл службы здесь не реализуются. Смена рабочей поставки не требует пересборки анализатора.

Для нового вложенного пути истории можно явно вызвать `Store::preparePath(path)` до `runJob`: он возвращает абсолютный путь и создаёт родительский каталог, не открывая и не переписывая саму БД. GUI использует этот метод. Конструктор Store и CLI сохраняют прежнее требование существующего родителя. Отказ создания каталога/открытия содержит путь и русское объяснение.

## Эвристика и наблюдение

```cpp
request.heuristicPath = heuristicJson; // явное включение PE/ELF
auto result = resheto::runJob(request);

resheto::MonitorRequest config;
config.directory = selectedDirectory;
config.signaturePath = signatureDatabase;
config.heuristicPath = heuristicJson;
config.behaviorPath = behaviorJson;
config.processImageDirectory = controlledProcessDirectory;
config.storagePath = writableHistory;
resheto::MonitorRuntime runtime;
runtime.start(config);                // подготовка и работа асинхронны
auto status = runtime.status();       // потокобезопасная копия, ready/active/state/reason/coverage/job
auto processes = runtime.processes(); // PID, PPID, время старта и образ доступных процессов
runtime.cancel();
runtime.wait();                       // вне GUI: дождаться завершения двух потоков
```

Объект Runtime владеет двумя потоками и живёт до остановки; его деструктор отменяет и присоединяет их. `start` возвращает false, если сессия ещё активна; ошибки параметров выбрасывают Error. Асинхронные ошибки отражаются в status и доступной истории. Обычная остановка — cancelled/код3, ошибка/неполнота имеют приоритет2. Наблюдение прекращается вместе с приложением. Controller/runJob и Runtime работают одновременно, с разными Job/progress/cancel и отдельными SQLite-соединениями. GUI фиксирует общий путь истории/правил на время активных операций, не меняет выбранную историю при обновлении фонового progress.

Новые поля MonitorRequest добавлены в конец структуры, сохраняя порядок прежних aggregate-полей:

```cpp
resheto::MonitorRequest watch;
watch.directory = watchedDirectory;
watch.files = true;                       // реальные create/modify выбранного дерева
watch.processes = true;                   // lifecycle и подключённые behavior-правила
watch.processImageDirectory = programs;   // область и видимого списка, и анализа
watch.scanProcessImages = true;           // отдельный opt-in файлового маршрута
watch.signaturePath = signatureDatabase;
watch.heuristicPath = staticRules;
watch.behaviorPath = behaviorRules;
watch.storagePath = historyPath;
resheto::MonitorRuntime runtime;
runtime.start(watch);
// В другом рабочем потоке допустим runJob(request) с той же историей.
// request.cancel отменяет только runJob; runtime.cancel() — только наблюдение.
```

Для процессного режима без файловых событий задайте files=false; для файлового без процессов — processes=false и scanProcessImages=false. Проверка образов допускается без behaviorPath. В сессии каждый scoped PID+start проверяется один раз, включая уже существующие процессы; статус processImages — число сохранённых результатов этой проверки, включая ошибки. Через `observation(jobId,result.eventId)` для type=process_image доступны process.pid/start_time/image. Сам Result описывает файл (его size и identity), а не память процесса; при исчезновении/смене процесса связь становится partial/not_checked с причиной. `processes()` возвращает scoped метаданные, сами по себе они не означают проверку файла.

Прежний process-only вызов с пустым directory и processes=true автоматически нормализуется в files=false; прежний CLI с --behavior/--process-scope без --path сохраняется. GUI отдельно проверяет путь, если пользователь явно включил файловый источник.

`FileMonitor`, `processSnapshot`, `ProcessTracker`, `BehaviorAnalyzer` доступны отдельно. После сохранения обнаружения контроллер вызывает `acknowledge`. Анализатор применяет одни и те же правила к событиям ОС и к заранее подготовленным событиям. Правила остаются неизменными до конца задания.

`Result::formatVersion=2` сериализует явную schema_version; source/outcome/details и rulesVersion отличают эвристику от поведения. `Job::behaviorVersion` связывает поведенческий набор отдельно от статического. `isDetection`/`detectionName` работают со всеми видами. `Store::query` фильтрует все обнаружения и partial; `observation(jobId,eventId)` возвращает связанное событие. Read-only v1-история читается без миграции, запись мигрирует1/2→3, старые payload сохраняются.

Новый потребитель вызывает статику, ошибку, предварительную отмену, настоящий create/modify, параллельный manual в той же истории, проверку файла собственного уже запущенного процесса, остановку и повторное чтение выбранных заданий через C++ API:

```powershell
$bin='./build/windows/Release'
& "$bin/resheto-lab4-prepare.exe" --output build/lab4-consumer-input --heuristics data/heuristic_rules.json --behavior data/behavior_rules.json
cmake -S examples/lab4_consumer -B build/lab4-consumer -G "Visual Studio 17 2022" -A x64 -DRESHETO_SOURCE="$PWD" -DCMAKE_PREFIX_PATH="$env:QT_ROOT" -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Widgets=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Test=TRUE
cmake --build build/lab4-consumer --config Release --parallel 1 -- /nr:false
./build/lab4-consumer/Release/lab4-consumer.exe distribution/working/current.json build/lab4-consumer-input/heuristic_rules.json build/lab4-consumer-input/fixtures/positive.exe build/lab4-consumer-input/fixtures/negative.exe build/lab4-consumer-run
```

Входной и выходной каталоги должны быть новыми. Код0 потребителя означает прохождение его проверок, хотя проверяемые им операции ожидаемо возвращают1/2/3. Он не запускает CLI/генератор и не требует Widgets/Test; подготовка входов выполняется до вызова.

### Показ файлов и процессов

На Windows запустите `./scripts/start.ps1 -Lab4 -Directory build/live-files-new` из корня проекта. Скрипт откроет GUI с собственной историей, подготовит безопасные файлы и задаст области наблюдения.

1. В «Параметрах проверки и наблюдения» включите «Наблюдать файлы», «Наблюдать процессы» и «Проверять файлы процессов». Нажмите «Начать наблюдение» и дождитесь запуска.
2. Скопируйте `negative.exe` из `build/live-files-new/lab4/fixtures` в соседний каталог `watched`. Дождитесь результата во вкладке «Файловое наблюдение». Затем замените содержимое копией `positive.exe` под тем же именем. Появится эвристическое обнаружение. Одновременно можно вручную проверить `positive.elf` из `fixtures`.
3. Запустите подготовленный помощник из каталога `processes` двумя отдельными командами.

```powershell
$helper='./build/live-files-new/lab4/processes/resheto-safe-helper.exe'
& $helper --children 1 --hold-ms 6000
& $helper --children 3 --hold-ms 6000
```

Во вкладке «Процессы» срабатывание `child-process-burst` появится после трёх дочерних процессов одного родителя за пять секунд. В подробностях есть PID и события. История остаётся доступна после остановки наблюдения. Автоматический вариант с открытием результатов выполняется через `./scripts/lab4-demo.ps1 -Output build/show-files-new -OpenGui`.

## Сетевой API

Цель `Resheto::Network` и заголовок `<network/api.h>` доступны с C++20 и Qt 6.2+. Сетевая цель использует Core и Qt Network. Включайте её явно при сборке без GUI.

```cmake
set(RESHETO_BUILD_GUI OFF CACHE BOOL "" FORCE)
set(RESHETO_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(RESHETO_BUILD_NETWORK ON CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory(path/to/Resheto resheto)
target_compile_features(my_analyzer PRIVATE cxx_std_20)
target_link_libraries(my_analyzer PRIVATE Resheto::Network)
```

Создайте `QCoreApplication` до первого вызова. Синхронный `scanNetworkPcap` напрямую вызывает библиотеку. Он разбирает пакеты, применяет правила и сохраняет результат на потоке вызова. Ошибки входа или открытия хранилища могут выбросить `resheto::Error`. Ошибки разбора после старта задания сохраняются в `NetworkJob` с причиной и кодом 2.

```cpp
#include <network/api.h>

using namespace resheto::network;
NetworkRequest request;
request.analysis.input = pcapPath;
request.analysis.durationMs = 0; // До конца PCAP.
request.rulesPath = rulesPath;
request.storagePath = sqlitePath;
std::atomic_bool cancel = false;
const auto job = scanNetworkPcap(request, &cancel);

NetworkStore history(sqlitePath, true);
const auto saved = history.getJob(job.id);
NetworkQuery query;
query.matchesOnly = true;
const auto page = history.flows(job.id, query);
```

Для живого захвата соберите `resheto-network-worker` вместе с GUI или с `RESHETO_BUILD_TOOLS=ON`. Задайте `analysis.source="live"`, ID интерфейса в `analysis.input` и путь к worker в `workerPath`. `durationMs = 0` означает захват до `cancel()`, значения 100–3 600 000 задают автоостановку в миллисекундах. При необходимости заполните `analysis.capture.tcpPorts` списком до 64 уникальных портов. `NetworkSession::submit` вызывается с потока владельца. `busy`, `progress` и `cancel` доступны из других потоков. Контроллер проверяет сообщения worker и сохраняет историю в собственном потоке. Деструктор `NetworkSession` останавливает и присоединяет поток.

У `resheto-network --interface` прежнее значение по умолчанию составляет 30 000 мс. Явный `--duration-ms 0` отключает автоостановку. Для ограниченного запуска CLI можно добавить `--cancel-after-ms 32000`, чтобы сессия получила штатную команду остановки и записала итог. В GUI «Сетевой интерфейс» сразу предлагает «До остановки», а «Локальный показ» начинает с 30 с.

Список устройств возвращает `resheto-network-worker --interfaces` в JSON. Для анализа собственного трафика на loopback есть готовый помощник и кнопки во вкладке «Сеть». `NetworkStore::getJob` проверяет задание, снимок правил, счётчики и связи с потоками. `flows` и `detections` ищут по всей выборке до ограничения страницы. У них раздельные результаты и счётчик `total`. Каждое SQLite-соединение создаётся и закрывается в своём потоке.

Внешний потребитель выполняет проверки парсера, обнаружения, ошибки, отмены после записанного батча и повторного чтения. Без параметров он использует собственные временные файлы. Отдельный режим `--profile` измеряет прямой вызов на 100 000 пакетах с записью и строгим повторным чтением истории.

```powershell
cmake -S examples/network_consumer -B build/network-consumer -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$env:QT_ROOT" -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Widgets=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Test=TRUE
cmake --build build/network-consumer --config Release
& './build/network-consumer/Release/resheto-network-consumer.exe'
```

### Сетевые правила

Штатный набор `data/network_rules.json` версии `2026.11.05-1` описывает три сценария.

| Правило | Условие | Пауза между срабатываниями |
| --- | --- | --- |
| `tcp-port-sweep` | Попытки с одного IP на 20 разных TCP-портов другого IP за 10 с | 30 с для пары адресов |
| `periodic-tcp-attempts` | 6 попыток с одного IP к одному IP и порту за 60 с. Средний интервал от 1 до 10 с, каждый интервал отклоняется от среднего не более чем на 10% | 60 с для пары адресов и порта |
| `dns-nxdomain-burst` | Один клиент получил ответы NXDOMAIN для 20 разных имён за 30 с. Учитывается обычный DNS на UDP-порту 53 | 30 с для клиента |

TCP-правила учитывают первые SYN без ACK и отбрасывают повторную отправку того же SYN. Для каждого обнаружения сохраняются правило, его версия, основание и события из окна. В «Локальном показе» можно воспроизвести оба TCP-сценария на собственных портах, а контрольный PCAP включает все три.

### Linux и права захвата

Linux-адаптер связывается с системной libpcap 1.10+ через `pkg-config`. На Windows тот же интерфейс использует Npcap, загруженный из системного каталога. Форматы PCAP, правила, IPC и SQLite-история общие. На Linux нужны разработческие заголовки libpcap при сборке и соответствующая библиотека при запуске.

```bash
pkg-config --modversion libpcap
cmake --preset release -DRESHETO_BUILD_NETWORK=ON
cmake --build --preset release
ctest --preset release -R '^network(-runtime|-gui)?$' --output-on-failure
cmake -S examples/network_consumer -B build/network-consumer-linux -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Widgets=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Test=TRUE
cmake --build build/network-consumer-linux
./build/network-consumer-linux/resheto-network-consumer
./build/release/resheto-network-prepare --output build/linux-pcap-new --rules data/network_rules.json
./build/release/resheto-network --pcap build/linux-pcap-new/control.pcap --rules data/network_rules.json --storage build/linux-pcap-new/history.db
./build/release/resheto --db distribution/working/current.json --heuristics data/heuristic_rules.json --behavior data/behavior_rules.json --storage build/linux-pcap-new/history.db --network-rules data/network_rules.json
```

Для живого захвата Linux может требовать `CAP_NET_RAW`. Если обычному пользователю недоступен захват, администратор может выдать право именно проверенному локальному worker после сборки. Используйте доступные системному загрузчику Qt и libpcap.

```bash
sudo setcap cap_net_raw=ep "$PWD/build/release/resheto-network-worker"
getcap "$PWD/build/release/resheto-network-worker"
./build/release/resheto-network-worker --interfaces
```

`setcap` предоставляется, например, пакетом `libcap2-bin` в Debian/Ubuntu. Сборка, приложение и тесты сами права не изменяют. После пересборки worker проверьте их заново. Доступ к захвату не нужен для PCAP и штатного CTest. Сборка и живой сетевой показ на Linux в этой итерации не подтверждены.

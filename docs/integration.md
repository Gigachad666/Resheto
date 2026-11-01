# Подключение файлового модуля

Этап4 добавляет к той же цели статическую эвристику и `MonitorRuntime`; зависимости остаются Qt Core/Sql/Threads. Старые вызовы без эвристики сохраняются. Новый независимый пример — `examples/lab4_consumer`, прежний `examples/consumer` остаётся сигнатурным.

Публичная цель — `Resheto::Core` (реализация `resheto_core`), заголовок `<core/api.h>`. C++20, Qt 6.2–6.x Core/Sql, Threads и QSQLITE. Совместимость исходного API — в пределах этой версии; произвольный бинарный ABI между компиляторами не обещается. Установочный CMake package пока не предоставляется: используется `add_subdirectory`.

```cmake
set(RESHETO_BUILD_GUI OFF CACHE BOOL "" FORCE)
set(RESHETO_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
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

`FileMonitor`, `processSnapshot`, `ProcessTracker`, `BehaviorAnalyzer` доступны отдельно. Детект поведения подтверждается `acknowledge` после commit; replay использует тот же анализатор, но не выдаётся за ОС. Снимок правил неизменяем на сессию. Ограничения и формат — [implementation.md](implementation.md).

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

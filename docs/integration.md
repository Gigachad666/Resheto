# Подключение файлового модуля

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

`Store::page` сохраняет прежний последовательный API. `query` фильтрует весь job до LIMIT/OFFSET, возвращает `total` и `upperRow`. Передавайте неизменный `upperRow` следующим страницам одного представления; изменили фильтр/сортировку — начинайте с offset=0. При равных ключах дополнительный порядок row_id. Поиск — буквальная подстрока Unicode с учётом регистра, `%`/`_` не являются wildcard. SQL остаётся в библиотеке.

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
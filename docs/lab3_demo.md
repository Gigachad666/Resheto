# Показ АС Решето: 5–7 минут

Перед показом выполните сборку/CTest из README. Все следующие файлы безопасны и создаются нашим C++ генератором. Сеть во время проверки не нужна. Для Windows команды ниже выполняются из корня проекта, Qt bin уже в PATH. Для Linux замените `build/windows/Release/*.exe` на `build/release/*`.

1. **0:00–1:00 — подготовка и границы.**

   ```powershell
   ./build/windows/Release/resheto-prepare.exe --source data/demo_signatures.json --output demo-show
   ./build/windows/Release/resheto.exe --path demo-show/fixtures --db demo-show/signatures.db --storage demo-show/resheto.db
   ```

   `demo-show` должен отсутствовать. Объясните: Qt Widgets — оболочка, общий C++ модуль анализирует и сохраняет SQLite; служба и этапы 4–6 здесь не реализованы. Состояние базы должно стать «Готова», активных сигнатур 5 (ещё одна выключена). Manifest — контроль целостности, не подпись издателя.

2. **1:00–2:15 — сканирование и обнаружения.** Нажмите «Начать» с включёнными подкаталогами. Ожидается 11 проверенных файлов, 5 совпадений, 0 ошибок. HASH: `hash.bin`; PATTERN: `exact.bin`, `masked.bin`, `fixed.bin`, `boundary.bin`. Пустой, похожие и вложенный Unicode-файл не дают совпадений. Откройте подсказку основания: boundary начинается на 65534 и заканчивается после границы блока 65536. Маска `1011` игнорирует один байт; fixed offset=17 и размер=32. Это анализ содержимого, расширение роли не играет.

3. **2:15–3:15 — CLI, JSON и сохранение.**

   ```powershell
   ./build/windows/Release/resheto-cli.exe --path demo-show/fixtures --db demo-show/signatures.db --storage demo-show/resheto.db --json
   ./build/windows/Release/resheto-cli.exe --last --storage demo-show/resheto.db --json
   ```

   Оба кода — 1. JSON Lines содержит результаты и итог задания; большие целые представлены строками. Закройте и заново откройте GUI с теми же аргументами: последнее задание/таблица восстанавливаются из SQLite. «Совпадений не обнаружено» не означает «безопасен».

4. **3:15–4:15 — обход, отсутствие совпадения и ошибка.**

   ```powershell
   ./build/windows/Release/resheto-cli.exe --path demo-show/fixtures --db demo-show/signatures.db --storage demo-show/resheto.db --non-recursive
   ./build/windows/Release/resheto-cli.exe --path demo-show/fixtures/empty --db demo-show/signatures.db --storage demo-show/resheto.db
   ./build/windows/Release/resheto-cli.exe --path demo-show/missing --db demo-show/signatures.db --storage demo-show/resheto.db
   ```

   Нерекурсивно: 10 файлов, 5 совпадений, 1 объяснимый пропуск каталога, код 1. Пустой файл: full/no_match, код 0. Отсутствующий объект: «Не проверен» с причиной, failed/код 2. Ошибка не превращается в отсутствие совпадения. Для реального отказа одного файла/изменения во время чтения покажите соответствующие строки журнала автотестов: они управляемы, не зависят от удачного тайминга.

5. **4:15–5:30 — отмена и отзывчивость.** Подготовьте заранее большой файл, чтобы не тратить время показа:

   ```powershell
   ./build/windows/Release/resheto-prepare.exe --source data/demo_signatures.json --output demo-large --large-mib 512
   ./build/windows/Release/resheto-cli.exe --path demo-large/fixtures --db demo-large/signatures.db --storage demo-large/resheto.db --cancel-after-ms 100 --json
   ./build/windows/Release/resheto-cli.exe --path demo-large/fixtures --db demo-large/signatures.db --storage demo-large/resheto.db --cancel-after-ms 0 --json
   ```

   На обычной машине первая команда сканирования успевает начать чтение; ожидается отмена, код 3. На очень быстрой машине уменьшите таймер или используйте GUI «Остановить» во время проверки `large.bin`. Второе сканирование детерминированно отменяется до обхода. В GUI выберите `demo-large/fixtures`, соответствующую базу и хранилище, нажмите «Начать», подвигайте окно/выделите строку и «Остановить». Индикатор не обещает точного процента. Проверьте состояние «Отменено» и доступность уже сохранённых строк; непосещённые файлы не выдумываются.

6. **5:30–6:30 — проверяемость и ограничения.**

   ```powershell
   ctest --test-dir build/windows -C Release --output-on-failure
   ```

   Покажите `core-results.txt`, `cli-results.txt`, `gui-results.txt` в каталоге сборки. Особо объясните: длинный шаблон может пересекать несколько блоков; файл проверяется через один открытый объект; обнаруженное изменение даёт not_checked; текущему заданию принадлежит снимок базы. Пропущенные проверки ОС нельзя выдавать за пройденные. Полный объём результатов и ограничения среды перечислены в verification.md. EICAR — отдельный ручной сценарий, не часть этого показа.

Для полностью автоматического повтора основных консольных сценариев: `./scripts/demo.ps1 -Bin build/windows/Release -Output demo-auto`. Он сохраняет JSONL и сравнивает исходный вывод с повторно прочитанным, отказывается перезаписывать каталог.

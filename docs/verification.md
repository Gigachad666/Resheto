# Доработка сценария этапа 4 — 01.11.2026

Итоговая Release-сборка успешна: Windows 11 x64, Qt 6.8.3, MSVC 2022. После последнего исправления выбора задания полный CTest прошёл **8/8 групп за 72,94 с**. В core один пропуск: ОС не разрешила создать symlink; проверка junction выполнена. Группа Windows PowerShell 5.1 запускалась вне песочницы из-за ограничения чтения политик реестра; настройки ОС не менялись. Linux в этой итерации не собирался и не запускался.

Внешний `examples/lab4_consumer` заново собран с выключенными GUI, tools и тестами и запретом поиска Qt Widgets/Qt Test. Прямой вызов библиотеки подтвердил PE-эвристику, отрицательный контроль, ошибку, отмену, реальные create/modify, ручную проверку одновременно с наблюдением, проверку файла собственного процесса и повторное чтение истории. Автоматический `scripts/lab4-demo.ps1` завершился успешно в PowerShell 7; `start.ps1 -Lab4 -NoLaunch` проверен также в Windows PowerShell 5.1.

В нативном окне выполнены параллельная ручная проверка и наблюдение в собственных временных каталогах: создание/изменение безопасного файла, проверка файлов собственных процессов, один и три дочерних процесса, сохранение результатов. При этом найдено рассогласование кнопок перехода и списка заданий. Оно исправлено; целевой GUI-тест и последующий полный CTest прошли. Повторный нативный показ после этого исправления прерван пользователем через Escape и не заявляется выполненным.

Финальные логи и контрольные суммы 64 входных файлов: `build/ux4-final-20261101-fa9322e5` — `configure.txt`, `build-after-native-fix.txt`, `ctest.txt`, `consumer-*.txt`, `demo-ps7.txt`, `start-ps51.txt`, `inputs-sha256.json`. В финальном GUI-тесте задержка уведомления после завершения анализа составила 95 мс для ручного задания и 167 мс для наблюдения; это не время анализа и не замер производительности. Рабочая база и исходные DOCX сохранены. Новых измерений памяти и производительности в этой итерации нет.

Ниже сохранены целевые проверки текущей итерации. Полный прежний отчёт с историей проверок хранится локально в `.local/archive/cleanup-2026-11-01/docs/verification-before-cleanup.md`; старые прогоны — в `build/` того же архива. Эти материалы исключены из Git. Старый сценарий `lab3_demo.md` находится в `.local/archive/lab4-2026-11-01`; актуальный показ описан в README.

## Целевые проверки разработки

Эти проверки относятся к одновременной ручной проверке/наблюдению, выбору прежних заданий и проверке файлов процессов. Они выполнены до итогового полного прогона, указанного выше.

| Проверено | Реальный результат |
| --- | --- |
| Новый Store, параллельные писатели в новую SQLite, выбор обоих Job, повреждение Detection, PID-поиск после2101 обычной строки, оба активных веса60 | lab4:11 passed,0 failed,0 skipped;11,054с |
| Живые file create/modify, прежнее поведение, existing/new PID × HASH/static image-file, раздельная область, один результат на lifetime, исчезновение процесса во время чтения, сохранённые связи после reopen | monitor:16 passed,0 failed,0 skipped;12,447с |
| Прежний process-only API с пустым directory | дополнительно legacyProcessOnlyRequest:3 passed,0 failed;90мс |
| Строгая история v1 и прежние audit-регрессии | audit:85 passed,0 failed,0 skipped;593мс (граница глубины в этом запуске реально выполнилась) |
| Прежний CLI, реальное наблюдение, legacy process-only CLI, неверные опции/code2/JSON | cli:9 passed,0 failed,0 skipped; CTest3,72с |
| Прежние GUI-сценарии и automatic history, одновременно manual+monitor в новой общей истории, обе независимые отмены, сохранение выбранного Job при новых событиях, scoped список, единый поиск/PID/основания, страницы52 Job и возврат к новым | gui:12 passed,0 failed,0 skipped;24,964с |
| Последнее уточнение processResults: видимый PID правильного родителя/образа, копирование полного пути, очистка живого списка после stop | отдельно processImageResultsAreScopedAndSearchable:3 passed,0 failed;4292мс |

Финальная целевая группа GUI+CLI прошла2/2 за28,77с. Уведомление от UTC Result.time (анализ завершён, до commit) до наблюдения видимого баннера: manual92мс, monitor154мс; время анализа/ожидания события не включено. Qt offscreen сообщает отсутствие штатного каталога шрифтов/propagateSizeHints; тест загружает SegoeUI. Это QtTest/offscreen, не самостоятельное доказательство ручного показа нативного окна. Снимки — build/windows/gui-process-preview.png и gui-parallel-preview.png.

Логи целевых запусков: build/windows/{lab4,monitor,audit,gui,cli}-results.txt, gui-ux-pid.txt, monitor-ux-legacy.txt. В промежуточном monitor-прогоне новая тестовая HASH-запись ошибочно не содержала algorithm=SHA-256; исправлена фикстура. Строгая сверка Detection.time выявила, что старый audit-тест «восстанавливал» Result с заново созданным временем: он теперь сохраняет и восстанавливает исходную строку; все прежние assert сохранены. GUI-тест выявил PPID-поиск вместо точного PID, он исправлен; проваленные промежуточные отчёты не считаются результатом.

Команды из корня проекта (PATH только текущего процесса, глобальные настройки не меняются):

```powershell
$env:PATH="$PWD/.tools/python/cmake/data/bin;$PWD/.tools/qt/6.8.3/msvc2022_64/bin;$env:PATH"
cmake --build build/windows --config Release --target resheto-monitor-tests resheto-lab4-tests resheto-gui-tests resheto-audit-tests resheto-integration resheto-cli resheto-lab4-prepare --parallel 1 -- /nr:false
ctest --test-dir build/windows -C Release -R '^(lab4|monitor|audit|cli)$' --output-on-failure
# После относящихся к ним исправлений повторены monitor/audit, затем GUI/CLI:
ctest --test-dir build/windows -C Release -R '^(monitor|audit|gui)$' --output-on-failure
ctest --test-dir build/windows -C Release -R '^(gui|cli)$' --output-on-failure
Push-Location build/windows
./Release/resheto-gui-tests.exe processImageResultsAreScopedAndSearchable -platform offscreen -o gui-ux-pid.txt,txt
./Release/resheto-monitor-tests.exe legacyProcessOnlyRequest -o monitor-ux-legacy.txt,txt
Pop-Location
```

start.ps1 -Lab4 -NoLaunch и Parser::ParseFile прошли в отдельном временном каталоге: безопасные fixtures, отдельный первоначально пустой watched и собственный helper. Данные сохранены локально в `.local/archive/cleanup-2026-11-01/build/ux4-targeted/live-prepared-20261101`. При обычном запуске GUI получает актуальные project/data JSON, даже если старый каталог fixtures переиспользуется; пользовательские копии правил не переписываются. Сам запуск -NoLaunch не является живым показом.

Узкие границы сохранены: проверяется файл процесса по доступному пути с PID+ID запуска, память не анализируется; polling не восстанавливает все действия и короткие процессы; один monitorJob содержит выбранные file/process источники, представления разделены. Новых замеров памяти/производительности этой итерацией не заявляем. Фактический пропуск итогового прогона указан в начале документа. Рабочая база и DOCX не изменялись.

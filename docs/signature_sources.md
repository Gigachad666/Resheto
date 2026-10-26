# Рабочая HASH-поставка

Источник — [Romain MARCOUX, malicious-hash](https://github.com/romainmarcoux/malicious-hash), опубликованный список `full-hash-sha256-aa.txt`. Закреплена ревизия **9e6be541abb33859f49c06d66cf7c97e54ab2bc4**, а не изменяемая ветка main. Проверены README и [MIT-лицензия этой ревизии](https://github.com/romainmarcoux/malicious-hash/blob/9e6be541abb33859f49c06d66cf7c97e54ab2bc4/LICENSE): разрешены использование, изменение и распространение с сохранением copyright/текста лицензии, без гарантии пригодности. `distribution/source/LICENSE` сохраняет Copyright (c) 2025 Romain MARCOUX. При передаче поставки сохраняйте весь `distribution`, включая лицензию и атрибуцию.

Это агрегатор опубликованных вредоносных хешей, а не собственная классификация Решето. Список не содержит семейства, времени наблюдения, размера файла и первоисточника каждого digest; эти сведения не выдумываются. `provenance` в SQLite хранит исходную строку и её номер именно в закреплённом агрегированном снимке, а manifest указывает его URL/ревизию. Список upstream-источников сохранён в `README.upstream.md`. Проверка формата и сверка с выгрузкой не является независимым подтверждением вредоносности каждого образца.

## Фактический артефакт

- Выбор версии: `distribution/working/current.json`.
- База: `distribution/working/versions/0310dd5e-5e8b-46c0-b116-ab8cf1f2265d/signatures.db`.
- Рядом: `signatures.db.sha256`, `manifest.json`, точная копия `source.txt`.
- Версия: `malicious-hash-9e6be541abb33859`.
- Исходник и лицензия: `distribution/source`; момент получения записан в provenance/manifest в UTC.
- Исходный SHA-256: `07bf75ab004da3f5f5d1b25e41a8e3544ea7b66255d27ec7536672cb1f5e3b60`.
- SHA-256 SQLite: `d2e4fff6ca3684bb41925457174fd5fe6176ac9bd05da62c8f43f9d7b4eec967`.
- **11 636 строк → 11 632 уникальных активных HASH, 4 одинаковых дубля, 0 PATTERN, 0 disabled, 0 неподдержанных алгоритмов, 0 исключённых тестовых/PUA записей.**

База HASH-only. Она не поддерживает изменённые варианты файлов и не обещает современную полноту покрытия. В импортируемом формате нет коротких масок/тестовых правил. Собственные безопасные контроли и синтетический профиль поставляются отдельно. Реальные вредоносные файлы не получались и не запускались.

SOREL-20M был отклонён: отдельные Terms and Conditions of Use для данных запрещают передачу третьим лицам, хотя код имеет Apache-лицензию. MalwareBazaar не выбран: действующие условия требуют аутентификацию и не позволяют полагаться на прежние упоминания CC0. ClamAV CVD с официального адреса в этой среде вернул HTTP 403. Эти источники не использованы в рабочей поставке.

## Получение и воспроизводимый офлайн-импорт

Из корня репозитория, PowerShell 7; в PATH — Qt bin:

```powershell
# Единственная сетевая операция, запускается явно; новый каталог:
./scripts/fetch-signatures.ps1 -Output build/source-new
# Весь следующий шаг работает офлайн; можно использовать distribution/source:
./build/final-20261025/Release/resheto-import.exe --format sha256-lines --input distribution/source/full-hash-sha256-aa.txt --provenance distribution/source/provenance.json --repository build/reproduced-working --version malicious-hash-9e6be541abb33859
# Обычный выбор рабочей базы тем же CLI:
./build/final-20261025/Release/resheto-cli.exe --path build/consumer-control/fixtures --db build/reproduced-working/current.json --storage build/reproduced-working/results.db --json
```

`fetch-signatures.ps1 -Revision <40-hex>` позволяет явно получить другую ревизию; условия новой ревизии нужно проверить заново. Обычная сборка, CTest, сканер и GUI не скачивают данные, Qt Network не используется. Существующий снимок не перезаписывается. На Ubuntu точный список можно получить `curl --fail --location` с закреплённого URL из provenance, вместе с LICENSE/README; далее тот же `resheto-import` без `.exe`. Linux-прогон отложен.

Импорт `sha256-lines`: одна hex-строка на запись, пробелы по краям/пустые строки/комментарии `#` разрешены, 64 hex — SHA-256. Валидные MD5/SHA1 (32/40 hex) считаются неподдержанными и явно подсчитываются, иная длина/hex — ошибка всего импорта. Дубли digest с теми же данными объединяются, сохраняется первое происхождение; конфликт данных отклоняет весь снимок. Нулевой итог отклоняется. Происхождение — обязательный JSON с source_url/source_revision/source_sha256/acquired_utc/license/attribution; checksum сверяется до импорта и после копирования снимка.

Дополнительно поддержан ограниченный `clamav-hsb`: `hash:size:name[:min_functional_level[:max_functional_level]]`, SHA-256 полного файла, размер — целое 0..INT64_MAX либо `*`, имена ASCII по формату ClamAV. Числа functional level валидируются, это условия версии стороннего движка, а не ограничения байтового поиска. PE section/import hashes, логические/текстовые нормализованные сигнатуры и остальные форматы ClamAV не поддержаны. Test/EICAR/PUA по имени исключаются со счётчиком. Для такого источника требуется отдельная проверка лицензии и происхождения; текущая поставка HSB не использует.

## Замена и возврат

Повторите import с тем же `--repository`, новой версией и новым снимком. Импортер берёт локальную блокировку, создаёт отдельный временный каталог, закрывает запись SQLite, записывает checksum и manifest, проверяет базу штатным загрузчиком. Затем переименовывает весь каталог в `versions/<uuid>` и публикует **один** `current.json` через QSaveFile. В нём одновременно находятся database и previous. Нет двух независимых переименований активных database/manifest. Предыдущая версия не изменяется и не удаляется.

При ошибке до переключения текущий указатель сохраняется. После сбоя публикации может остаться невыбранный проверенный каталог версии; его можно проверить/выбрать повторно. Для возврата возьмите `previous` из current.json:

```powershell
$previous=(Get-Content distribution/working/current.json -Raw | ConvertFrom-Json).previous
./build/final-20261025/Release/resheto-import.exe --repository distribution/working --activate $previous
```

У первой поставки previous пустой — возвращаться ещё не к чему. `--activate versions/<uuid>/signatures.db` сначала повторно проверяет базу. Не правьте файлы опубликованной версии на месте. Активное задание уже держит снимок в памяти; следующее читает новый указатель. Контрольная сумма проверяет целостность, не удостоверяет доверенного издателя. Атомарность относится к публикации при обычном сбое операции; гарантии сохранности при аппаратном отказе носителя/питания не заявляются.

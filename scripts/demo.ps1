param(
    [string]$Bin = 'build/windows/Release',
    [string]$Output = 'demo-run'
)
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$binaryDir = [IO.Path]::GetFullPath((Join-Path $project $Bin))
$target = [IO.Path]::GetFullPath((Join-Path $project $Output))
if (Test-Path -LiteralPath $target) { throw "Каталог уже существует: $target. Укажите новый -Output." }
& (Join-Path $binaryDir 'resheto-prepare.exe') --source (Join-Path $project 'data/demo_signatures.json') --output $target
if ($LASTEXITCODE -ne 0) { throw 'Подготовка данных завершилась ошибкой' }
$scanner = Join-Path $binaryDir 'resheto-cli.exe'
$workingSelection = Join-Path $project 'distribution/working/current.json'
& $scanner --db $workingSelection --storage (Join-Path $target 'working-results.db') --path (Join-Path $target 'fixtures') --json | Set-Content -Encoding utf8 (Join-Path $target 'working.jsonl')
if ($LASTEXITCODE -ne 0) { throw 'Рабочая база: ожидается отсутствие совпадений на собственных безопасных фикстурах' }
& $scanner --last --storage (Join-Path $target 'working-results.db') --json | Set-Content -Encoding utf8 (Join-Path $target 'working-reopened.jsonl')
if ($LASTEXITCODE -ne 0 -or (Get-FileHash (Join-Path $target 'working.jsonl')).Hash -ne (Get-FileHash (Join-Path $target 'working-reopened.jsonl')).Hash) { throw 'Ошибка повторного чтения рабочей проверки' }
$baseArgs = @('--db', (Join-Path $target 'signatures.db'), '--storage', (Join-Path $target 'resheto.db'), '--json')
& $scanner @baseArgs --path (Join-Path $target 'fixtures') | Set-Content -Encoding utf8 (Join-Path $target 'scan.jsonl')
if ($LASTEXITCODE -ne 1) { throw 'Ожидался код 1: найдены тестовые сигнатуры' }
& $scanner --last --storage (Join-Path $target 'resheto.db') --json | Set-Content -Encoding utf8 (Join-Path $target 'reopened.jsonl')
if ($LASTEXITCODE -ne 1) { throw 'Ошибка повторного чтения' }
if ((Get-FileHash -LiteralPath (Join-Path $target 'scan.jsonl')).Hash -ne (Get-FileHash -LiteralPath (Join-Path $target 'reopened.jsonl')).Hash) { throw 'Сохранённые результаты отличаются' }
& $scanner @baseArgs --path (Join-Path $target 'fixtures/empty') | Set-Content -Encoding utf8 (Join-Path $target 'no-match.jsonl')
if ($LASTEXITCODE -ne 0) { throw 'Ожидался код 0: нет совпадений' }
& $scanner @baseArgs --path (Join-Path $target 'missing') | Set-Content -Encoding utf8 (Join-Path $target 'error.jsonl')
if ($LASTEXITCODE -ne 2) { throw 'Ожидался код 2: объект отсутствует' }
& $scanner @baseArgs --path (Join-Path $target 'fixtures') --cancel-after-ms 0 | Set-Content -Encoding utf8 (Join-Path $target 'cancelled.jsonl')
if ($LASTEXITCODE -ne 3) { throw 'Ожидался код 3: отмена' }
Write-Output "Одним модулем проверены рабочая и контрольная базы, совпадения, отсутствие совпадений, ошибка, отмена, повторное чтение. Результаты: $target"

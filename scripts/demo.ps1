param(
    [string]$Bin = 'build/windows/Release',
    [string]$Output = 'build/demo'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$tools = Get-ReshetoTools $Bin
$project = $tools.Project
$binaryDir = $tools.Bin
$target = Get-ReshetoPath $Output
if (Test-Path -LiteralPath $target) { throw "Каталог уже существует: $target. Укажите новый -Output." }
$prepared = Invoke-ReshetoCommand (Join-Path $binaryDir 'resheto-prepare.exe') @('--source', (Join-Path $project 'data/demo_signatures.json'), '--output', $target)
Write-Output $prepared.Output.Trim()
$scanner = Join-Path $binaryDir 'resheto-cli.exe'
$workingSelection = Join-Path $project 'distribution/working/current.json'
$scan = Invoke-ReshetoCommand $scanner @('--db', $workingSelection, '--storage', (Join-Path $target 'working-results.db'), '--path', (Join-Path $target 'fixtures'), '--json')
Save-ReshetoUtf8 (Join-Path $target 'working.jsonl') $scan.Output
$reopened = Invoke-ReshetoCommand $scanner @('--last', '--storage', (Join-Path $target 'working-results.db'), '--json')
Save-ReshetoUtf8 (Join-Path $target 'working-reopened.jsonl') $reopened.Output
if ($scan.Output -cne $reopened.Output) { throw 'Ошибка повторного чтения рабочей проверки' }
$baseArgs = @('--db', (Join-Path $target 'signatures.db'), '--storage', (Join-Path $target 'resheto.db'), '--json')
$scan = Invoke-ReshetoCommand $scanner ($baseArgs + @('--path', (Join-Path $target 'fixtures'))) @(1)
Save-ReshetoUtf8 (Join-Path $target 'scan.jsonl') $scan.Output
$reopened = Invoke-ReshetoCommand $scanner @('--last', '--storage', (Join-Path $target 'resheto.db'), '--json') @(1)
Save-ReshetoUtf8 (Join-Path $target 'reopened.jsonl') $reopened.Output
if ($scan.Output -cne $reopened.Output) { throw 'Сохранённые результаты отличаются' }
$scan = Invoke-ReshetoCommand $scanner ($baseArgs + @('--path', (Join-Path $target 'fixtures/empty')))
Save-ReshetoUtf8 (Join-Path $target 'no-match.jsonl') $scan.Output
$scan = Invoke-ReshetoCommand $scanner ($baseArgs + @('--path', (Join-Path $target 'missing'))) @(2)
Save-ReshetoUtf8 (Join-Path $target 'error.jsonl') $scan.Output
$scan = Invoke-ReshetoCommand $scanner ($baseArgs + @('--path', (Join-Path $target 'fixtures'), '--cancel-after-ms', '0')) @(3)
Save-ReshetoUtf8 (Join-Path $target 'cancelled.jsonl') $scan.Output
Write-Output "Одним модулем проверены рабочая и контрольная базы, совпадения, отсутствие совпадений, ошибка, отмена, повторное чтение. Результаты: $target"

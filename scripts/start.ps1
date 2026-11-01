param(
    [switch]$Control,
    [switch]$Lab4,
    [string]$Bin = 'build/windows/Release',
    [switch]$NoLaunch,
    [string]$Directory = 'build/manual',
    [string]$Path = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$tools = Get-ReshetoTools $Bin
if ($Control -and $Lab4) { throw 'Выберите -Control либо -Lab4.' }
$gui = Join-Path $tools.Bin 'resheto.exe'
if (!(Test-Path -LiteralPath $gui -PathType Leaf)) { throw "Не найден GUI: $gui" }
$manual = Get-ReshetoPath $Directory
[IO.Directory]::CreateDirectory($manual) | Out-Null
$object = ''
if ($Path.Trim()) {
    $object = Get-ReshetoPath $Path
    if (!(Test-Path -LiteralPath $object)) { throw "Объект проверки не найден: $object" }
}
$signatures = Join-Path $tools.Project 'distribution/working/current.json'
$lab4Dir = ''
if ($Lab4) {
    $lab4Dir = Join-Path $manual 'lab4'
    if (!(Test-Path -LiteralPath $lab4Dir)) {
        $prepared = Invoke-ReshetoCommand (Join-Path $tools.Bin 'resheto-lab4-prepare.exe') @('--output', $lab4Dir, '--heuristics', (Join-Path $tools.Project 'data/heuristic_rules.json'), '--behavior', (Join-Path $tools.Project 'data/behavior_rules.json'))
        Write-Output $prepared.Output.Trim()
    }
    $processDir = Join-Path $lab4Dir 'processes'
    [IO.Directory]::CreateDirectory($processDir) | Out-Null
    $helper = Join-Path $processDir 'resheto-safe-helper.exe'
    if (!(Test-Path -LiteralPath $helper)) { Copy-Item -LiteralPath (Join-Path $tools.Bin 'resheto-safe-helper.exe') -Destination $helper }
    if (!$object) { $object = Join-Path $lab4Dir 'fixtures' }
    $watchDir = Join-Path $lab4Dir 'watched'
    [IO.Directory]::CreateDirectory($watchDir) | Out-Null
    Write-Output "Файловое наблюдение: $watchDir (пустая область при первой подготовке)"
    Write-Output "Безопасные файлы для копирования: $(Join-Path $lab4Dir 'fixtures')"
    Write-Output "Безопасный помощник: $helper --children 3 --hold-ms 6000"
}
if ($Control) {
    $controlDir = Join-Path $manual 'control'
    if (!(Test-Path -LiteralPath $controlDir)) {
        $prepared = Invoke-ReshetoCommand (Join-Path $tools.Bin 'resheto-prepare.exe') @('--source', (Join-Path $tools.Project 'data/demo_signatures.json'), '--output', $controlDir)
        Write-Output $prepared.Output.Trim()
    }
    if (!$object) { $object = Join-Path $controlDir 'fixtures' }
    $signatures = Join-Path $controlDir 'signatures.db'
    if (!(Test-Path -LiteralPath $object -PathType Container) -or !(Test-Path -LiteralPath $signatures -PathType Leaf)) {
        throw "Контрольный каталог неполон: $controlDir. Подготовьте данные в новом каталоге командой resheto-prepare."
    }
}
if (!(Test-Path -LiteralPath $signatures -PathType Leaf)) { throw "Не найдена выбранная база: $signatures" }
$storage = Join-Path $manual 'results.db'
Write-Output "Объект: $object"
Write-Output "Сигнатуры: $signatures"
Write-Output "История: $storage"
if (!$object) { Write-Output 'Выберите файл или каталог кнопкой в окне программы.' }
if (!$NoLaunch) {
    $guiArguments = @('--db', $signatures, '--storage', $storage)
    if ($Lab4) { $guiArguments += @('--heuristics', (Join-Path $tools.Project 'data/heuristic_rules.json'), '--behavior', (Join-Path $tools.Project 'data/behavior_rules.json'), '--process-scope', (Join-Path $lab4Dir 'processes'), '--watch-path', $watchDir) }
    if ($object) { $guiArguments += @('--path', $object) }
    Start-Process -FilePath $gui -WorkingDirectory $tools.Project -WindowStyle Normal -ArgumentList (($guiArguments | ForEach-Object { ConvertTo-ReshetoArgument $_ }) -join ' ')
}

param(
    [string]$Bin = 'build/windows/Release',
    [Parameter(Mandatory=$true)][string]$Output,
    [switch]$OpenGui
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$tools = Get-ReshetoTools $Bin
$target = Get-ReshetoPath $Output
if (Test-Path -LiteralPath $target) { throw 'Нужен новый выходной каталог.' }
$prepared = Invoke-ReshetoCommand (Join-Path $tools.Bin 'resheto-lab4-prepare.exe') @('--output', $target, '--heuristics', (Join-Path $tools.Project 'data/heuristic_rules.json'), '--behavior', (Join-Path $tools.Project 'data/behavior_rules.json'))
Write-Output $prepared.Output.Trim()
$db = Join-Path $tools.Project 'distribution/working/current.json'
$heuristics = Join-Path $target 'heuristic_rules.json'
$behavior = Join-Path $target 'behavior_rules.json'
$cli = Join-Path $tools.Bin 'resheto-cli.exe'
$baseArgs = @('--db', $db, '--heuristics', $heuristics, '--storage', (Join-Path $target 'manual.db'), '--json')
foreach ($case in @(@('positive.exe',1), @('negative.exe',0), @('positive.elf',1), @('negative.elf',0), @('renamed.txt',0), @('broken.exe',2))) {
    $result = Invoke-ReshetoCommand $cli ($baseArgs + @('--path', (Join-Path $target ('fixtures/'+$case[0])))) @([int]$case[1])
    Save-ReshetoUtf8 (Join-Path $target ($case[0]+'.jsonl')) $result.Output
}
$partial = Invoke-ReshetoCommand $cli @('--db', (Join-Path $target 'missing.db'), '--heuristics', $heuristics, '--storage', (Join-Path $target 'partial.db'), '--path', (Join-Path $target 'fixtures/positive.exe'), '--json') @(2)
Save-ReshetoUtf8 (Join-Path $target 'partial.jsonl') $partial.Output
$processDir = Join-Path $target 'processes'
$observed = Join-Path $target 'observed'
[IO.Directory]::CreateDirectory($processDir) | Out-Null
[IO.Directory]::CreateDirectory($observed) | Out-Null
$helper = Join-Path $processDir 'resheto-safe-helper.exe'
Copy-Item -LiteralPath (Join-Path $tools.Bin 'resheto-safe-helper.exe') -Destination $helper
function Start-Lab4Monitor([string]$Storage) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $tools.Bin 'resheto-monitor.exe'
    $argv = @('--path', $observed, '--db', $db, '--heuristics', $heuristics, '--behavior', $behavior, '--process-scope', $processDir, '--storage', $Storage, '--duration-ms', '4500', '--json')
    $info.Arguments = ($argv | ForEach-Object { ConvertTo-ReshetoArgument $_ }) -join ' '
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $info.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $native = New-Object Diagnostics.Process; $native.StartInfo = $info
    if (!$native.Start()) { throw 'Не запустить наблюдение' }
    $errorText = $native.StandardError.ReadToEndAsync()
    $initial = New-Object Text.StringBuilder
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        while ($clock.ElapsedMilliseconds -lt 6000) {
            $read = $native.StandardOutput.ReadLineAsync()
            while (!$read.Wait(200)) { if ($clock.ElapsedMilliseconds -ge 6000) { throw 'Наблюдение не готово за 6 секунд' } }
            $text = $read.Result
            if ($null -eq $text) { throw 'Наблюдение завершилось до готовности' }
            [void]$initial.AppendLine($text)
            $record = $text | ConvertFrom-Json
            if ($record.type -eq 'monitor_status' -and $record.ready) {
                return [pscustomobject]@{ Native=$native; Initial=$initial; Rest=$null; Error=$errorText }
            }
        }
        throw 'Наблюдение не готово'
    } catch { if (!$native.HasExited) { $native.Kill(); $native.WaitForExit() }; $native.Dispose(); throw }
}
function Wait-Lab4Results($Watch,[int]$Count) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.ElapsedMilliseconds -lt 6000) {
        $read = $Watch.Native.StandardOutput.ReadLineAsync()
        while (!$read.Wait(200)) { if ($clock.ElapsedMilliseconds -ge 6000) { throw 'Не получен результат файлового события за 6 секунд' } }
        if ($null -eq $read.Result) { throw 'Наблюдение завершилось до результата' }
        [void]$Watch.Initial.AppendLine($read.Result)
        $record = $read.Result | ConvertFrom-Json
        if ($record.type -eq 'monitor_status' -and [long]$record.data.results -ge $Count) { return }
    }
    throw 'Не получен результат файлового события'
}
foreach ($children in @(1,3)) {
    $watch = Start-Lab4Monitor (Join-Path $target ('monitor-'+$children+'.db'))
    try {
        if ($children -eq 3) {
            Copy-Item -LiteralPath (Join-Path $target 'fixtures/negative.exe') -Destination (Join-Path $observed 'file.exe')
            Wait-Lab4Results $watch 1
            Copy-Item -LiteralPath (Join-Path $target 'fixtures/positive.exe') -Destination (Join-Path $observed 'file.exe') -Force
            Wait-Lab4Results $watch 2
        }
        $watch.Rest = $watch.Native.StandardOutput.ReadToEndAsync()
        $run = Invoke-ReshetoCommand $helper @('--children', [string]$children, '--hold-ms', '1800', '--delay-ms', '600')
        if (!$watch.Native.WaitForExit(12000)) { throw 'Превышено время показа наблюдения' }
        if ($watch.Native.ExitCode -ne 3) { throw "Ошибка наблюдения: $($watch.Native.ExitCode) $($watch.Error.Result)" }
        $text = $watch.Initial.ToString()+$watch.Rest.Result
        Save-ReshetoUtf8 (Join-Path $target ('monitor-'+$children+'.jsonl')) $text
        $rows = @($text.Trim() -split '\r?\n' | ForEach-Object { $_ | ConvertFrom-Json })
        $results = @($rows | Where-Object { $_.type -eq 'result' })
        $behavioral = @($results | Where-Object { $_.data.outcome -eq 'behavioral_match' })
        $heuristic = @($results | Where-Object { $_.data.outcome -eq 'heuristic_match' })
        if ($children -eq 1 -and $behavioral.Count -ne 0) { throw 'Отрицательный процессный контроль дал обнаружение' }
        if ($children -eq 3 -and ($behavioral.Count -lt 1 -or $heuristic.Count -lt 1)) { throw 'Не получены реальные файловое и поведенческое обнаружения' }
    } finally { if (!$watch.Native.HasExited) { $watch.Native.Kill(); $watch.Native.WaitForExit() }; $watch.Native.Dispose() }
}
$reopened = Invoke-ReshetoCommand $cli @('--last', '--storage', (Join-Path $target 'monitor-3.db'), '--json') @(3)
Save-ReshetoUtf8 (Join-Path $target 'reopened.jsonl') $reopened.Output
Write-Output "Показ завершён: PE/ELF с обнаружением и без него, неполная проверка, создание и изменение файлов, один и три дочерних процесса, остановка и чтение истории. Данные: $target"
if ($OpenGui) {
    $argv = @('--path', $observed, '--db', $db, '--heuristics', $heuristics, '--behavior', $behavior, '--process-scope', $processDir, '--storage', (Join-Path $target 'monitor-3.db'))
    Start-Process -FilePath (Join-Path $tools.Bin 'resheto.exe') -WorkingDirectory $tools.Project -WindowStyle Normal -ArgumentList (($argv | ForEach-Object { ConvertTo-ReshetoArgument $_ }) -join ' ')
}

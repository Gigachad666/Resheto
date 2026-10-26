param(
    [switch]$Control,
    [string]$Bin = 'build/windows/Release',
    [switch]$NoLaunch,
    [string]$Directory = 'build/manual'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$tools = Get-ReshetoTools $Bin
$gui = Join-Path $tools.Bin 'resheto.exe'
if (!(Test-Path -LiteralPath $gui -PathType Leaf)) { throw "Не найден GUI: $gui" }
$manual = Get-ReshetoPath $Directory
[IO.Directory]::CreateDirectory($manual) | Out-Null
$object = ''
$signatures = Join-Path $tools.Project 'distribution/working/current.json'
if ($Control) {
    $controlDir = Join-Path $manual 'control'
    if (!(Test-Path -LiteralPath $controlDir)) {
        $prepared = Invoke-ReshetoCommand (Join-Path $tools.Bin 'resheto-prepare.exe') @('--source', (Join-Path $tools.Project 'data/demo_signatures.json'), '--output', $controlDir)
        Write-Output $prepared.Output.Trim()
    }
    $object = Join-Path $controlDir 'fixtures'
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
if (!$Control) { Write-Output 'Выберите файл или каталог кнопкой в окне программы.' }
if (!$NoLaunch) {
    $guiArguments = @('--db', $signatures, '--storage', $storage)
    if ($object) { $guiArguments += @('--path', $object) }
    Start-Process -FilePath $gui -WorkingDirectory $tools.Project -WindowStyle Normal -ArgumentList (($guiArguments | ForEach-Object { ConvertTo-ReshetoArgument $_ }) -join ' ')
}

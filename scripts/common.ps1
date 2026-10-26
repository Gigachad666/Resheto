# Совместимо с Windows PowerShell 5.1 и PowerShell 7.
function Get-ReshetoPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) $Path))
}

function Get-ReshetoTools([string]$Bin) {
    $directory = Get-ReshetoPath $Bin
    foreach ($name in @('resheto-cli.exe', 'resheto-prepare.exe')) {
        if (!(Test-Path -LiteralPath (Join-Path $directory $name) -PathType Leaf)) {
            throw "Не найдена сборка: $directory. Соберите проект или задайте -Bin с каталогом Release."
        }
    }
    $project = Split-Path -Parent $PSScriptRoot
    $qt = Join-Path $project '.tools/qt/6.8.3/msvc2022_64/bin'
    if (Test-Path -LiteralPath $qt -PathType Container) { $env:PATH = "$qt;$env:PATH" }
    return [pscustomobject]@{ Project = $project; Bin = $directory }
}

function ConvertTo-ReshetoArgument([string]$Value) {
    # Экранирование аргумента по правилам Windows argv, включая завершающие \.
    $quoted = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $quoted = [regex]::Replace($quoted, '(\\+)$', '$1$1')
    return '"' + $quoted + '"'
}

function Invoke-ReshetoCommand {
    param([string]$Executable, [string[]]$Arguments, [int[]]$ExpectedExitCode = @(0))
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = ($Arguments | ForEach-Object { ConvertTo-ReshetoArgument $_ }) -join ' '
    $info.WorkingDirectory = Split-Path -Parent $PSScriptRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $info.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $nativeProcess = New-Object System.Diagnostics.Process
    $nativeProcess.StartInfo = $info
    try {
        if (!$nativeProcess.Start()) { throw "Не удалось запустить $Executable" }
        $stdout = $nativeProcess.StandardOutput.ReadToEndAsync()
        $stderr = $nativeProcess.StandardError.ReadToEndAsync()
        if (!$nativeProcess.WaitForExit(120000)) {
            $nativeProcess.Kill(); $nativeProcess.WaitForExit()
            throw "Превышено время выполнения 120 с: $Executable"
        }
        $result = [pscustomobject]@{ Code = $nativeProcess.ExitCode; Output = $stdout.Result; Error = $stderr.Result }
        if ($ExpectedExitCode -notcontains $result.Code) {
            throw "Ошибка запуска $Executable (код $($result.Code)).`n$($result.Error)`n$($result.Output)"
        }
        return $result
    } finally { $nativeProcess.Dispose() }
}

function Save-ReshetoUtf8([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

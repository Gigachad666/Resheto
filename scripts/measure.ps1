param([Parameter(Mandatory=$true)][string]$Bin,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Output) { throw 'Нужен новый каталог измерений' }
New-Item -ItemType Directory -Path $Output | Out-Null
$root=(Resolve-Path -LiteralPath $Output).Path
$exe=(Resolve-Path -LiteralPath (Join-Path $Bin 'resheto-benchmark.exe')).Path
# Бюджет заранее: 120 секунд на процесс; конечные 64/256 МиБ, 1000 файлов.
function Run-Bounded([string]$Name,[string[]]$Arguments) {
    $start=New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName=$exe; $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    foreach($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process=New-Object System.Diagnostics.Process; $process.StartInfo=$start
    if(!$process.Start()) { throw 'Не запустить измерение' }
    $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
    if(!$process.WaitForExit(120000)) { $process.Kill($true); throw "Превышен бюджет 120 с: $Name" }
    $stdout.Result | Set-Content -Encoding utf8NoBOM (Join-Path $root "$Name.json")
    $stderr.Result | Set-Content -Encoding utf8NoBOM (Join-Path $root "$Name.stderr.txt")
    if($process.ExitCode -ne 0) { throw "Неуспешный прогон $Name, код $($process.ExitCode)" }
}
@{budget_seconds=120; os=[Environment]::OSVersion.VersionString; cpu=(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name); ram_bytes=(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory; utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -Encoding utf8NoBOM (Join-Path $root 'environment.json')
Run-Bounded 'prepare' @('prepare',"$root/data")
foreach($profile in @('small','large')) { foreach($mib in @('64','256')) { Run-Bounded "$profile-$mib" @('run',"$root/data",$profile,$mib) } }
Write-Output "Измерения и данные: $root"

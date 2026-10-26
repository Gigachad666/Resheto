param([Parameter(Mandatory=$true)][string]$Bin, [Parameter(Mandatory=$true)][string]$WorkDir)
$ErrorActionPreference='Stop'
$project=Split-Path -Parent $PSScriptRoot
. (Join-Path $project 'scripts/common.ps1')
function Assert-True([bool]$Condition,[string]$Message) { if(!$Condition) { throw $Message } }
foreach($script in (Get-ChildItem (Join-Path $project 'scripts') -Filter '*.ps1')) {
    $tokens=$null; $errors=$null
    [System.Management.Automation.Language.Parser]::ParseFile($script.FullName,[ref]$tokens,[ref]$errors) | Out-Null
    Assert-True ($errors.Count -eq 0) "Ошибка разбора $($script.Name): $errors"
    $bytes=[IO.File]::ReadAllBytes($script.FullName)
    Assert-True ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) "Скрипту $($script.Name) нужен UTF-8 BOM для Windows PowerShell"
}
$root=Join-Path ([IO.Path]::GetFullPath($WorkDir)) ("script-check-"+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
    $demo=Join-Path $root 'показ с пробелом'
    & (Join-Path $project 'scripts/demo.ps1') -Bin $Bin -Output $demo | Out-Null
    $text=[IO.File]::ReadAllText((Join-Path $demo 'scan.jsonl'),[Text.Encoding]::UTF8)
    $records=@($text.Trim() -split '\r?\n' | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-True ($records[-1].data.checked -eq '11' -and $records[-1].data.matches -eq '5') 'Не выполнен контрольный показ'
    $unicode=@($records | Where-Object { $_.type -eq 'result' -and $_.data.path.EndsWith('вложенный каталог/данные с пробелом.dat') })
    Assert-True ($unicode.Count -eq 1) 'Русский путь в JSON повреждён кодировкой'
    $replay=[IO.File]::ReadAllText((Join-Path $demo 'reopened.jsonl'),[Text.Encoding]::UTF8)
    Assert-True ($text -ceq $replay) 'Повторное чтение отличается'
    $many=Join-Path $root 'много файлов'
    & (Join-Path $project 'scripts/demo-results.ps1') -Bin $Bin -Output $many | Out-Null
    $rows=@([IO.File]::ReadAllText((Join-Path $many 'scan.jsonl'),[Text.Encoding]::UTF8).Trim() -split '\r?\n' | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-True ($rows[-1].data.checked -eq '2101' -and $rows[-1].data.matches -eq '1') 'Не выполнен большой показ'
    $match=@($rows | Where-Object { $_.type -eq 'result' -and $_.data.outcome -eq 'signature_match' })
    Assert-True ($match.Count -eq 1 -and $match[0].data.path.EndsWith('я совпадение.bin')) 'Потеряно обнаружение/русское имя'
    $failed=$false
    try { & (Join-Path $project 'scripts/demo.ps1') -Bin $Bin -Output $demo | Out-Null } catch { $failed=$true }
    Assert-True $failed 'Нельзя перезаписывать существующий показ'
    $gui=Join-Path (Get-ReshetoPath $Bin) 'resheto.exe'
    if(Test-Path -LiteralPath $gui) {
        $manual=Join-Path $root 'запуск GUI'
        & (Join-Path $project 'scripts/start.ps1') -Bin $Bin -Directory $manual -Control -NoLaunch | Out-Null
        Assert-True (Test-Path -LiteralPath (Join-Path $manual 'control/fixtures/hash.bin')) 'Запуск не подготовил контрольные данные'
        $before=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $manual 'control/signatures.db')))
        & (Join-Path $project 'scripts/start.ps1') -Bin $Bin -Directory $manual -Control -NoLaunch | Out-Null
        $after=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $manual 'control/signatures.db')))
        Assert-True ($before -ceq $after) 'Повторный запуск переписал контрольную базу'
        & (Join-Path $project 'scripts/start.ps1') -Bin $Bin -Directory $manual -NoLaunch | Out-Null
    }
    Write-Output "PowerShell $($PSVersionTable.PSVersion): разбор, UTF-8/Unicode, 11/5, 2101/1, история и защита от перезаписи — успешно"
} finally {
    $parent=[IO.Path]::GetFullPath($WorkDir).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    if(![IO.Path]::GetFullPath($root).StartsWith($parent,[StringComparison]::OrdinalIgnoreCase)) { throw 'Недопустимый путь временного каталога' }
    Remove-Item -LiteralPath $root -Recurse -Force
}

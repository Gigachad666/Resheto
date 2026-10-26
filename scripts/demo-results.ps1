param([string]$Bin='build/final-20261025/Release',[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Output) { throw 'Выберите новый каталог' }
$project=Split-Path -Parent $PSScriptRoot
$binaryDir=[IO.Path]::GetFullPath((Join-Path $project $Bin))
& (Join-Path $binaryDir 'resheto-prepare.exe') --source (Join-Path $project 'data/demo_signatures.json') --output $Output
if($LASTEXITCODE -ne 0) { throw 'Ошибка подготовки контроля' }
$root=(Resolve-Path -LiteralPath $Output).Path
$tree=Join-Path $root 'many'
New-Item -ItemType Directory -Path $tree | Out-Null
for($i=0;$i -lt 2100;$i++) { [IO.File]::WriteAllText((Join-Path $tree ('обычный {0:d4}.bin' -f $i)),'ordinary harmless data',[Text.UTF8Encoding]::new($false)) }
Copy-Item -LiteralPath (Join-Path $root 'fixtures/hash.bin') -Destination (Join-Path $tree 'я совпадение.bin')
& (Join-Path $binaryDir 'resheto-cli.exe') --path $tree --db (Join-Path $root 'signatures.db') --storage (Join-Path $root 'results.db') --json | Set-Content -Encoding utf8NoBOM (Join-Path $root 'scan.jsonl')
if($LASTEXITCODE -ne 1) { throw 'Ожидалось одно обнаружение' }
$job=(Get-Content -LiteralPath (Join-Path $root 'scan.jsonl') -Tail 1 | ConvertFrom-Json).data
if($job.checked -ne '2101' -or $job.matches -ne '1' -or $job.errors -ne '0') { throw 'Счётчики задания отличаются от ожидаемых' }
Write-Output "Готово: 2101 файл, одно совпадение. Откройте GUI с --storage $root/results.db --db $root/signatures.db; выберите сортировку по пути и фильтр «Совпадения»."

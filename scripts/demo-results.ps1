param([string]$Bin='build/windows/Release',[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$tools=Get-ReshetoTools $Bin
$project=$tools.Project
$binaryDir=$tools.Bin
$root=Get-ReshetoPath $Output
if(Test-Path -LiteralPath $root) { throw 'Выберите новый каталог' }
$prepared=Invoke-ReshetoCommand (Join-Path $binaryDir 'resheto-prepare.exe') @('--source', (Join-Path $project 'data/demo_signatures.json'), '--output', $root)
Write-Output $prepared.Output.Trim()
$tree=Join-Path $root 'many'
New-Item -ItemType Directory -Path $tree | Out-Null
for($i=0;$i -lt 2100;$i++) { [IO.File]::WriteAllText((Join-Path $tree ('обычный {0:d4}.bin' -f $i)),'ordinary harmless data',[Text.UTF8Encoding]::new($false)) }
Copy-Item -LiteralPath (Join-Path $root 'fixtures/hash.bin') -Destination (Join-Path $tree 'я совпадение.bin')
$scan=Invoke-ReshetoCommand (Join-Path $binaryDir 'resheto-cli.exe') @('--path', $tree, '--db', (Join-Path $root 'signatures.db'), '--storage', (Join-Path $root 'results.db'), '--json') @(1)
Save-ReshetoUtf8 (Join-Path $root 'scan.jsonl') $scan.Output
$job=($scan.Output.Trim() -split '\r?\n' | Select-Object -Last 1 | ConvertFrom-Json).data
if($job.checked -ne '2101' -or $job.matches -ne '1' -or $job.errors -ne '0') { throw 'Счётчики задания отличаются от ожидаемых' }
Write-Output "Готово: 2101 файл, одно совпадение. Откройте GUI с --storage $root/results.db --db $root/signatures.db; выберите сортировку по пути и фильтр «Совпадения»."

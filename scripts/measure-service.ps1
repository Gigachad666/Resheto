#requires -Version 7.2
param(
    [Parameter(Mandatory)][string]$Output,
    [string]$Bin = '',
    [ValidateRange(1,3)][int]$Repetitions = 2,
    [ValidateRange(0,120)][int]$IdleSeconds = 0
)
$ErrorActionPreference = 'Stop'
if (!$IsWindows -and !$IsLinux) { throw 'Supported platforms: Windows and Linux' }
if (!$Bin) { $Bin = if ($IsWindows) { 'build/windows/Release' } else { 'build/release' } }
$exeSuffix = if ($IsWindows) { '.exe' } else { '' }
$repo = (Resolve-Path -LiteralPath '.').Path
$Bin = (Resolve-Path -LiteralPath $Bin).Path
$serviceBinary = Join-Path $Bin "resheto-service$exeSuffix"
$workerName = "resheto-network-worker$exeSuffix"
$Output = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $Output) { throw "A new output directory is required: $Output" }
New-Item -ItemType Directory -Path $Output | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false)

function Assert-That([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw $Message }
}

function Prepare([string]$Program, [string[]]$Arguments, [string]$Log) {
    & (Join-Path $Bin "$Program$exeSuffix") @Arguments | Set-Content -LiteralPath (Join-Path $Output $Log)
    Assert-That ($LASTEXITCODE -eq 0) "$Program exited with $LASTEXITCODE"
}

function Read-Bytes($Stream, [int]$Length, $Token) {
    $bytes = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $received = $Stream.ReadAsync($bytes, $offset, $Length - $offset, $Token).GetAwaiter().GetResult()
        if ($received -eq 0) { throw 'The pipe closed before a complete response' }
        $offset += $received
    }
    return ,$bytes
}

function Open-UnixServiceStream([string]$Path) {
    $socket = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::Unix,
        [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Unspecified)
    $timeout = [Threading.CancellationTokenSource]::new(1600)
    try {
        $address = [Net.Sockets.UnixDomainSocketEndPoint]::new($Path)
        $null = $socket.ConnectAsync($address, $timeout.Token).AsTask().GetAwaiter().GetResult()
        return [Net.Sockets.NetworkStream]::new($socket, $true)
    } catch {
        $socket.Dispose()
        throw
    } finally { $timeout.Dispose() }
}

function Open-ServiceStream([string]$Endpoint) {
    if ($IsLinux) {
        # QLocalServer resolves a short endpoint inside Qt's temporary directory.
        return (Open-UnixServiceStream (Join-Path ([IO.Path]::GetTempPath()) $Endpoint))
    }
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $Endpoint, [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Impersonation)
    try {
        $pipe.Connect(1600)
        return $pipe
    } catch {
        $pipe.Dispose()
        throw
    }
}

function Request($Service, [string]$Command, [hashtable]$Fields = @{}) {
    $body = $utf8.GetBytes((@{version=1; command=$Command} + $Fields | ConvertTo-Json -Depth 12 -Compress))
    $header = [BitConverter]::GetBytes([uint32]$body.Length)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($header) }
    $stream = Open-ServiceStream $Service.endpoint
    $timeout = [Threading.CancellationTokenSource]::new(15000)
    try {
        $stream.Write([byte[]]($header + $body), 0, 4 + $body.Length)
        $stream.Flush()
        $header = Read-Bytes $stream 4 $timeout.Token
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($header) }
        $length = [BitConverter]::ToUInt32($header, 0)
        Assert-That ($length -gt 0 -and $length -le 4MB) 'Invalid local response size'
        $reply = $utf8.GetString((Read-Bytes $stream $length $timeout.Token)) | ConvertFrom-Json
        if (!$reply.ok) { throw "$Command failed: $($reply.code) $($reply.message)" }
        return $reply.result
    } finally {
        $timeout.Dispose()
        $stream.Dispose()
    }
}

function Start-FixtureService([string]$Name, [string]$Database, [string]$Heuristics = '') {
    $tag = [guid]::NewGuid().ToString('N').Substring(0,12)
    $directory = Join-Path $Output $Name
    New-Item -ItemType Directory -Path $directory | Out-Null
    $config = @{endpoint="resheto-accept-$tag"; db=$Database; heuristics=$Heuristics;
                network_rules=(Join-Path $repo 'data/network_rules.json'); storage='history.db'}
    $path = Join-Path $directory 'service.json'
    [IO.File]::WriteAllText($path, ($config | ConvertTo-Json), $utf8)
    $stdout = Join-Path $directory 'stdout.txt'
    $stderr = Join-Path $directory 'stderr.txt'
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $launch = @{FilePath=$serviceBinary; ArgumentList=@('--config', ('"{0}"' -f $path));
        RedirectStandardOutput=$stdout; RedirectStandardError=$stderr; PassThru=$true}
    if ($IsWindows) { $launch.WindowStyle = 'Hidden' }
    $process = Start-Process @launch
    try {
        while (!$process.HasExited -and $watch.ElapsedMilliseconds -lt 15000) {
            if (Select-String -LiteralPath $stdout -Quiet -SimpleMatch "READY $($config.endpoint)") {
                return @{endpoint=$config.endpoint; process=$process; directory=$directory; startup_ms=$watch.ElapsedMilliseconds}
            }
            Start-Sleep -Milliseconds 35
        }
        throw "Service did not become ready: $(Get-Content -LiteralPath $stderr -Raw)"
    } catch {
        Stop-FixtureService @{process=$process}
        throw
    }
}

function Stop-FixtureService($Service) {
    $process = $Service.process
    try {
        if ($IsLinux -and !$process.HasExited) {
            & kill -TERM $process.Id 2>$null
            $null = $process.WaitForExit(3000)
        }
        if (!$process.HasExited) {
            $process.Kill()
            $null = $process.WaitForExit(3000)
        }
    } finally { $process.Dispose() }
}

function Get-CpuName {
    if ($IsWindows) { return (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name) }
    $model = Select-String -LiteralPath '/proc/cpuinfo' -Pattern '^model name\s*:\s*(.+)$' | Select-Object -First 1
    if ($model) { return $model.Matches[0].Groups[1].Value }
    return [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
}

function Find-WorkerId([int]$ParentId) {
    if ($IsWindows) {
        $child = Get-CimInstance Win32_Process -Filter "ParentProcessId=$ParentId AND Name='$workerName'" | Select-Object -First 1
        if ($child) { return [int]$child.ProcessId }
        return 0
    }
    foreach ($childId in (& ps --ppid $ParentId -o pid=)) {
        $childId = [int]$childId
        try { $executable = [IO.File]::ResolveLinkTarget("/proc/$childId/exe", $false) }
        catch [IO.IOException] { continue }
        if ($executable -and $executable.Name -ceq $workerName) { return $childId }
    }
    return 0
}

function Await($Service, [string]$Command, [scriptblock]$Condition, [int]$Seconds = 20) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt $Seconds) {
        $value = Request $Service $Command
        if (& $Condition $value) { return $value }
        Start-Sleep -Milliseconds 60
    }
    throw "$Command failed to reach the expected state within $Seconds seconds"
}

function Rows($Service, [string]$JobId) {
    (Request $Service query @{job_id=$JobId; query=@{filter=0;sort=0;object=0;descending=$false;offset='0';upper_row='0';limit=200;path='';text=''}}).rows
}

function Scan($Service, [string]$Path, [bool]$Recursive = $false) {
    $job = Request $Service start_scan @{path=$Path;recursive=$Recursive}
    $null = Await $Service status { param($state) !$state.busy -and $state.job.id -eq $job.id } 25
    (Request $Service get_job @{job_id=$job.id;recover_running=$true}).job
}

$sigs = Join-Path $Output 'file-input'
$heur = Join-Path $Output 'heur-input'
$net = Join-Path $Output 'net-input'
Prepare resheto-prepare @('--source','data/demo_signatures.json','--output',$sigs) 'prepare-signatures.txt'
Prepare resheto-lab4-prepare @('--heuristics','data/heuristic_rules.json','--behavior','data/behavior_rules.json','--output',$heur) 'prepare-heuristics.txt'
Prepare resheto-network-prepare @('--rules','data/network_rules.json','--output',$net) 'prepare-network.txt'
$controlDb = Join-Path $sigs 'signatures.db'
$workingDb = Join-Path $repo 'distribution/working/current.json'
$current = Get-Content -LiteralPath $workingDb -Raw | ConvertFrom-Json
$workingSqlite = Join-Path (Split-Path -Parent $workingDb) $current.database
$heuristics = Join-Path $repo 'data/heuristic_rules.json'

$report = [ordered]@{
    format='resheto-acceptance-v1'; timestamp_utc=[DateTime]::UtcNow.ToString('o')
    system=[Environment]::OSVersion.VersionString
    os_description=[Runtime.InteropServices.RuntimeInformation]::OSDescription
    cpu=(Get-CpuName)
    service_sha256=(Get-FileHash -LiteralPath $serviceBinary).Hash
    worker_sha256=(Get-FileHash -LiteralPath (Join-Path $Bin $workerName)).Hash
    working_db_sha256=(Get-FileHash -LiteralPath $workingSqlite).Hash
    quality=[ordered]@{}; profile=@()
}
function Save-Report { [IO.File]::WriteAllText((Join-Path $Output 'summary.json'), ($report | ConvertTo-Json -Depth 14), $utf8) }

$service = Start-FixtureService 'controls' $controlDb $heuristics
try {
    $fixtureDir = Join-Path $sigs 'fixtures'
    $expected = Get-Content -LiteralPath (Join-Path $sigs 'expected.json') -Raw | ConvertFrom-Json
    $manual = Scan $service $fixtureDir $true
    $results = @(Rows $service $manual.id)
    $root = $fixtureDir.Replace([char]92,[char]47).TrimEnd('/') + '/'
    Assert-That ($results.Count -eq $expected.Count) 'Wrong number of signature controls'
    $tp = 0; $tn = 0
    foreach ($item in $expected) {
        $row = @($results | Where-Object {$_.path -eq ($root + $item.path)})
        Assert-That ($row.Count -eq 1 -and $row[0].outcome -eq $item.outcome) "Wrong result for $($item.path)"
        if ($item.signature_id) {
            Assert-That ($row[0].signature_id -eq $item.signature_id -and $row[0].offset -eq $item.offset) "Wrong finding for $($item.path)"
            $tp++
        } else { $tn++ }
    }
    $report.quality.signatures = @{positive=$tp; negative=$tn; expected_missed=0; unexpected_matches=0; job_id=$manual.id}
    $manual = Scan $service (Join-Path $heur 'fixtures') $true
    $results = @(Rows $service $manual.id)
    Assert-That ($results.Count -eq 6) 'Wrong number of PE/ELF controls'
    $positive = @($results | Where-Object {$_.outcome -eq 'heuristic_match'})
    $bad = @($results | Where-Object {$_.path -like '*/broken.exe'})
    $ordinary = @($results | Where-Object {$_.completeness -eq 'full' -and $_.outcome -eq 'no_match'})
    Assert-That ($positive.Count -eq 2 -and $ordinary.Count -eq 3 -and $bad.Count -eq 1 -and $bad[0].completeness -ne 'full' -and
        @($positive | Where-Object {$_.rule_id -eq 'writable-executable' -and $_.path -match '/positive\.(exe|elf)$'}).Count -eq 2) 'Unexpected PE/ELF results'
    $report.quality.heuristics=@{positive=2; negative=3; malformed=1; malformed_outcome=$bad[0].outcome; completeness=$bad[0].completeness; unexpected_matches=0; job_id=$manual.id}
    foreach ($case in @(@{file='ordinary.pcap';packets=102;rules=@()},@{file='control.pcap';packets=2147;rules=@('tcp-port-sweep','periodic-tcp-attempts','dns-nxdomain-burst')})) {
        $job = Request $service network_start @{source='pcap';input=(Join-Path $net $case.file);duration_ms=0;tcp_ports=@()}
        $done = Await $service network_status {param($state) !$state.busy -and $state.job.id -eq $job.id}
        $alerts = @( (Request $service network_detections @{job_id=$job.id;flow_id='';text='';offset='0';limit=50;linked=$false}).rows )
        $actualRules = @($alerts | ForEach-Object rule_id)
        Assert-That ($done.job.state -eq 'completed' -and [int]$done.job.counters.packets -eq $case.packets -and
            $alerts.Count -eq $case.rules.Count -and @($case.rules | Where-Object {$_ -notin $actualRules}).Count -eq 0) "Unexpected PCAP results: $($case.file)"
        $report.quality[$case.file] = @{packets=$case.packets; matches=$alerts.Count; rules=$actualRules; job_id=$job.id}
    }
    Save-Report
} finally { Stop-FixtureService $service }

$service = Start-FixtureService 'working-db' $workingDb
try {
    $manual = Scan $service (Join-Path $sigs 'fixtures') $true
    Assert-That ($manual.state -eq 'completed' -and [int]$manual.matches -eq 0 -and [int]$manual.checked -eq $expected.Count) 'Unexpected result with production HASH metadata'
    $report.quality.working_base=@{version=$manual.database_version; checked=[int]$manual.checked; matches=0; job_id=$manual.id}
    Save-Report
} finally { Stop-FixtureService $service }

if ($IdleSeconds -gt 0) {
    Write-Host "Idle observation: $IdleSeconds seconds"
    $service = Start-FixtureService 'idle' $workingDb $heuristics
    try {
        $watchArea = Join-Path $service.directory 'watched'
        New-Item -ItemType Directory -Path $watchArea | Out-Null
        $monitor = Request $service start_monitor @{options=@{directory=$watchArea;process_scope=$watchArea;
            behavior=(Join-Path $repo 'data/behavior_rules.json');files=$true;processes=$true;recursive=$true;scan_process_images=$false}}
        $null = Await $service monitor_status {param($s) $s.ready -and $s.active} 10
        $service.process.Refresh()
        $startMiB = $service.process.WorkingSet64 / 1MB
        $workingSetPeakMiB = $startMiB
        $cpuStart = $service.process.TotalProcessorTime.TotalSeconds
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while ($timer.Elapsed.TotalSeconds -lt $IdleSeconds) {
            Start-Sleep -Seconds 1
            $service.process.Refresh()
            $workingSetPeakMiB = [Math]::Max($workingSetPeakMiB, $service.process.WorkingSet64 / 1MB)
        }
        $timer.Stop()
        $endMiB = $service.process.WorkingSet64 / 1MB
        $cpuSeconds = $service.process.TotalProcessorTime.TotalSeconds - $cpuStart
        $idleStatus = Request $service monitor_status
        Assert-That ($idleStatus.active -and $idleStatus.job.id -eq $monitor.job.id -and
            [int]$idleStatus.job.checked -eq 0 -and [int]$idleStatus.job.matches -eq 0 -and [int]$idleStatus.lost -eq 0) 'Unexpected idle monitoring result'
        $null = Request $service cancel_monitor @{job_id=$monitor.job.id}
        $null = Await $service monitor_status {param($s) !$s.active}
        $report.idle = @{duration_ms=$timer.ElapsedMilliseconds;sample_interval_ms=1000;file_monitor=$true;process_monitor=$true;
            service_start_mib=[Math]::Round($startMiB,1);service_end_mib=[Math]::Round($endMiB,1);
            service_sample_peak_mib=[Math]::Round($workingSetPeakMiB,1);service_cpu_seconds=[Math]::Round($cpuSeconds,3);lost=0}
        Save-Report
    } finally { Stop-FixtureService $service }
}

$payload = Join-Path $Output 'clean-128mib.bin'
$file = [IO.File]::Open($payload, [IO.FileMode]::CreateNew)
try {
    $block = [byte[]]::new(1MB)
    for ($i=0; $i -lt 128; $i++) { $file.Write($block,0,$block.Length) }
} finally { $file.Dispose() }
$report.profile_hashes=@{file=(Get-FileHash -LiteralPath $payload).Hash; pcap=(Get-FileHash -LiteralPath (Join-Path $net 'profile-100k.pcap')).Hash}
for ($run=1; $run -le $Repetitions; $run++) {
    Write-Host "Concurrent profile: $run/$Repetitions"
    $service = Start-FixtureService "profile-$run" $workingDb $heuristics
    try {
        $watchArea = Join-Path $service.directory 'watched'
        New-Item -ItemType Directory -Path $watchArea | Out-Null
        $monitor = Request $service start_monitor @{options=@{directory=$watchArea;process_scope='';behavior='';
            files=$true;processes=$false;recursive=$true;scan_process_images=$false}}
        $null = Await $service monitor_status {param($s) $s.ready} 10
        $service.process.Refresh()
        $idleMiB = $service.process.WorkingSet64 / 1MB
        $cpuStart = $service.process.TotalProcessorTime.TotalSeconds
        $time = [Diagnostics.Stopwatch]::StartNew()
        $network = Request $service network_start @{source='pcap';input=(Join-Path $net 'profile-100k.pcap');duration_ms=0;tcp_ports=@()}
        $fileStart = $time.ElapsedMilliseconds
        $manual = Request $service start_scan @{path=$payload;recursive=$false}
        $initial = Request $service status
        Assert-That ($initial.busy -and $initial.monitor.active -and (Request $service network_status).busy) 'Jobs did not overlap'
        for ($i=0; $i -lt 20; $i++) {
            [IO.File]::WriteAllText((Join-Path $watchArea ("own-{0:D3}.txt" -f $i)), "Harmless fixture $i", $utf8)
        }
        $afterWrite = $time.ElapsedMilliseconds
        $manualMs = $networkMs = $monitorMs = $workerPeak = $workerCpu = 0
        $workerId = 0
        while (($manualMs -eq 0 -or $networkMs -eq 0 -or $monitorMs -eq 0) -and $time.Elapsed.TotalSeconds -lt 120) {
            $state = Request $service status
            if (!$manualMs -and !$state.busy -and $state.job.id -eq $manual.id) { $manualMs=$time.ElapsedMilliseconds-$fileStart }
            if (!$monitorMs -and [int]$state.monitor.job.checked -eq 20) { $monitorMs=$time.ElapsedMilliseconds-$afterWrite }
            $ns = Request $service network_status
            if (!$networkMs -and !$ns.busy -and $ns.job.id -eq $network.id) { $networkMs=$time.ElapsedMilliseconds }
            if (!$workerId -and $ns.busy) {
                $workerId = Find-WorkerId $service.process.Id
            }
            if ($workerId) {
                $worker = Get-Process -Id $workerId -ErrorAction SilentlyContinue
                if ($worker) {
                    $workerPeak=[Math]::Max($workerPeak,$worker.PeakWorkingSet64)
                    $workerCpu=[Math]::Max($workerCpu,$worker.TotalProcessorTime.TotalSeconds)
                }
            }
            Start-Sleep -Milliseconds 60
        }
        Assert-That ($manualMs -gt 0 -and $networkMs -gt 0 -and $monitorMs -gt 0 -and $workerPeak -gt 0) 'Profile did not finish within 120 seconds or worker was not sampled'
        $service.process.Refresh()
        $servicePeak = $service.process.PeakWorkingSet64 / 1MB
        $serviceCpu = $service.process.TotalProcessorTime.TotalSeconds - $cpuStart
        $null = Request $service cancel_monitor @{job_id=$monitor.job.id}
        $watchResult = Await $service monitor_status {param($s) !$s.active}
        $fileJob = (Request $service get_job @{job_id=$manual.id;recover_running=$true}).job
        $networkJob = (Request $service network_job @{job_id=$network.id}).job
        Assert-That ($fileJob.state -eq 'completed' -and [int]$fileJob.checked -eq 1 -and [int]$fileJob.matches -eq 0) 'Unexpected profile file result'
        Assert-That ($networkJob.state -eq 'completed' -and [int]$networkJob.counters.packets -eq 100000 -and [int]$networkJob.stored_detections -eq 3) 'Unexpected profile PCAP result'
        Assert-That ([int]$watchResult.job.checked -eq 20 -and [int]$watchResult.lost -eq 0 -and [int]$watchResult.job.matches -eq 0) 'Unexpected monitoring loss or matches'
        $report.profile+=@{run=$run;startup_ms=$service.startup_ms;file_ms=$manualMs;file_mib_s=[Math]::Round(128000/$manualMs,1);
            pcap_ms=$networkMs; pcap_packets_s=[Math]::Round(100000000/$networkMs); flows=[int]$networkJob.stored_flows;
            monitor_files=20;monitor_lost=[int]$watchResult.lost;monitor_after_last_write_ms=$monitorMs;
            service_idle_mib=[Math]::Round($idleMiB,1);service_peak_mib=[Math]::Round($servicePeak,1);worker_sample_peak_mib=[Math]::Round($workerPeak/1MB,1);
            service_cpu_seconds=[Math]::Round($serviceCpu,2);worker_sample_cpu_seconds=[Math]::Round($workerCpu,2)}
        Save-Report
    } finally { Stop-FixtureService $service }
}
Get-Content -LiteralPath (Join-Path $Output 'summary.json') -Raw

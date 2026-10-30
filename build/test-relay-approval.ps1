$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -ne 'DESKTOP-V8117LP'){throw 'Offline build only on PW; never a WeChat guest'}
$root=Split-Path $PSScriptRoot -Parent
$out=Join-Path $root 'artifacts\relay-approval-contract'
if((Get-PSDrive D).Free -lt 10GB){throw 'Need 10 GiB disk reserve'}
New-Item -ItemType Directory -Path $out -Force | Out-Null
$environment='C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$python='D:\Programming\Anaconda3\python.exe'
if(-not(Test-Path -LiteralPath $environment) -or -not(Test-Path -LiteralPath $python)){throw 'Existing offline toolchain missing'}
$batch=Join-Path $out 'test.cmd'
$commands=@(
 '@echo off',
 ('call "'+$environment+'" >nul'),
 'if errorlevel 1 exit /b 1',
 ('cd /d "'+$root+'"'),
 'cl.exe /nologo /std:c++17 /EHsc /utf-8 /MD /O2 /W4 /I include tests\relay_approval_contract.cpp src\send_api.cpp src\send_approval.cpp /Fe:artifacts\relay-approval-contract\relay_approval_contract.exe /Fo:artifacts\relay-approval-contract\ /link bcrypt.lib',
 'if errorlevel 1 exit /b 1',
 ('set "RELAY_APPROVAL_PROBE='+$out+'\relay_approval_contract.exe"'),
 ('"'+$python+'" -B tests\test_relay_approval_contract.py'),
 'if errorlevel 1 exit /b 1',
 ('"'+$python+'" -B tests\test_pm_relay.py'),
 'exit /b %errorlevel%'
)
[IO.File]::WriteAllText($batch,($commands -join "`r`n")+"`r`n",[Text.ASCIIEncoding]::new())
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName=$env:ComSpec
$info.Arguments='/d /c '+$batch
$info.WorkingDirectory=$root
$info.UseShellExecute=$false
$info.RedirectStandardOutput=$true
$info.RedirectStandardError=$true
$process=New-Object Diagnostics.Process
$process.StartInfo=$info
$started=Get-Date
$null=$process.Start()
$stdout=$process.StandardOutput.ReadToEndAsync()
$stderr=$process.StandardError.ReadToEndAsync()
$peak=0L
$stopReason=$null
while(-not $process.WaitForExit(1000)){
 $all=@(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,WorkingSetSize)
 $ids=New-Object 'Collections.Generic.HashSet[uint32]'
 $null=$ids.Add([uint32]$process.Id)
 do{$changed=$false;foreach($child in $all){if($ids.Contains([uint32]$child.ParentProcessId)){$changed=$ids.Add([uint32]$child.ProcessId) -or $changed}}}while($changed)
 $memory=($all | Where-Object {$ids.Contains([uint32]$_.ProcessId)} | Measure-Object WorkingSetSize -Sum).Sum
 if($memory -gt $peak){$peak=[long]$memory}
 if(((Get-Date)-$started).TotalSeconds -gt 180){$stopReason='Three-minute timeout'}
 if($memory -gt 2GB){$stopReason='Sampled process tree working set exceeded 2 GiB'}
 if((Get-PSDrive D).Free -lt 10GB){$stopReason='Disk reserve below 10 GiB'}
 if($stopReason){& taskkill.exe /PID $process.Id /T /F | Out-Null;break}
}
$process.WaitForExit()
$exit=$process.ExitCode
$output=$stdout.GetAwaiter().GetResult()
$errors=$stderr.GetAwaiter().GetResult()
$process.Dispose()
[IO.File]::WriteAllText((Join-Path $out 'test.stdout.log'),$output)
[IO.File]::WriteAllText((Join-Path $out 'test.stderr.log'),$errors)
$output -split "`r?`n" | Select-Object -Last 15
if($errors){$errors -split "`r?`n" | Select-Object -Last 10}
if($stopReason){throw $stopReason}
if($exit -ne 0){throw "Offline tests failed: $exit"}
[ordered]@{ExitCode=$exit;ElapsedSeconds=[math]::Round(((Get-Date)-$started).TotalSeconds,1);SampledPeakTreeBytes=$peak;NoWeChatProcessAccess=$true;NoGuestAccess=$true;NoDLLBuilt=$true} | ConvertTo-Json | Tee-Object -FilePath (Join-Path $out 'test-result.json')

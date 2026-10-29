param([Parameter(Mandatory=$true)][string]$NativeSample)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:PCNAME -ne 'PW'){throw 'Offline build only on PW'}
$root=Split-Path $PSScriptRoot -Parent
$out=Join-Path $root 'artifacts\send-fix'
if((Get-PSDrive D).Free -lt 10GB){throw 'Disk reserve below 10 GiB'}
if(-not(Test-Path -LiteralPath $NativeSample)){throw 'Native input missing'}
New-Item -ItemType Directory -Path $out -Force | Out-Null
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$cmd=Join-Path $out 'ownership-build.cmd'
$commands=@('@echo off',('call "'+$vc+'" >nul'),'if errorlevel 1 exit /b 1',('cd /d "'+$root+'"'),
 'cl.exe /nologo /std:c++17 /EHsc /utf-8 /MD /O2 /W4 /D_WIN32_WINNT=0x0A00 /I include tests\send_ownership_tests.cpp src\send_api.cpp src\send_approval.cpp /Fe:artifacts\send-fix\send_ownership_tests.exe /Fo:artifacts\send-fix\ /link bcrypt.lib version.lib ole32.lib',
 'exit /b %errorlevel%')
[IO.File]::WriteAllText($cmd,($commands -join "`r`n")+"`r`n",[Text.ASCIIEncoding]::new())
function Run-Bounded([string]$Name,[string]$File,[string]$Arguments){
 $p=[Diagnostics.Process]::new();$p.StartInfo.FileName=$File;$p.StartInfo.Arguments=$Arguments
 $p.StartInfo.WorkingDirectory=$root;$p.StartInfo.UseShellExecute=$false
 $p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
 $watch=[Diagnostics.Stopwatch]::StartNew();$null=$p.Start()
 $stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync();$peak=$p.WorkingSet64;$stop=$null
 while(-not $p.WaitForExit(250)){
  $p.Refresh();$memory=$p.WorkingSet64
  if($Name -eq 'ownership-build'){
   $all=@(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,WorkingSetSize)
   $ids=[Collections.Generic.HashSet[uint32]]::new();$null=$ids.Add([uint32]$p.Id)
   do{$changed=$false;foreach($child in $all){if($ids.Contains([uint32]$child.ParentProcessId)){$changed=$ids.Add([uint32]$child.ProcessId) -or $changed}}}while($changed)
   $memory=($all|Where-Object {$ids.Contains([uint32]$_.ProcessId)}|Measure-Object WorkingSetSize -Sum).Sum
  }
  $peak=[math]::Max($peak,$memory)
  if($watch.Elapsed.TotalSeconds -gt 180 -or $peak -gt 1GB -or (Get-PSDrive D).Free -lt 10GB){
   $stop='Ownership test exceeded time/memory/disk budget';& taskkill.exe /PID $p.Id /T /F | Out-Null;break
  }
 }
 $p.WaitForExit();$code=$p.ExitCode;$pidUsed=$p.Id
 $text=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult();$p.Dispose()
 [IO.File]::WriteAllText((Join-Path $out ($Name+'.stdout.log')),$text,[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllText((Join-Path $out ($Name+'.stderr.log')),$err,[Text.UTF8Encoding]::new($false))
 Write-Output $text;if($err){Write-Output $err}
 $result=[ordered]@{Name=$Name;ExitCode=$code;Seconds=$watch.Elapsed.TotalSeconds;SampledPeakBytes=$peak}
 $result|ConvertTo-Json -Compress
 # Cleanup only this exited test PID; no user data.
 $temp=Join-Path ([IO.Path]::GetTempPath()) ('wechat-owned-offline-'+$pidUsed)
 if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Recurse -Force}
 if($stop){throw $stop};if($code -ne 0){throw "$Name failed: $code"}
}
Run-Bounded 'ownership-build' $env:ComSpec ('/d /c "'+$cmd+'"')
$exe=Join-Path $out 'send_ownership_tests.exe'
foreach($mode in @('normal','ctor-fault','params-fault','submit-fault','cleanup-fault','destroy-fault','clone-fault','metadata-fault')){
 Run-Bounded ('ownership-'+$mode) $exe ('"'+$NativeSample+'" '+$mode)
}

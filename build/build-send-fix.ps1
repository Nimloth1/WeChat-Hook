$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -ne 'DESKTOP-V8117LP'){throw 'Build only on PW; never inside a WeChat guest'}
$root=Split-Path $PSScriptRoot -Parent
$out=Join-Path $root 'artifacts\send-fix'
if((Get-PSDrive D).Free -lt 10GB){throw 'Less than 10 GiB disk reserve'}
New-Item -ItemType Directory -Path $out -Force | Out-Null
$vs='C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools'
$environment=Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
if(-not(Test-Path -LiteralPath $environment)){throw 'Existing compiler missing'}
$batch=Join-Path $out 'build.cmd'
$commands=@(
 '@echo off',
 ('call "'+$environment+'" >nul'),
 'if errorlevel 1 exit /b 1',
 ('cd /d "'+$root+'"'),
 'cl.exe /nologo /std:c++17 /EHsc /utf-8 /MD /O2 /W4 /D_WIN32_WINNT=0x0A00 /DCPPHTTPLIB_THREAD_POOL_COUNT=4 /I include tests\send_layout_tests.cpp /Fe:artifacts\send-fix\send_layout_tests.exe /Fo:artifacts\send-fix\send_layout_tests.obj',
 'if errorlevel 1 exit /b 1',
 'artifacts\send-fix\send_layout_tests.exe',
 'if errorlevel 1 exit /b 1',
 'cl.exe /nologo /std:c++17 /EHsc /utf-8 /MD /O2 /W4 /D_WIN32_WINNT=0x0A00 /DCPPHTTPLIB_THREAD_POOL_COUNT=4 /I include tests\send_api_tests.cpp src\send_api.cpp src\send_native.cpp src\send_approval.cpp src\send_routes.cpp /Fe:artifacts\send-fix\send_api_tests.exe /Fo:artifacts\send-fix\ /link bcrypt.lib version.lib ole32.lib ws2_32.lib crypt32.lib',
 'if errorlevel 1 exit /b 1',
 'artifacts\send-fix\send_api_tests.exe',
 'if errorlevel 1 exit /b 1',
 'cl.exe /nologo /std:c++17 /EHsc /utf-8 /MD /O2 /W4 /D_WIN32_WINNT=0x0A00 /I include tests\send_image_tests.cpp src\send_api.cpp src\send_native.cpp /Fe:artifacts\send-fix\send_image_tests.exe /Fo:artifacts\send-fix\ /link bcrypt.lib version.lib ole32.lib',
 'if errorlevel 1 exit /b 1',
 'artifacts\send-fix\send_image_tests.exe',
 'if errorlevel 1 exit /b 1',
 'cl.exe /nologo /std:c++17 /EHsc /utf-8 /MD /O2 /W3 /LD /DWECHAT_HOOK_SEND_ONLY=1 /D_WIN32_WINNT=0x0A00 /DCPPHTTPLIB_THREAD_POOL_COUNT=4 /I include /I minhook\include /I 3rdparty src\dllmain_send.cpp src\version_proxy.cpp src\send_api.cpp src\send_native.cpp src\send_approval.cpp src\send_routes.cpp /Fo:artifacts\send-fix\ /link /DEF:version.def /OUT:artifacts\send-fix\version.dll bcrypt.lib version.lib ole32.lib ws2_32.lib crypt32.lib',
 'if errorlevel 1 exit /b 1',
 'cl.exe /nologo /std:c++17 /EHsc /utf-8 /MD /O2 tests\send_proxy_tests.cpp /Fe:artifacts\send-fix\send_proxy_tests.exe /Fo:artifacts\send-fix\send_proxy_tests.obj',
 'if errorlevel 1 exit /b 1',
 ('artifacts\send-fix\send_proxy_tests.exe "'+$out+'\version.dll"'),
 'if errorlevel 1 exit /b 1',
 'cl.exe /nologo /std:c++17 /EHsc /utf-8 /MD /O2 /W4 tests\send_lifetime_tests.cpp /Fe:artifacts\send-fix\send_lifetime_tests.exe /Fo:artifacts\send-fix\send_lifetime_tests.obj /link ws2_32.lib',
 'if errorlevel 1 exit /b 1',
 ('artifacts\send-fix\send_lifetime_tests.exe "'+$out+'\version.dll"'),
 'if errorlevel 1 exit /b 1',
 'cl.exe /nologo /std:c++17 /EHsc /utf-8 /MD /O2 /W4 /I include tests\send_startup_tests.cpp /Fe:artifacts\send-fix\send_startup_dynamic.exe /Fo:artifacts\send-fix\send_startup_dynamic.obj /link ws2_32.lib iphlpapi.lib',
 'if errorlevel 1 exit /b 1',
 'cl.exe /nologo /std:c++17 /EHsc /utf-8 /MD /O2 /W4 /DSEND_STARTUP_STATIC_IMPORT=1 /I include tests\send_startup_tests.cpp /Fe:artifacts\send-fix\send_startup_static.exe /Fo:artifacts\send-fix\send_startup_static.obj /link ws2_32.lib iphlpapi.lib version.lib',
 'if errorlevel 1 exit /b 1',
 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File build\test-send-startup.ps1',
 'if errorlevel 1 exit /b 1',
 'dumpbin.exe /exports artifacts\send-fix\version.dll > artifacts\send-fix\exports.txt',
 'if errorlevel 1 exit /b 1',
 'dumpbin.exe /imports artifacts\send-fix\version.dll > artifacts\send-fix\imports.txt',
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
 if(((Get-Date)-$started).TotalSeconds -gt 300){$stopReason='Five-minute timeout'}
 if($memory -gt 2GB){$stopReason='Sampled process tree working set exceeded 2 GiB'}
 if((Get-PSDrive D).Free -lt 10GB){$stopReason='Disk reserve below 10 GiB'}
 if($stopReason){& taskkill.exe /PID $process.Id /T /F | Out-Null;break}
}
$process.WaitForExit()
$exit=$process.ExitCode
$output=$stdout.GetAwaiter().GetResult()
$errors=$stderr.GetAwaiter().GetResult()
$process.Dispose()
[IO.File]::WriteAllText((Join-Path $out 'build.stdout.log'),$output)
[IO.File]::WriteAllText((Join-Path $out 'build.stderr.log'),$errors)
$output -split "`r?`n" | Select-Object -Last 35
if($errors){$errors -split "`r?`n" | Select-Object -Last 10}
if($stopReason){throw $stopReason}
if($exit -ne 0){throw "Build/tests failed: $exit"}
$dll=Join-Path $out 'version.dll'
[ordered]@{ExitCode=$exit;ElapsedSeconds=[math]::Round(((Get-Date)-$started).TotalSeconds,1);SampledPeakTreeBytes=$peak;Bytes=(Get-Item -LiteralPath $dll).Length;SHA256=(Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash;NoWeChatGuestAccess=$true;SendingPermissionCreated=$false} | ConvertTo-Json | Tee-Object -FilePath (Join-Path $out 'build-result.json')

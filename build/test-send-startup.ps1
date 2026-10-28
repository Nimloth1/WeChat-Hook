$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -ne 'DESKTOP-V8117LP'){throw 'Offline startup tests only on PW'}
$root=Split-Path $PSScriptRoot -Parent
$out=Join-Path $root 'artifacts\send-fix'
$dll=Join-Path $out 'version.dll'
if((Get-PSDrive D).Free -lt 10GB){throw 'Need 10 GiB reserve'}
if(@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object {$_.LocalPort -eq 30001}).Count){throw 'PW 30001 already owned; no process changed'}
$fixture=Join-Path $out ('startup-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$results=@()
$socket=$null
try{
 Copy-Item -LiteralPath $dll -Destination (Join-Path $fixture 'version.dll')
 foreach($binary in @('send_startup_dynamic.exe','send_startup_static.exe')){
  foreach($mode in @('ready','collision','child')){
   Copy-Item -LiteralPath (Join-Path $out $binary) -Destination (Join-Path $fixture 'Weixin.exe') -Force
   $profile=Join-Path $fixture ('profile-'+[Guid]::NewGuid().ToString('N'))
   New-Item -ItemType Directory -Path $profile | Out-Null
   if($mode -eq 'collision'){
    $socket=New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
    $socket.ExclusiveAddressUse=$true
    $socket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,30001))
    $socket.Listen(1)
   }
   $info=New-Object Diagnostics.ProcessStartInfo
   $info.FileName=Join-Path $fixture 'Weixin.exe'
   $info.Arguments='"'+(Join-Path $fixture 'version.dll')+'" "'+$profile+'" '+$mode
   if($mode -eq 'child'){$info.Arguments+=' --type=renderer'}
   $info.EnvironmentVariables['LOCALAPPDATA']=$profile
   $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
   $process=New-Object Diagnostics.Process;$process.StartInfo=$info
   $null=$process.Start();$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
   if(-not $process.WaitForExit(10000)){$process.Kill();$process.WaitForExit();throw 'Synthetic child timeout'}
   $case=[ordered]@{Binary=$binary;Mode=$mode;Exit=$process.ExitCode;Output=$stdout.GetAwaiter().GetResult();Error=$stderr.GetAwaiter().GetResult()}
   $process.Dispose()
   if($socket){$socket.Dispose();$socket=$null}
   $results+=$case
   if($case.Exit -ne 0){$results | ConvertTo-Json -Depth 5;throw 'Startup diagnostics regression'}
   if(Test-Path -LiteralPath (Join-Path $profile 'VW12-WeChatHook')){throw 'Unexpected permission or state file'}
  }
 }
 [ordered]@{Cases=$results;PrivateCalls=0;PostCalls=0;RealWeChatLoaded=$false;VW12Accessed=$false;VW11Accessed=$false} | ConvertTo-Json -Depth 5 | Tee-Object -FilePath (Join-Path $out 'startup-tests.json')
}finally{
 if($socket){$socket.Dispose()}
 if(Test-Path -LiteralPath $fixture){Remove-Item -LiteralPath $fixture -Recurse -Force}
}

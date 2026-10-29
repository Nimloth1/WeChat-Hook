param([switch]$ReadCache)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new()
if(-not $ReadCache){throw 'Explicit read-cache scope is required. This does not authorize sending.'}
if($env:COMPUTERNAME -ne 'VW12'){throw 'VW12 only'}
if([Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'VW12\maegl'){throw 'Wrong account'}
if([IntPtr]::Size -ne 8){throw '64-bit PowerShell required'}
$permit=Join-Path $env:LOCALAPPDATA 'VW12-WeChatHook\send-approval.json'
if(Test-Path -LiteralPath $permit){throw 'Sending permit present; no actions taken'}
$all=@(Get-CimInstance Win32_Process -Filter "Name='Weixin.exe'")
$main=@($all | Where-Object {$_.ExecutablePath -eq 'C:\Program Files\Tencent\Weixin\Weixin.exe' -and $_.CommandLine -notmatch '--type=|--crashpad-handler'})
if($main.Count -ne 1){throw 'One unambiguous main Weixin process required'}
$wechat=$main[0]
$owner=Invoke-CimMethod -InputObject $wechat -MethodName GetOwner
if(($owner.Domain+'\'+$owner.User) -ne 'VW12\maegl'){throw 'Unexpected Weixin owner'}
$started=$wechat.CreationDate.ToUniversalTime().ToString('o')
$processStarted=([Diagnostics.Process]::GetProcessById($wechat.ProcessId)).StartTime.ToUniversalTime().ToFileTimeUtc()
Add-Type -Path (Join-Path $PSScriptRoot 'contact_cache_reader.cs')
$result=[ContactCacheReadOnly.Reader]::Scan($wechat.ProcessId,$processStarted)
$after=Get-CimInstance Win32_Process -Filter ('ProcessId='+$wechat.ProcessId)
if(-not $after -or $after.CreationDate.ToUniversalTime().ToString('o') -ne $started){throw 'Process changed; discard result'}
[ordered]@{
 Computer='VW12';UTC=[DateTime]::UtcNow.ToString('o');ProcessId=$wechat.ProcessId;StartedUtc=$started
 Observation=$result;ActualContactMembershipVerified=$false;RawMemorySaved=$false
 TargetCodeExecuted=$false;DatabaseKeySearchOrExtractionPerformed=$false;DatabaseQueried=$false
 RawPagesMayContainUnrelatedSensitiveData=$true
 HookChanged=$false;SendRequests=0;LoginActions=0;VW11Accessed=$false
} | ConvertTo-Json -Depth 6

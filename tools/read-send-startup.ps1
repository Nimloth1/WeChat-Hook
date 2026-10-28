param([Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ReviewedSHA256)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new()
if($env:COMPUTERNAME -ne 'VW12' -or [Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'VW12\maegl' -or [IntPtr]::Size -ne 8){throw 'Only VW12/maegl/x64'}
$path='C:\Program Files\Tencent\Weixin\version.dll'
$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
if($hash -ne $ReviewedSHA256){throw 'Reviewed disk DLL mismatch'}
$main=@(Get-CimInstance Win32_Process -Filter "Name='Weixin.exe'" | Where-Object {$_.CommandLine -notmatch '--type=|--crashpad-handler'})
if($main.Count -ne 1 -or $main[0].ExecutablePath -ne 'C:\Program Files\Tencent\Weixin\Weixin.exe'){throw 'Expected one installed Weixin main process'}
$owner=Invoke-CimMethod -InputObject $main[0] -MethodName GetOwner
if(($owner.Domain+'\'+$owner.User) -ne 'VW12\maegl'){throw 'Unexpected process owner'}
$module=@(([Diagnostics.Process]::GetProcessById($main[0].ProcessId)).Modules | Where-Object {$_.FileName -eq $path})
if($module.Count -ne 1){throw 'Reviewed module not observed'}
$csharp=@'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class StartupExportReader {
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int id);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr process,IntPtr at,byte[] data,UIntPtr size,out UIntPtr read);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 public static int LastReadBytes;
 static byte[] Read(IntPtr handle,long at,int size) {
  if(size<1 || size>512 || LastReadBytes+size>8192)throw new InvalidOperationException("metadata_budget");
  var data=new byte[size];UIntPtr got;
  if(!ReadProcessMemory(handle,new IntPtr(at),data,(UIntPtr)size,out got) || got.ToUInt64()!=(ulong)size)throw new Win32Exception(Marshal.GetLastWin32Error());
  LastReadBytes+=size;return data;
 }
 static byte[] Rva(IntPtr handle,long image,uint length,uint rva,int size) {
  if(rva>length || (uint)size>length-rva)throw new InvalidOperationException("rva_outside_module");
  return Read(handle,image+rva,size);
 }
 public static uint[] Query(int pid,long image,uint expectedSize) {
  if(expectedSize<4096 || expectedSize>1048576)throw new InvalidOperationException("unexpected_module_size");
  LastReadBytes=0;
  var handle=OpenProcess(0x410,false,pid);if(handle==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
  try {
   var dos=Read(handle,image,64);int pe=BitConverter.ToInt32(dos,60);
   if(BitConverter.ToUInt16(dos,0)!=0x5a4d || pe<0 || (ulong)pe+256>expectedSize)throw new InvalidOperationException("not_pe");
   var nt=Read(handle,image+pe,256);
   if(BitConverter.ToUInt32(nt,0)!=0x4550 || BitConverter.ToUInt16(nt,4)!=0x8664 || BitConverter.ToUInt16(nt,24)!=0x20b)throw new InvalidOperationException("not_x64_pe");
   uint length=BitConverter.ToUInt32(nt,80),exports=BitConverter.ToUInt32(nt,136),exportSize=BitConverter.ToUInt32(nt,140);
   if(length!=expectedSize || exports==0)throw new InvalidOperationException("unexpected_proxy_image");
   var directory=Rva(handle,image,length,exports,40);
   uint functions=BitConverter.ToUInt32(directory,20),names=BitConverter.ToUInt32(directory,24);
   uint addressTable=BitConverter.ToUInt32(directory,28),nameTable=BitConverter.ToUInt32(directory,32),ordinalTable=BitConverter.ToUInt32(directory,36);
   if(names>64 || functions>64 || names==0)throw new InvalidOperationException("export_budget");
   for(uint i=0;i<names;i++) {
    uint name=BitConverter.ToUInt32(Rva(handle,image,length,checked(nameTable+i*4),4),0);
    var bytes=Rva(handle,image,length,name,32);int end=Array.IndexOf(bytes,(byte)0);
    if(end<0 || System.Text.Encoding.ASCII.GetString(bytes,0,end)!="SendFixStartupState")continue;
    uint ordinal=BitConverter.ToUInt16(Rva(handle,image,length,checked(ordinalTable+i*2),2),0);
    if(ordinal>=functions)throw new InvalidOperationException("bad_ordinal");
    uint address=BitConverter.ToUInt32(Rva(handle,image,length,checked(addressTable+ordinal*4),4),0);
    if(address>=exports && (ulong)address<(ulong)exports+exportSize)throw new InvalidOperationException("forwarded_export");
    var data=Rva(handle,image,length,address,40);
    if(BitConverter.ToUInt32(data,0)!=0x31534653 || BitConverter.ToUInt32(data,4)!=1 || BitConverter.ToUInt32(data,8)!=40)throw new InvalidOperationException("startup_schema_mismatch");
    var fields=new uint[10];for(int field=0;field<10;field++)fields[field]=BitConverter.ToUInt32(data,field*4);
    return fields;
   }
   throw new InvalidOperationException("startup_export_missing");
  } finally {CloseHandle(handle);}
 }
}
'@
Add-Type -TypeDefinition $csharp
$fields=[StartupExportReader]::Query($main[0].ProcessId,$module[0].BaseAddress.ToInt64(),[uint32]$module[0].ModuleMemorySize)
[ordered]@{Computer=$env:COMPUTERNAME;CheckedUtc=[DateTime]::UtcNow.ToString('o');ProcessId=$main[0].ProcessId;DiskSHA256=$hash;Schema=$fields[1];LoaderStage=$fields[3];WorkerStage=$fields[4];ObservedWin32Error=$fields[5];ObservedWinsockError=$fields[6];WorkerThreadId=$fields[7];StandardErrorCode=$fields[8];StandardErrorCategory=$fields[9];MetadataBytesRead=[StartupExportReader]::LastReadBytes;TargetMemoryWritten=$false;TargetFunctionsCalled=0;SendRequests=0} | ConvertTo-Json

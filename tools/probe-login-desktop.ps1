# 只读可见窗口，OCR 仅在本机内存中匹配固定提示，不输出/保存正文或截图。
param([Parameter(Mandatory=$true)][string]$OutputPath, [switch]$SelfTest)
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'VW12') { throw 'wrong_host' }
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Runtime.WindowsRuntime
Add-Type @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class LoginWindowProbe {
  public delegate bool Callback(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] static extern bool EnumWindows(Callback f, IntPtr p);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out Rect r);
  public struct Rect { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder b, int n);
  public class Window { public long Handle; public string NativeClass; }
  public static List<Window> Read(int[] pids) {
    var ids = new HashSet<int>(pids); var result = new List<Window>();
    EnumWindows((h,p) => {
      uint id; GetWindowThreadProcessId(h, out id);
      if (ids.Contains((int)id) && IsWindowVisible(h)) {
        var b = new StringBuilder(256); GetClassName(h,b,256);
        result.Add(new Window { Handle=h.ToInt64(), NativeClass=b.ToString() });
      }
      return result.Count < 64;
    }, IntPtr.Zero);
    return result;
  }
}
'@
function Await-Operation($operation, [Type]$type) {
    $method = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1
    $task = $method.MakeGenericMethod($type).Invoke($null, @($operation))
    if (-not $task.Wait(5000)) { throw 'ocr_timeout' }
    return $task.Result
}
[Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder,Windows.Graphics.Imaging,ContentType=WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.SoftwareBitmap,Windows.Graphics.Imaging,ContentType=WindowsRuntime] | Out-Null
[Windows.Media.Ocr.OcrResult,Windows.Foundation,ContentType=WindowsRuntime] | Out-Null
$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
function Read-PromptFlags([long]$handle, [string]$sample='') {
    $rect = [LoginWindowProbe+Rect]::new()
    if ($sample) { $rect.Right=1000; $rect.Bottom=300 }
    elseif (-not [LoginWindowProbe]::GetWindowRect([IntPtr]$handle, [ref]$rect)) { throw 'window_rect_failed' }
    $width = $rect.Right-$rect.Left; $height = $rect.Bottom-$rect.Top
    if ($width -lt 100 -or $height -lt 100 -or $width -gt 3000 -or $height -gt 2000) { return $null }
    if ($null -eq $engine) { throw 'ocr_language_unavailable' }
    $bitmap = [Drawing.Bitmap]::new($width,$height)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $stream = [IO.MemoryStream]::new()
    $random = $null; $software = $null
    try {
        if ($sample) {
            $graphics.Clear([Drawing.Color]::White)
            $font = [Drawing.Font]::new('Microsoft YaHei',24)
            try { $graphics.DrawString($sample,$font,[Drawing.Brushes]::Black,20,60) }
            finally { $font.Dispose() }
        } else {
            $dc = $graphics.GetHdc()
            try { $captured = [LoginWindowProbe]::PrintWindow([IntPtr]$handle,$dc,2) }
            finally { $graphics.ReleaseHdc($dc) }
            if (-not $captured) { throw 'capture_unavailable' }
        }
        $bitmap.Save($stream,[Drawing.Imaging.ImageFormat]::Png); $stream.Position = 0
        $random = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($stream)
        $decoder = Await-Operation ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($random)) ([Windows.Graphics.Imaging.BitmapDecoder])
        $software = Await-Operation ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
        $recognized = Await-Operation ($engine.RecognizeAsync($software)) ([Windows.Media.Ocr.OcrResult])
        $text = $recognized.Text -replace '\s',''
        # 不把普通聊天里的“重新登录”单词作为登录提示。
        return [ordered]@{
            readable=($text.Length -gt 0)
            security_relogin=(($text -match '为了.{0,6}安全') -and ($text -match '重新登录|重新登陆'))
            qr_login=(($text -match '扫码登录|扫码登陆|扫描二维码登录') -and ($text -match '微信|WeChat|Weixin'))
            confirm_login=(($text -match '请在手机上确认登录|请在手机上确认登陆'))
        }
    } finally {
        if ($null -ne $software) {$software.Dispose()}
        if ($null -ne $random) {$random.Dispose()}
        $stream.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
    }
}
if ($SelfTest) {
    $samples = @('正常聊天窗口','这段话只有重新登录四个字','为了您的账号安全，请重新登录','为了你的安全，请重新登录','微信 请使用手机扫码登录','请在手机上确认登录')
    $results = @($samples | ForEach-Object { Read-PromptFlags 0 $_ })
    [IO.File]::WriteAllText($OutputPath,($results | ConvertTo-Json -Depth 3 -Compress),[Text.UTF8Encoding]::new($false))
    exit
}
$session = (Get-Process -Id $PID).SessionId
$processes = @(Get-Process Weixin -ErrorAction SilentlyContinue | Where-Object {$_.SessionId -eq $session})
$classes = @()
$ocr = @(); $errors = @(); $attempts = 0
foreach ($w in [LoginWindowProbe]::Read([int[]]@($processes | ForEach-Object {$_.Id}))) {
    $provider = $null
    try {
        # 仅根元素的 ClassName，不读 Name/Value、子元素或聊天正文。
        $root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]$w.Handle)
        $provider = $root.Current.ClassName
    } catch {}
    $classes += [ordered]@{native=$w.NativeClass; provider=$provider}
    if ($attempts -lt 3) {
        $attempts++
        try { $flags = Read-PromptFlags $w.Handle; if ($null -ne $flags) {$ocr += $flags} }
        catch { $errors += 'ocr_unavailable' }
    }
}
$result = [ordered]@{version=1; computer=$env:COMPUTERNAME; observed_utc=[DateTime]::UtcNow.ToString('o');
    session=$session; process_count=$processes.Count; classes=@($classes); ocr=@($ocr); errors=@($errors);
    read_scope='window_classes_and_local_ocr_fixed_flags_no_text_or_images_saved'}
$dir = Split-Path -Parent $OutputPath
$text = $result | ConvertTo-Json -Depth 5 -Compress
$temporary = $OutputPath + '.tmp'
[IO.File]::WriteAllText($temporary, $text, [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $temporary -Destination $OutputPath -Force

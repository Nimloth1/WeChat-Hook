"""PM 五分钟巡检的 VW12 登录提示观察器；不调用 Hook、发送或登录。"""
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time

STATE = Path('/Volumes/ssd/data/vw12-relay/login-watch.json')
REMOTE_STATUS = r'C:\Users\maegl\Downloads\VW12-Setup\login-monitor\status.json'
ALERTS = {
    'security_relogin_prompt': ('VW12：疑似微信安全登录提示',
        '本地OCR识别到安全/重新登录提示，请查看 VW12 并自行确认登录。未自动扫码、重开或重试消息。'),
    'login_prompt': ('VW12：微信显示登录提示',
        '本地窗口识别到扫码或手机确认登录提示，请在 VW12 查看并自行登录。未操作账号或发送消息。'),
    'client_not_running': ('VW12：未发现微信进程',
        '桌面探针未发现微信进程，请查看 VW12。无法仅凭这一点确定是否被风控退出。'),
    'unobservable': ('VW12：暂时无法判断微信登录状态',
        '探针无法读取有效窗口，或结果已过期；可能是锁屏、窗口隐藏或连接异常。不能确认是否掉线，请查看 VW12。'),
}


def classify(report, now):
    """只识别可见提示，不将进程/主窗口/无提示解释为服务端登录证明。"""
    if (report.get('version') != 1 or report.get('computer') != 'VW12'
            or type(report.get('session')) is not int or report['session'] <= 0
            or type(report.get('process_count')) is not int or report['process_count'] < 0):
        return 'unobservable'
    try:
        observed = datetime.fromisoformat(report['observed_utc'].replace('Z', '+00:00'))
        age = now - observed.astimezone(timezone.utc).timestamp()
    except (KeyError, ValueError, TypeError, AttributeError):
        return 'unobservable'
    if not -60 <= age <= 720:
        return 'unobservable'
    if report['process_count'] == 0:
        return 'client_not_running'
    ocr = report.get('ocr', [])
    classes = report.get('classes', [])
    if not isinstance(ocr, list) or not isinstance(classes, list):
        return 'unobservable'
    if any(x.get('security_relogin') is True for x in ocr if isinstance(x, dict)):
        return 'security_relogin_prompt'
    if (any(x.get('qr_login') is True or x.get('confirm_login') is True
            for x in ocr if isinstance(x, dict))
            or any('mmui::LoginWindow' in (x.get('native'), x.get('provider'))
                   for x in classes if isinstance(x, dict))):
        return 'login_prompt'
    if any(x.get('readable') is True for x in ocr if isinstance(x, dict)):
        return 'no_login_prompt_observed'
    return 'unobservable'


def observe():
    ps = ("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
          "if($env:COMPUTERNAME -ne 'VW12'){throw 'wrong_host'};"
          "[IO.File]::ReadAllText('" + REMOTE_STATUS + "')")
    encoded = base64.b64encode(ps.encode('utf-16le')).decode()
    result = subprocess.run(
        ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', 'VW12',
         'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + encoded],
        capture_output=True, timeout=30, check=True,
    )
    if len(result.stdout) > 32768:
        raise ValueError('oversize_report')
    return json.loads(result.stdout.decode('utf-8-sig'))


def notify(title, body):
    result = subprocess.run(
        ['/opt/homebrew/bin/python3', str(Path.home() / '.local/bin/bark-notify.py'),
         '--title', title, '--body', body, '--group', 'VW12微信登录', '--level', 'active'],
        capture_output=True, timeout=12,
    )
    return result.returncode == 0


def update(path, status, send=notify):
    previous = json.loads(path.read_text()) if path.exists() else {}
    # 同状态不改文件、不重复通知，通知失败由既有 Healthchecks 报警。
    if previous.get('status') == status:
        return previous.get('notification_failed', False)
    state = {'status': status, 'notification_failed': False}
    if status in ALERTS:
        title, body = ALERTS[status]
        # 先保存本次通知尝试，避免进程在发送后退出导致重复推送。
        state['notification_failed'] = True
    elif previous.get('status') in ALERTS:
        title, body = ('VW12：登录提示已消失',
            '探针重新读到可见微信窗口，当前未识别到登录提示。这不等同于服务端在线或消息送达证明。')
        state['notification_failed'] = True
    else:
        title = body = None
    def save():
        text = json.dumps(state, ensure_ascii=False, sort_keys=True) + '\n'
        if path.exists() and path.read_text() == text:
            return
        temporary = path.with_suffix('.tmp')
        with open(temporary, 'w', opener=lambda p, flags: os.open(p, flags, 0o600)) as f:
            f.write(text)
        temporary.replace(path)
    save()
    if title:
        state['notification_failed'] = not send(title, body)
        save()
    return state['notification_failed']


def main():
    try:
        status = classify(observe(), time.time())
    except (OSError, ValueError, subprocess.SubprocessError):
        status = 'unobservable'
    failed = update(STATE, status)
    print(status + (':notification_failed' if failed else ''))
    return int(status in ALERTS or failed)


if __name__ == '__main__':
    raise SystemExit(main())

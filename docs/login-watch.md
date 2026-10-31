# VW12 登录提示监控

DLL 的 `/QueryDB/status` 返回 `IsLogin=null / LoginStateKnown=false`，不能作为登录检测器。
本功能观察微信可见窗口里的登录提示，不新增原生调用、Hook、消息测试或账号动作；不判断账号被退出的原因。

## 两端分工

- VW12 `VW12-WeChat-Login-Observe`：以已登录桌面用户的普通权限，每5分钟及用户登录Windows时运行
  `tools/probe-login-desktop.ps1`。只枚举 Weixin 的可见顶层窗口，读取根类名。
  当前4.1.10.27仅暴露通用Qt类，因此再使用系统中文OCR在本机内存中匹配固定提示。
  窗口像素/文字（可能包括聊天内容或二维码）只临时存在本机内存，不保存、不上传；结果仅含固定布尔值。
- PM 的既有五分钟 `keepalive-probe` 增加观察项，运行 `tools/watch_login_pm.py`。
  只通过SSH读取上述小JSON；不用Hook接口、不发消息、不修改转发账本。
  Bark普通通知提醒本人；登录/安全提示和监控失败同时使既有Healthchecks观察项失败，沿用既有Feishu渠道。
  同状态只通知一次，提示消失时通知一次；通知接口失败也保留失败状态，不把失败改绿。

## 状态与限制

固定安全文字与重新登录同时出现、扫码登录/手机确认提示、或明确LoginWindow类会触发提醒。
进程不存在提醒检查客户端。报告超过12分钟、连接失败、黑屏/隐藏窗口/本地识别不可用返回
`unobservable`，提醒“无法判断”，不能要求用户据此扫码。

`no_login_prompt_observed`只表示窗口可读且未匹配到提示，**不是服务端登录证明**。
截图OCR可能遗漏不同措辞、遮挡、缩放等情况；聊天里引用完整提示也可能误触发，通知必须由用户查看确认。
不通过故意退出、踢下线或真实发送验证；不能保证发现所有掉线。两端各5分钟巡检，正常提醒延迟约5–10分钟。
监控独立于转发；不自动登录、重开、暂停/恢复队列、重试任务或操作VW11。

## 调度、资源与回退

Windows任务仅普通Interactive用户，不保存密码；单次45秒，重叠跳过。最多3个窗口、单窗最大3000×2000，
异步OCR每步5秒。内存预算低于300MiB；状态小文件每5分钟更新，288轮约数百KiB/天，
含PowerShell临时编译预计低于100MiB/天。PM无变化不重写状态；无独立常驻进程、额外端口或独立Healthchecks心跳。
若部署后测量超预算，应停止新观察项并排查，不影响原转发配置。

部署目录为私有运维状态，不进Git：VW12 `Downloads/VW12-Setup/login-monitor/`，
PM `/Volumes/ssd/projects/d/vw12-relay/ops/login-monitor/`，
去重状态 `/Volumes/ssd/data/vw12-relay/login-watch.json`。
回退只需移除PM探针新增观察项并禁用/删除该Windows任务；不恢复或修改微信/DLL/队列。

验证：`python3 -B -m unittest discover -s tests -p 'test_login_watch.py'`。
Windows `probe-login-desktop.ps1 -SelfTest -OutputPath <临时JSON>` 用6张合成文字图检验系统OCR：
两项负例、两种安全提示、扫码、手机确认；不打开测试窗口或接触微信。真实探针必须经Windows调度器执行验证。
Bark接口接受成功不等于手机已收到；HTTP202与原生进入也不等于消息送达。

参考：[系统OCR](https://learn.microsoft.com/en-us/uwp/api/windows.media.ocr.ocrengine.trycreatefromuserprofilelanguages)、
[PrintWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-printwindow)。PrintWindow是同步窗口渲染请求，
可能阻塞，所以由有45秒上限的独立探针调用，不在微信线程中运行。

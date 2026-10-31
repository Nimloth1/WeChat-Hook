# 自动转发图片 422：诊断补丁与当前阻塞

## 已确认的故障

2026-10-31 东京时间 09:50 恢复 PR11 自动转发后，10 条文字取得
`submitted_unconfirmed` 回执；这不是送达证明。09:51:08 首张图片的来宾回执为
`post_attempts=1`、HTTP422、`native_entered=false`、`response_state=not_attempted`。
两端随后暂停，失败图片没有重试。旧的 POST=0 图片已经另外运维结案，不属于本补丁。

DLL 的 `Response()` 本来包含固定 `error` 码，但执行器没有持久化它；
PM 在失败回执校验后又只保存 `remote_result_unknown`。因此当时究竟是哪项原生预检
拒绝，不能从现存回执恢复。不能把 `ValueError` 等同于某一个路径或摘要错误。

## 本补丁完成的工作

- 文字、图片、文件、视频和链接共用的来宾回执保存固定 `hook_error` 码。
- PM 只在回执的任务 ID 和摘要都匹配时保留这些诊断字段，同时写入 `dispatch_failed` 日志。
- 错误码只接受已知常量；其他内容记为 `unrecognized_hook_error`，不记录任意异常原文、路径、正文或 token。
- 未提供 `NativeEntered` 的异常响应保持未知，不再以 `false` 冒充未进入原生函数。
- 原有逐条许可、消费标记、暂停、不重试和素材回收行为不变；没有恢复/清账入口。

没有修改 DLL、偏移、文件稳定路径锁或原生发送参数；不需要为此补丁重开客户端。
本次未部署、未操作微信登录、未访问 VW11，也未再次调用真实发送接口。

## 离线验证的范围

`tests/relay_approval_contract.cpp` 默认使用生产 `Controller` 和替身发送后端。
五种消息都由生产执行器创建许可，再让生产 C++ 校验器返回合成的固定预检错误；
验证 HTTP422/错误码/未进入原生函数的证据到达两端账本及 PM 日志，且重放不再次调用。

Windows 另有 `RELAY_NATIVE_IMAGE_PREFLIGHT` 构建：链接生产 `send_native.cpp`，
仅调用 `OpenImage`，发送后端仍是替身，不调用 `WindowsBackend::Prepare` 或微信函数。
在 PW 的临时 AppData 目录使用真实执行器目录结构和执行器文件锁，测试合成 PNG、中文名称及
1 MiB JPEG。文件摘要、长度及生产路径锁均通过。临时文件在测试结束后清理。
这证明这些合成条件可以通过，不代表复现了真实微信进程的故障。

## 图片根因仍未确证

**图片 422 尚未修好，不应将此补丁称作完整图片修复。** 当前离线实验未复现拒绝，
而历史响应的具体错误码已经丢失。不能据此移除文件锁、放宽摘要校验、添加重试或猜改原生 ABI。

若先审核并部署本诊断补丁，后续仍须由用户决定是否恢复队列或批准一条新的图片观察；
此次失败图片继续不重试。部署诊断补丁本身不授权发送，不清除两端暂停状态。
只有取得固定错误码、复现实际失败条件后，才能确认图片修复方案。

## 复现命令

PM：`python -B -m unittest discover -s tests -p 'test*relay*.py'`。
macOS 的生产 C++ 许可/Controller 检查使用 ASan/UBSan。

PW：`powershell.exe -NoProfile -ExecutionPolicy Bypass -File build/test-relay-approval.ps1`。
只在 PW 构建两个离线夹具；3 分钟、2 GiB 采样工作集及 D 盘 10 GiB 保留空间保护。
不会构建 DLL，也不运行此前被 Defender 隔离的 lifetime 测试程序。

最终结果：PM 39 项，36 通过、3 项 Windows 专属检查跳过；生产 C++ 契约检查的
ASan/UBSan 无报告。PW 39 项，37 通过、2 项 PM 媒体检查跳过；其中实际图片文件预检
通过。PW 总耗时 50.4 秒，进程树采样峰值 182321152 字节。
这不是 DLL 全量回归，也不代表真实微信 ABI 或图片发送已验证。

## 临时恢复节奏（2026-10-31）

用户要求恢复积压时先每分钟一条。PM 配置可设置 `dispatch_interval_seconds: 60`，
仅 PM 串行执行器根据账本中最近一次调用的完成时间等待；来宾不增加第二套限流。
等待时不 claim、不上传、不消耗许可、不暂停；进程重启继续使用同一账本时间。
默认值0保留原行为，后续移除临时配置即可取消。该间隔不保证微信账号安全，
也不改变既有24小时规则、目标、逐条许可、防重放或未知结果不重试。

# Windows 暂存附件权限修复

## 原因与证据

2026-10-31 恢复转发时，文件预检返回 `attachment_path_not_stable`，
HTTP422、NativeEntered=false。Python上传/目录处理位于高权限SSH进程，
微信桌面进程使用同一账号的普通用户令牌。

Windows Python3.13对mkdir(mode=0700)生成独立DACL，只允许令牌默认owner和SYSTEM；
高权限进程的owner可以是Administrators。receive在这种目录创建附件后，
同卷rename到assets仍保留原ACL，所以桌面用户不能读附件。

用实际receive及rename链路、合成PDF和现有桌面令牌复现：高权限读取成功，
桌面读取文件返回WinError5。未调用微信函数、未读取进程内存、未发送消息。
旧版与修复版对照回归中，PDF/JPEG/MP4三个旧版子案例均失败，修复版均通过。
这定位的是可重现的权限故障；已丢失错误码的历史图片无法逐条追溯证明。

## 最小修改

Windows目录创建继承预配置私有数据根的DACL；不使用0700覆盖继承。
POSIX保留0700。共享创建模式用于Store新建根、receive新建暂存目录和snapshot目录。
PM视频处理是macOS专用，保留其0700。

前提是部署根已经限制为该用户、SYSTEM和Administrators；本次核对现有VW12根ACL，
不新增Everyone或Authenticated Users权限，不改已有根ACL或已有文件。
DLL的逐层父目录锁、重解析点拒绝、文件摘要、一次性许可和防重放均未改。

## 验证与部署

PM：43项，38通过、5项平台检查跳过，包含生产C++契约ASan/UBSan。
VW12嵌入式Python3.13：test_relay_windows_acl.py，显式指定现有桌面令牌PID。
2项中Windows用例通过、POSIX用例跳过；Windows用例包含PDF/JPEG/MP4三个子案例。
该回归不调用微信函数，仅在临时私有目录操作合成文件并查询令牌。

此次只改Python，可按项目约定直接部署并恢复原自动转发范围，无需重开微信。
保持用户临时dispatch_interval_seconds=60；不重试此前失败图片/文件。
部署及实际运行结果以私有运维记录为准，离线通过不代表消息送达或账号安全。

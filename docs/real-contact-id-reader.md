# 真实 ID 入口：只读缓存工具候选，尚未读取

目标是列出 VW12 两位好友和“PAYL能化观察”的真实 ID，不发送、不动登录或 VW11。
现有发送 DLL 没有联系人查询入口，本次没有修改、重新加载或替换它。
用户此前明确选择 DLL 进程内方向；下述 Windows 只读缓存方法是另一个读取入口，
仍在等待用户确认是否接受，不能把本工具准备好当成已获得执行许可。

## 核对的新来源

发现同版本项目 [mosheng20205/WechatHook4.1.10.27](https://github.com/mosheng20205/WechatHook4.1.10.27/tree/713ec7d6f01d858e067a623c9bf2cda64d0d3e19)。
固定提交 `713ec7d6f01d858e067a623c9bf2cda64d0d3e19` 的
`src/inline_weixin_dll_load.cpp` 中 `Hook_ContactResponseParser` 记录了1080字节 Contact 结构：
username 在 +0x08，nickname 在 +0xD8，均为32字节的 native string。
原项目会安装多个代码 Hook；其 `/GetContacts` 还向 SQLite 所在线程提交查询。
这些是第三方项目的代码/说明，不是我们对 VW12 的验证结果；没有运行它的二进制或照搬 Hook。
仅把字段布局作为只读解析候选线索，不把扫描地址交给任何微信/SQLite 函数。

## 工具实际行为

- `tools/read-contact-ids.ps1` 默认拒绝运行，必须显式提供 `-ReadCache`。
- 只允许 VW12、maegl 和唯一主 Weixin.exe；要求发送许可不存在。
  使用实际打开的进程句柄再核对创建时间和完整可执行路径，防止 PID 复用时读错对象。
- `contact_cache_reader.cs` 仅以 `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` 打开进程。
  导入为 OpenProcess、VirtualQueryEx、ReadProcessMemory、CloseHandle、GetProcessTimes、QueryFullProcessImageName；
  没有写内存、远程线程、挂起、注入、模块加载或网络接口。
- 只扫描已提交的 private、可读且不可执行区域，不扫描映像/映射文件页。
  流式查找 wxid_ / 数字@chatroom 字符串，再核对引用它们的 native string 与昵称字段；
  字符串元数据和内容重复读取，变化/越界/读取失败的候选不接受。
- 原始页面可能经过聊天缓存、账号信息等其他敏感数据；这不是“只读取三个联系人占用的内存”。
  不搜索/提取密钥，不输出或落盘原始页面，只返回 ID、昵称和候选状态。
- 最多两个各240MiB的流式遍历，总读取512MiB、45秒检查、4096个字符串位置、256种 ID、32个候选。
  预算内未覆盖全部区域会明确标记 partial；所有结果 `Complete=false`，不能声称完整好友名单。
  单块1MiB并限制字符串拷贝，预计辅助进程内存低于256MiB，但没有整进程硬内存配额。
  ReadProcessMemory/正则调用返回前不能保证45秒是硬截止；不杀微信进程来取消。
  不保存内存转储，不创建常驻服务或定时任务；新增源码约15KiB，临时编译产物预计小于10MiB。

实际执行前需用户接受这一入口。执行命令（本轮未执行）：

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\read-contact-ids.ps1 -ReadCache
```

缓存扫描只能给候选：残留记录、不同结构、尚未加载的数据都可能造成误报或漏报。
稳定的两次读取不是数据库快照、对象生命周期或好友关系的证明。
即使拿到三个候选，也需核对姓名/群名，不能据此直接解锁发送。
没有承诺只读操作不会触发客户端检测；此前安全提示原因仍未知。

## 本轮验证与未完成

PW Windows PowerShell Add-Type 编译通过，并验证在 PW 调用时由 VW12 主机保护拒绝，未打开微信进程。
PowerShell 脚本语法检查通过，不带 ReadCache 开关时的默认拒绝检查通过。
验证只涉及编译和主机门禁，未测试所有保护、Windows 读取结果或真实联系人结构。
VW12 仅进行动态 OS 进程/发送许可检查：主进程2288，发送许可不存在。
一次旧辅助脚本因写死的历史 PID 1596 不存在而失败，随后改为动态枚举；失败没有修改任何进程。
没有实际扫描缓存，没有拿到好友/群 ID，没有调用 Hook API、取钥、登录或发送，没有访问 VW11。
实际读取等待用户在“允许 Windows 只读缓存”与“坚持 DLL 入口先审核”之间确定路线。

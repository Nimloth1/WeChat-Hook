# MP4 视频、链接卡片与其他附件发送

本文记录PR8审核时的历史接口。后续自动转发变更取消附件20/100MiB门槛，现行候选行为及未部署状态见[转发审核说明](pm-relay-review.md)。

## 本次范围

普通附件 `/send_file_msg` 已经支持任意扩展名，本次保留其协议和实现，补充 MP3/WAV/M4A、MP4、DOCX/XLSX/PPTX、ZIP/TXT/CSV 文件名、扩展名、摘要和克隆持锁回归。音频按可下载播放的附件处理，不实现微信原生语音气泡。新增 `/send_video_msg` 和 `/send_link_msg`，视频按原生类型43构造，卡片按49/5构造，不把普通文件或文字URL算作原生视频/卡片。

不包含 PM 采集/转发改动、联系人查询、部署、发送许可、真实发送、微信登录、微信数据库或进程内存读取，也不操作 VW11。仅复制已知安装路径中的固定腾讯程序文件用于静态分析和隔离夹具。未运行作者发布 DLL，未启用旧 XML 转发、协议任务捕获、MinHook、默认补丁或模块隐藏。

## 接口与逐条许可

所有接口仍只绑定127.0.0.1，经现有Bearer校验和 Controller。v2许可仍为相同九字段，固定单个数字群ID、请求ID、类型、完整内容摘要和腾讯模块摘要，逐请求读取，持久消耗后才进入任何本条消息的私有函数。没有常开群发送授权、自动重试或自动切换到其他类型。

视频请求恰好七字段：

```json
{"request_id":"unique-video-request-0001","wxidorgid":"12345678901@chatroom","path":"C:\\approved\\clip.mp4","file_sha256":"64位小写SHA256","thumbnail_path":"C:\\approved\\cover.jpg","thumbnail_sha256":"64位小写SHA256","duration_seconds":2}
```

`kind=video`，`POST /send_video_msg`。文件沿用100MiB上限，必须是`.mp4`且头部含`ftyp`；缩略图必须通过原有图片检查、20MiB上限及JPEG头检查。**这些检查不是完整媒体解码或编解码器兼容性验证**。调用方应先离线探测源媒体，准备可解码的MP4和JPEG缩略图，并把向上取整的时长秒数一并提交预览；DLL不解析完整MP4、不运行FFmpeg、不转码、不自行下载文件。秒数必须为整数1–86400，不能传浮点、布尔或字符串。

视频许可摘要是如下对象经排序键、紧凑UTF-8 JSON序列化后的SHA256：

```json
{"kind":"video","recipient":"12345678901@chatroom","value":"C:\\approved\\clip.mp4","file_sha256":"...","thumbnail_path":"C:\\approved\\cover.jpg","thumbnail_sha256":"...","duration_seconds":2}
```

视频与缩略图分别逐层锁住祖先和实际文件、流式校验摘要；传给原生对象的两条路径都使用同一已验证对象的卷GUID路径。最后一个被跟踪的原生对象/克隆析构完成后，才释放两组路径锁。任一路径或摘要失败，在消耗许可之前停止，并释放已取得的两组资源。隔离故障保留两组资源，不因超时猜测可释放。

链接请求恰好五字段：

```json
{"request_id":"unique-link-request-0001","wxidorgid":"12345678901@chatroom","title":"能源研究简报","description":"报告摘要","url":"https://example.com/report?a=1&b=2"}
```

`kind=link`，`POST /send_link_msg`。标题1–256 UTF16单元且不能全空白；描述0–2000；URL最多2048。只接受小写`http://`或`https://`、非空ASCII主机与可选有效端口，不接收用户信息、空白、反斜杠、其他协议或外部XML；目前不接受IPv6字面量、Unicode主机名或封面参数，可使用ASCII/punycode主机。标题/描述是原生字符串字段，未手工拼接XML。DLL不访问网页或下载封面，URL打开后的服务端行为不在此验证范围内。

链接许可摘要对象：

```json
{"kind":"link","recipient":"12345678901@chatroom","title":"能源研究简报","description":"报告摘要","url":"https://example.com/report?a=1&b=2"}
```

文字、图片、普通文件的旧许可摘要格式保持不变。`LoadApproval`白名单同步允许`link/video`；新增HTTP测试覆盖真实磁盘许可加载、一次消耗、再请求及重建Controller后拒绝，而不只使用内存许可替身。

## 固定原生版本与静态依据

只允许Weixin.dll 4.1.10.27，183094832字节，SHA256 `f487e4f56930456a25fb0d7b058c77e2dcd364e268d49bdfff4dc0e3be26ba36`，不搜索偏移或适配其他版本。

| 项目 | MP4视频 | 链接卡片 |
|---|---|---|
| 原生工厂 | 0x22A9190 | 0x3F8BA20 |
| 控制块总大小 / 具体对象大小 | 0x770 / 0x760 | 0x8B8 / 0x8A8 |
| 构造器 | 0x18EFD70 | 0x2B52B90 |
| 控制块vtable | 0x84F97F8 | 0x878BE68 |
| 对象vtable | 0x84F9888 | 0x878BDA8 |
| Clone入口（对象vtable[4]） | 0x1778B10 | 0x2B54890 |
| 消息类型object+0xD8 | 43 | 0x500000031（49/5） |
| 接收人 | object+0xB0 | object+0xB0 |
| 其他填充字段 | 视频路径0xE0、名称0x168、字节数0x188、缩略图路径0x720、秒数0x71C | 标题0x708、描述0x728、URL0x798 |

视频字段来自0x4374910链路：0x437498E写缩略图路径、0x437499E写视频路径、0x43749CF写时长、0x43749D5读取文件大小；0x22A59D0的视频分支提供第二处路径/类型/秒数字段依据。保留0x708等构造器默认标志，不把未验证标志含义写成事实；是否需要额外消费者元数据仍须真实单条试验确认。

链接字段来自0x3F895E0的`ForwardWebPage`调用链：0x3F89729读取`url`、0x3F89774读取`title`、0x3F897FB读取`digest`，随后分别写入0x798、0x708、0x728。该函数调用0x3F8BA20并写49/5。原作者发布版虽然包含`/send_xml`，但采用另一条`/cgi-bin/micromsg-bin/sendappmsg`协议任务链路；本实现未接入这条需要额外捕获上下文的链路。

原生工厂都会建立`enable_shared_from_this`弱引用。候选构造完成、发布前建立同样的object+8/+16和strong=1/weak=2；观察器另外持有自己的弱引用。消息/子孙克隆复用PR6配对回收和模块引用保护，未使用定时强行回收或仅靠累计上限维持运行。

## 验证与限制

`build/build-send-fix.ps1`运行布局、实际Prepared预检、许可/HTTP、防重放、代理导出及启动回归。`build/test-native-ownership.ps1 -NativeSample <固定样本>`运行实际生产代码与固定原生指令的构造、排队参数复制、子孙克隆、析构、分配/释放配对，一万次五类型混合循环，以及原有14项和新增视频/卡片各7项故障模式。

新增测试校验两条视频稳定路径在子孙克隆中仍能打开批准的相同内容，校验卡片长中文字符串的复制与释放、全部字段绑定、未授权/跨类型/换字段拒绝、真实许可文件消耗与持久防重放、失败不消耗许可和路径锁释放。不同扩展名的夹具验证的是通用附件传递和名称/扩展名保持，不代表Office格式解析或音视频播放已经端到端验证。原生循环的媒体头夹具也不是可播放影片。

另在离线目录生成了可解码的H264 MP4、JPEG、MP3和PCM WAV，由FFprobe核验编码/时长；仅用于可复现准备流程，不发送，不将这些文件的可解码性算作微信兼容性。macOS布局与内存路径经过ASan/UBSan；这不表示Windows原生指令经过消毒器。

排队后的实际上传业务体在夹具内明确禁止执行。因此**没有验证视频上传、聊天内播放、卡片展示/点击、各类附件下载/打开、服务端接受或账号安全**。新增`NativeVideoRuntimeVerified=false`、`LinkCardRuntimeVerified=false`，`RuntimeCompatibilityVerified/DeliveryConfirmed`仍为false；`LinkCardThumbnailSupported=false`、`NativeVoiceSupported=false`。HTTP202只表示进入本地调用，不是送达回执。

必须先由独立审核检查代码和证据，用户批准部署后，才考虑逐条预览并获批准的真实测试。之前PDF/文字/图片的成功不作为本次新类型的授权或兼容性证明。

最终断言、构建摘要和资源采样见`media-send-results.json`；真实运行台账仍与仓库分离，不包含任何真实群ID、账号、消息内容或密钥。

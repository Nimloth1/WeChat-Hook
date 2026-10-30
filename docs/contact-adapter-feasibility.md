# 联系人进程内适配器：离线可行性与停止条件

基线为已合并 PR #2 的 `7588859`。本轮目标是研究真实适配器的连接来源、生命周期和读取快照；
保持进程内方向，不改为联系人库副本方案，也不扫描真实微信或读取密钥。

**结论：独立拥有读取连接的结构在普通 SQLite 合成实验中可行，但现有资料不足以实现可部署的微信适配器。**
本变更只增加可复现的实验和本文，不增加生产适配器、HTTP 入口、模块偏移、原生 Hook 或新 DLL。
`src/contact_lookup.cpp`、现有发送源码和 DLL 构建均不修改；没有任何代码连接 VW12/VW11。

## 已知源码证据

- `xdb/db_mgr.cpp:searchDatabases` 把 VFS 地址扫描命中当作 `sqlite3*`，并直接调用 errcode/prepare。
  `IsBadReadPtr` 和 errcode 不是对象所有权证明；数据库关闭与地址复用仍可能发生。
  自己的 `m_searchDbMtx` 只保护管理器，不能阻止微信关闭或使用连接。
- `DatabaseMgr` 构造时还修改 backup_init 附近14字节；不使用这个构造器来取得函数表。
- 当前 `xdb/xwechat_offsets.h` 只有 `#pragma once`，没有给出数据库 API/VFS/codec 的偏移值。
  源码里存在函数表结构不代表结构布局、函数地址、调用约定或当前 4.1.10.27 模块已验证。
- `codec_get_key(sqlite3*)` 在函数开头返回空值；备用代码不能提供现成可用的初始化方案。
  本轮没有修复、执行或绕过这条路径。
- 项目没有向我们提供可证明所有权的联系人库读取工厂或安全的 SQLite 生命周期注册机制。
  现有数据库名缓存也没有账号绑定证据。

这些事实说明不能把“找到地址、加 mutex、检查 autocommit”拼成已完成的真实适配器。
SQLite close 接口要求传入仍有效且由 open 系列取得的对象；函数调用本身不能验证扫描命中。
参见 [SQLite close](https://sqlite.org/c3ref/close.html)。

## 本轮实验及结论

`tests/contact_adapter_feasibility.cpp` 没有命令行路径参数，只创建自己的微型临时数据库。
所有标识符都是合成数据；不接受真实数据库或宿主连接。

| 实验 | 实际检查 | 能证明的范围 |
| --- | --- | --- |
| 独立读取连接 | READONLY/FULLMUTEX/PRIVATECACHE 打开；自己设置 query_only 并 BEGIN | 能在自有普通 SQLite 上建立独立读取上下文 |
| 宿主待提交写入 | 另一条连接持有写事务；新读取连接返回原已提交联系人 | 不需要借用宿主写事务来运行核心 |
| 结束与错误清理 | 关闭自己连接及合成 BUSY 查询错误后，宿主待提交行和事务仍在 | 该实验中生命周期和错误清理不接管宿主事务；BUSY 是函数表注入，不是真实锁冲突 |
| 读取快照 | 别的连接提交联系人更改，已有读取事务仍看到原值，新事务看到新值 | 独立连接可以满足 PR #2 的跨语句快照前提 |
| 只读 main 反例 | db_readonly(main)=1 的连接仍能拥有 temp 待提交写入 | 单独检查文件只读属性不能证明整条借用连接无待提交写入 |
| 账号归属反例 | 两个相同结构、相同姓名的库返回不同 ID | 查询成功和表结构相符都不能证明“当前账号的联系人库” |
| 打开成功反例 | 人工构造非 SQLite 文件，open 返回 OK，但核心读取 schema 失败 | 打开成功不等于成功取得可用联系人上下文 |
| 全局初始化反例 | 测试自己注册 auto-extension，它在 READONLY open 时执行并修改 temp | open 前必须了解目标 SQLite 的全局初始化/VFS 行为；query_only/authorizer 安装在 open 后不能追溯约束它 |
| 四线程 | 每个线程独立打开、查询、关闭自己的连接 | 合成实验不依赖跨线程共享一个 SQLite 句柄 |

测试不使用 URI/immutable、备份或附加真实库；不会忽略 WAL。
READONLY 不表示完全没有文件系统写入：某些 WAL/共享内存场景仍可能有 sidecar 活动，
本实验没有证明“零写盘”，也没有证明所有宿主 VFS 都具有标准 SQLite 的行为。

Apple SDK 将全局扩展 API 标为不支持；PM 全套实验使用机器上已安装的 Homebrew SQLite，
不关闭该弃用警告来假装 Apple 系统实现支持此实验。PW 使用既有 Anaconda SQLite。
所有修改 SQLite 配置、回调或事务的代码仅在测试拥有的连接/进程内运行，不应复制到微信共享连接。

## 建议的接入结构与仍缺的证据

更有希望的结构是在已核实的进程内 SQLite/加密上下文中取得**由适配器独立拥有的读取连接**，
连接不提供给宿主、不含待提交写入；同一工作线程完成打开、快照、固定查询和清理。
这是待验证结构，不是本 PR 新增的生产 API。当前实验不能自动解决以下阻塞：

1. **函数表和模块寿命。** 需要当前安装版本的原始模块及可复现静态分析，核实 API 布局、地址和调用约定，
   并证明调用期间模块有效。不能用公开空偏移头或某个版本号相同作为替代。
2. **加密初始化。** 标准 SQLCipher 要在读取页面前设置正确密钥及参数；普通 open 不证明具备正确读取上下文。
   微信是否有可安全调用的独立读取工厂、初始化是否依赖 VFS/全局回调、所需参数来自哪里，均未验证。
   [SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/) 只说明标准接口，不能用来断言微信的实际实现。
   非 SQLite 夹具不是 SQLCipher 加密夹具；本轮没有完成 SQLCipher 或微信解密兼容性测试。
3. **账号、库及文件对象绑定。** 必须来自经核实的当前账号元数据；库的 basename 或 contact 字段组合不够。
   还需绑定 SQLite 实际读取的文件对象，处理路径重解析/替换，不能只比较一个字符串路径。
4. **打开阶段副作用。** 需要确认目标 VFS、自动扩展和加密初始化的行为及线程要求；
   自己拥有连接并不代表它在宿主进程中打开时没有其他副作用。
5. **准入与失败处置。** 完整的短期/持久单次查询授权、超时后处置仍须实现和审核；
   不能杀线程来中止 SQLite，也不能在失败时回退到扫描句柄、宿主写事务或自动重试。

如果独立读取工厂不存在，靠拦截 open/close/key 等调用追踪宿主连接是另一种更大范围的进程内改动，
涉及关闭覆盖、既有连接发现、重入和宿主调度，不能当作本轮的小适配器直接加入；需要单独设计及授权。

## 当前停止点

本轮已完成源码梳理和离线对照；没有足够证据实现真实连接提供者，因此**不产生可部署的查询 DLL**。
不能通过放入 Trusted=true、AccountVerified=true 等布尔标记替代上述证据，
也不能部署一个运行后才碰运气尝试取连接的入口。

继续真实适配器研究最少需要当前版本原始模块的离线静态样本及现有账号/联系人库路径的可信元数据。
如果需要从 VW12 只读取得这些文件/元数据，应先列清单、大小、用途及读取范围再取得授权；
不附带运行新 DLL、进程扫描、取钥、重开微信、登录或发送的许可。
在这些证据和授权到位前，不以实验夹具的通过替代真实兼容性或账号安全结论。

## 复现

PM（使用已存在的 Homebrew SQLite 头文件和库）：

```sh
clang++ -std=c++17 -Wall -Wextra -Werror -Wno-deprecated-literal-operator \
  -fsanitize=address,undefined -g -I include \
  -I /opt/homebrew/opt/sqlite/include -L /opt/homebrew/opt/sqlite/lib \
  tests/contact_adapter_feasibility.cpp src/contact_lookup.cpp -lsqlite3 \
  -o /tmp/contact_adapter_feasibility
/tmp/contact_adapter_feasibility
```

正式验证在外部五分钟/2GiB进程树RSS采样保护下运行；采样不是硬内存配额。
PW 的 `build/test-contact-lookup.ps1` 现在依次执行原核心套件和本实验；延续五分钟/2GiB采样保护和10GiB磁盘保留。
assertion 数量包括夹具创建/清理，不等于独立业务场景数。成功完成后关闭并删除合成库及 sidecar。


## 本轮实际验证

- PM：预装 Homebrew SQLite 3.54.1，新增153项合成断言通过；原核心616项通过；两套 ASan/UBSan通过。
- PW：既有 MSVC v142 / SQLite 3.33.0，同样通过153+616项断言；总耗时12.3秒，采样峰值268,689,408字节。
- 全局扩展实验在以上两个库中均实际执行；没有把 Apple 系统 SQLite 当作已验证对象。
- 本变更没有验证 SQLCipher、Weixin.dll 的 ABI、真实账号/联系人库或微信打开连接的副作用。
- 两个平台均未构建或加载 DLL；本轮没有连接 VW12/VW11，没有取钥、登录、重开微信或发送消息。

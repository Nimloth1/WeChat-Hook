# 金浩枫联系人查询：离线核心审查

## 范围和当前状态

本变更从已合并的发送修复 `3f20b60` 开始，仅增加固定联系人查询核心、合成测试及离线构建脚本。
用户明确选择“保留进程内方向，先提交离线核心和阻塞说明供审核”。
**没有进程内数据库入口、HTTP 路由、DLL 构建/部署、取钥、真实联系人查询或发送。**
现有 `build/build-send-fix.ps1`、发送 DLL 源码及其运行许可均不修改；本 PR 的新代码也不被该构建链接。
VW12/VW11 不被测试访问，微信不用退出、重开或重新登录。

## 已实现

- `Find(Sqlite&, void*)` 只查询固定姓名“金浩枫”，不接受数据库名、表名、任意 SQL 或其他姓名。
- 只通过精简 SQLite 函数表查询；没有 open/exec/backup/key、写操作或发送函数。
- 调用方必须独占/同步地持有连接和一个在整次调用中不变的显式事务。核心用
  `get_autocommit` 在每条语句前后拒绝 autocommit，并只读检查 `read_uncommitted=0`。
  第一次 schema SELECT 建立 main 库读取快照，后续校验和候选查询沿用它。
  核心不执行 BEGIN/COMMIT/ROLLBACK/SAVEPOINT。**这不保证事务保持有效**：SQLite 在错误恢复中
  可以自行回滚整个事务；不能借用含任何待提交写入的连接。
- 先确认 main schema 中存在普通 `contact` 表，拒绝视图、虚拟表、未知字段组合。
- 支持两组字段：`username/nick_name/remark/alias` 与 `UserName/NickName/Remark/Alias`。
  这是待适配的两种已知结构，**不代表已核实 VW12 的真实结构**。
- 只按备注或昵称二进制精确匹配，参数绑定固定常量；不读消息表、群成员或头像。
- 每个 statement 必须只读、参数数量正确、没有 SQL 尾部；检查 prepare/bind/step/finalize 结果。
  `BUSY`、错误、未知结构不会被返回为“查无结果”。不改变连接 PRAGMA、授权器、忙等待或进度回调。
- 最多接受五个候选；读取到第六个即失败且不输出部分列表。拒绝重复 ID、群/企业联系人 ID、
  超长字段、内嵌 NUL 和无效 UTF-8。只返回 ID、昵称、备注及 alias。
- 单个候选仍标记 `candidate_needs_confirmation`；多个为 `ambiguous`，无结果为 `not_found`。
  所有输出都标记 `IdentityConfirmed=false`、`SendingSupported=false`、`RuntimeCompatibilityVerified=false`。
- `Controller` 是供未来入口使用的纯 C++ 请求门禁，不启动服务。默认 token 为空时拒绝；
  只接受一个字段的 `{"name":"金浩枫"}`，拒绝重复键/额外字段/超过128字节请求。
  单个 controller 实例中仅允许一次后台调用；失败不重试，并发请求只有一个可以进入。

## 必须先解决的进程内入口阻塞

原 `xdb/db_mgr.cpp` 扫描匹配 VFS 指针的内存地址，再将地址当作 `sqlite3*`。
匹配值可能出现在栈、缓存或其他对象中；可读内存不等于有效 SQLite 对象。
`db_mutex`/`mutex_try` 调用本身就需要有效句柄，锁也不是拥有该句柄的生命周期引用。
扫描后微信可能关闭连接；重复检查、SEH 或把 mutex 加到查询外层都不能证明不存在释放竞争。
在异常后，进程内锁或 statement 还可能无法安全清理。**因此本 PR 不保留原扫描方法的可执行适配器。**

后续入口必须在取得真实联系人数据前满足以下全部条件，另行设计、审查并取得部署授权：

1. 能证明句柄来源和所有权/生命周期覆盖整个查询，不能把扫描命中直接交给 SQLite 函数。
2. 查询处于数据库允许的线程/同步上下文，连接不会并发关闭；函数表 ABI、版本和模块摘要已核实。
3. 能限定到当前 VW12 账号唯一的联系人库；不能仅凭存在一张 contact 表就判断账号或库身份。
4. 绕开原 DatabaseMgr 初始化的 14 字节代码补丁，不伪造 `g_IsLogin=1`，不引入备份/取钥逻辑。
5. 入口具备明确批准、短期有效、一次性且可持久记录的查询授权；当前 controller 的 token 和
   进程内 CAS **不是**完整授权方案：没有过期检查或跨实例/跨重启去重，不可单独用作上线入口。
6. 后台没有安全取消能力时不能靠杀线程实现超时，也不能改写微信共享连接的 progress handler。
   必须明确卡住后的处置和账号风险，禁止自动重试。
7. 调用方提供跨全部语句的稳定读取快照：显式事务保持不变，`read_uncommitted` 关闭；
   整次调用中同一连接不得有其他 DDL、事务控制或状态修改。仅有可用句柄及互斥锁不够。
8. 入口必须证明整条连接没有待提交写入，范围包括 main、所有 attached 库和 temp，且调用中不发生写入。
   不得借用宿主的写事务或用 SAVEPOINT 包裹它来声称隔离错误回滚；
   autocommit=0、语句 readonly、total_changes 不变、只检查 main 或持有 mutex 都不能提供这个证明。
   可以另行设计由适配器拥有且生命周期可靠的专用读取上下文，但本 PR 没有实现它；
   如果不能证明上述前提，入口必须拒绝调用，不得用一次试查询来验证安全性。

`Find` 的调用前提是：适配器提供**有效且在整个调用期间由调用方可靠持有并同步的连接**、
正确的函数表、没有任何待提交写入的显式读取事务；不能由另一个线程或回调在同一连接上写入、
提交/回滚后重新开启事务。此处“不变”是调用方不得主动更换事务，不是 SQLite 出错时仍保留事务的保证。
常规离线测试只在自己创建、自己持有的 SQLite 连接上满足这个前提；错误恢复负例故意违反无待提交写入条件。
没有证明真实微信能满足这些前提。
`get_autocommit` 可以拒绝没有事务或已丢失事务的调用，但不能替代对连接独占性/事务所有权的证明。
SQLite 的 NOMEM、IOERR、FULL、INTERRUPT 等错误可能自动取消整个事务，即使执行的是只读语句。
失败返回后，适配器必须在保持连接独占的情况下重新检查事务状态，将状态丢失交由连接所有者处置；
不得自动重开事务、重试查询或重放宿主写入。核心的错误码和空候选不构成“宿主事务未受影响”的证明。
详见 [事务错误响应](https://sqlite.org/lang_transaction.html#response_to_errors_within_a_transaction)。
当前函数表不证明“没有待提交写入”，这是未来适配器的强制前提，真实入口继续阻塞。
SQLite 的跨连接隔离和自动提交语义见 [isolation](https://sqlite.org/isolation.html) 与
[get_autocommit](https://sqlite.org/c3ref/get_autocommit.html)；核心只读取隔离设置，不改共享连接状态。

## 边界与资源

请求128字节；表结构最多64字段；候选最多5个（第6个使结果失败）；每列先限制4096字节，
联系人昵称/备注进一步限制512字节，ID和alias限制128字节。
这些是输出和临时容器预算，**不是 SQLite 或整进程内存上限**。
每次 Read 的两秒检查只发生在 step 返回后，不能中断一次长时间 step、prepare 或 finalize。
LIMIT 6 也不能保证只扫描六条底层记录；没有适合索引时可能扫描联系人表。
外部连接提供的自定义函数/排序规则、底层文件 I/O、内部 ABI 和微信安全策略均未在真实账号验证。
离线通过不构成账号安全保证，也不能用于解释此前的安全提示。

## 离线验证

PM（系统 SQLite，ASan+UBSan）：

```sh
mkdir -p artifacts/contact-lookup
clang++ -std=c++17 -Wall -Wextra -Werror -Wno-deprecated-literal-operator \
  -fsanitize=address,undefined -g -I include \
  tests/contact_lookup_tests.cpp src/contact_lookup.cpp -lsqlite3 \
  -o artifacts/contact-lookup/contact_lookup_tests
artifacts/contact-lookup/contact_lookup_tests
```

仅关闭已有第三方 `json.hpp` 的 literal-operator 弃用警告；不修改或降低我们代码的警告级别。
PW 使用现有 MSVC v142 与 Anaconda SQLite 头文件/导入库：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File build\test-contact-lookup.ps1
```

构建脚本仅允许 PW，5分钟超时、采样2GiB进程树工作集上限、10GiB磁盘保留；
超限终止构建进程树。采样保护不是硬内存配额。
合成测试主要使用内存 SQLite 数据库；跨连接DDL回归使用临时目录中的微型WAL数据库，
每个场景关闭连接后清理数据库和sidecar。涵盖两类结构、空结果/重名/超量、主 schema 与 temp 遮蔽、
字段预算/UTF-8/NUL、语句只读、错误退出、关闭 statement、请求门禁及16路并发单次进入。
测试自己连接上的 authorizer 会拒绝所有写操作，只允许读取、固定 table_info 和 read_uncommitted 查询；
这不是要求未来改写微信共享连接的 authorizer。

## 审查重点

请先审查固定查询范围、SQL只读与错误处理、候选身份的不确定性，以及以上进程内接入前提是否充分。
本 PR 只请求对离线核心的审核；即使合并，也不会把查询功能加到现有 DLL 中。

## 首次提交验证（90cd59b）

- PM 系统 SQLite：311项合成断言通过，ASan/UBSan通过。
- PW MSVC v142、SQLite 3.33.0：311项合成断言通过；7.5秒，采样峰值进程树工作集177,967,104字节。
- PW旧SQLite首次初始化表值PRAGMA会被测试授权器以内部schema更新拒绝；独立内存数据库已复现。
  已改用固定 `PRAGMA main.table_info`，没有放宽写操作权限。
- 没有构建DLL、读取真实数据库或密钥；真实微信线程、句柄生命周期、ABI与账号风险仍未验证。

## P2 跨语句快照修复

原始版本在每条语句结束后释放隐式读取事务，另一个连接可以在校验后把表替换成视图。
审查报告中的两个窗口均已在原90cd59b核心重现：table_info结束后，以及最终SELECT第一次step之前。
原版本均返回替换视图中的候选并执行观察用UDF一次；调用方显式事务的对照读取旧快照，UDF零次。

修复选择要求并检查调用方事务，避免擅自开关借用连接的事务。新版拒绝没有显式事务、
read_uncommitted开启或语句边界事务已结束的调用；持有事务时，两个DDL替换窗口均不能改变本次查询对象。
后续新事务可看到替换后的视图，并正确拒绝它。此前“失败路径也不会回滚调用方已有的未提交数据”
的表述不成立，已撤回；缺表等普通错误的单个对照不能外推到 SQLite 分配失败等错误。
这些测试只证明合成 SQLite 的行为，不证明未来微信适配器能够满足上述前提。

快照修复提交 ef2beb4 中，PM SQLite 3.51.0 的427项断言及 ASan/UBSan通过；PW MSVC v142、SQLite 3.33.0
同样通过427项断言（6.9秒，采样峰值260,415,488字节）。两版本的替换视图观察函数调用均为零。
427包含夹具创建/清理等断言，不代表427个独立业务场景；初始311项结果只对应90cd59b。

## P2 借用事务错误恢复契约修正

复审在含待提交写入的合成连接中注入真实 SQLite 转码分配失败，观察到 `step_failed_7`，
SQLite 自动回滚整个事务，待提交记录从1行变0行；核心没有显式发出 ROLLBACK，
`total_changes` 也没有变化。因此修正的是公开契约和适配器接入前提，不声称核心能阻止 SQLite 自动回滚。
核心查询逻辑和函数表保持不变，没有添加自动提交、回滚、重试或恢复宿主写入的行为。

常规测试改为由夹具先提交合成准备数据，再开启没有待提交写入的读取事务；
这仅由测试拥有的连接执行，不是要求核心提交宿主数据。
新增分配失败回归在本测试进程内临时包装 SQLite 分配器，仅在读取 UTF-16 alias 的转码时拒绝分配，
不是耗尽系统内存。无故障对照与真实 NOMEM 对照同时覆盖合规读取事务，以及故意违反前提的
main、temp、attached 待提交写入。检查错误返回无候选、statement 关闭、已提交数据保留，
并记录 autocommit 和待提交行数；允许 SQLite 版本选择保留或自动回滚错误事务，不要求所有版本相同。
这些负例仅展示为什么禁止借用待提交写事务，不构成对这类调用的支持或安全保证。


本次 PM SQLite 3.51.0 和 PW MSVC v142/SQLite 3.33.0 均通过616项合成断言，PM ASan/UBSan通过。
两个版本均观察到上述三个不合规写事务的待提交行被回滚（总行数2→1；已提交基线行保留），
无待提交写入的读取事务出错时也会结束，但已提交数据不丢失。快照替换回归的UDF调用仍为零。
616包含夹具断言，不代表616个独立业务场景；PW 7.2秒，采样峰值164,196,352字节。
未构建DLL、未连接VW12/VW11、未接触真实微信；没有验证真实入口或账号安全。

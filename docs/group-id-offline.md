# PAYL能化观察：最小只读群 ID 查询离线研究

本轮在已合并 PR #5 的 `e0f5d4d` 上研究固定群名，不改发送 DLL、个人联系人核心或登录逻辑。
仅新增 `tests/group_lookup_feasibility.cpp` 和本文。没有真实查询适配器、HTTP 入口、DLL 构建或部署，
没有连接 VW12/VW11、取钥、读取实时进程内存、重开微信或发送消息。发送许可不新增、不恢复。
用户要求继续进程内方向；独立外部取钥器、数据库全量导出和逐个联系人试发不在本轮范围。

## 最小查询形状

假定已由可靠的进程内提供者取得当前账号的专用读取连接，并确认真实 schema 后，候选查询可以缩到：

```sql
SELECT username,nick_name FROM main.contact
WHERE nick_name COLLATE BINARY=?1 LIMIT 6;
```

参数固定绑定完整群名“PAYL能化观察”，不接受任意姓名、SQL 或路径。实验同时验证已有核心采用的
`UserName/NickName` 另一组拼写。两种结构都只是合成假设，尚未读到 VW12 的真实 schema。
只复制 ID 和名称两列，不读备注、alias、聊天正文、群成员或头像；同名个人记录的这两列可能被复制后排除。
LIMIT 只限制返回记录，不保证底层仅扫描六行，没有索引时仍可能扫描联系人表。

查询前确认 main 中是普通 contact 表，检查列结构，拒绝视图/虚拟表、未知字段及 temp 同名遮蔽。
调用方持有整段显式读取事务且 `read_uncommitted=0`，从 schema 校验到候选查询共用一个快照。
实验不通过核心开关借用连接的事务，不把 query_only 或 autocommit 当作连接所有权证明。
SQLite 的快照行为见 [官方隔离说明](https://www.sqlite.org/isolation.html)。

C++ 在返回数据中检查精确的 `@chatroom` 后缀及受限前缀格式，排除同名好友。
不在 SQL 中加入 GLOB/LIKE/substr，以减少查询期间可执行的函数；SQLite 允许应用替换这些函数，
参见 [表达式文档](https://www.sqlite.org/lang_expr.html#like)。
这不能替代对宿主连接、排序规则、schema 和初始化回调的完整可信性核实。

零个群候选为 not_found；一个仍为 candidate_needs_confirmation，不据此确认账号/群身份；
两个以上（包括重复 ID 行）为 ambiguous，不输出“第一个 ID”。最多处理五个精确同名记录，
第六个使整次结果失败且清空候选，不能因为少量记录而自动挑选或改成试发。
ID 限128字节、名称512字节、schema最多64列；错误、无效字段和超预算都不返回部分 ID。

这条查询也可能查不到真实新群：尚未证明该群在当前微信版本中已持久化到 contact，
也未证明窗口显示名对应 nick_name。未找到不是“群不存在”，不能据此改登录、自动改查消息表或发送探测。
`@chatroom` 格式只用作候选格式约束，不证明实际群身份、成员、账号归属或发送兼容性。

## 已有静态样本能推进到哪里

复用此前保存的磁盘函数表小片段，不再次访问 VW12：样本模块 SHA256 为
`f487e4f56930456a25fb0d7b058c77e2dcd364e268d49bdfff4dc0e3be26ba36`。
在原候选表 RVA `0x8bb0d38` 上，使用编译器实际 offsetof 校核下列13个字段，
对应磁盘指针均落在可执行节：open_v2、close、prepare_v2、stmt_readonly、bind_parameter_count、
bind_text、step、column_count、column_type、column_text、column_bytes、finalize、get_autocommit。
结果只是字段位置/静态地址一致；没有运行这些函数，也没有证明函数起点、签名、调用语义或 ABI。
证据保留在本地运行记录 `outputs/WeChat-Hook-designated-recipient/group-offline/query-api-layout.json`，
不把带真实机器路径的运行产物加入源码仓库。

真正仍缺的是提供者：当前账号的、由适配器可靠独占拥有的、可解密且覆盖完整生命周期的读取连接。
公开源码没有提供这样的读取工厂。原 DatabaseMgr 扫描得到的句柄可能释放，构造器还修改宿主代码；
不能调用它来“试试看”。旧 codec 地址 `0x4ee64d0` 已发现位于别的函数内部，继续禁用。
新候选 `0x5054110` 及配对 `0x50541a0` 仍只是假设；静态代码存在下游调用和输出/上下文依赖，
不能因为名字像 getter 就称其纯只读、可安全调用或可用于取得独立连接。

因此本轮没有取得真实群 ID，也没有得到可部署的进程内读取入口。
需要继续证明：账号与文件对象绑定、专用读取连接的取得和加密初始化、线程及关闭规则、
打开阶段的 VFS/全局回调副作用、所有待提交写入隔离、单次查询批准和失败清理。
这些证据缺失时不进入真实进程，不回退到借用宿主写事务、句柄扫描、backup 补丁或自动重试。
先前安全提示原因仍未查明；此次合成实验不能解释或排除 DLL 与安全提示的关联。

## 离线实验与复现

程序无路径/目标参数，只创建自己拥有的微型合成 SQLite 库；所有 ID 均为夹具，不是实际收件人。
内部 Find 为匿名命名空间的实验函数，没有可链接给发送 DLL 的生产接口。
夹具对自己的连接设置 query_only、开启/结束事务和故障回调；不能照搬到微信共享连接。

覆盖两种 schema、同名好友、大小写/空格/备注差异、重名群、重复 ID、嵌入 NUL 和字段预算、
视图拒绝与观察函数零执行、temp 遮蔽、查询中断错误以及超量同名记录。
两个并发 DDL 窗口分别在 table_info 结束后、候选 SELECT 准备后第一次 step 前，
另一连接把 contact 换成带观察函数的视图；要求旧快照仍返回旧合成 ID，观察函数调用为零，
新事务见到视图后拒绝查询。中断实验只修改测试自己的 progress handler，不是宿主取消方案。
还在夹具上覆盖 GLOB 函数会终止测试的替身，确保这条候选 SQL 没有调用它。

```sh
mkdir -p artifacts/group-lookup
clang++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  tests/group_lookup_feasibility.cpp -lsqlite3 -o artifacts/group-lookup/group-system
artifacts/group-lookup/group-system
clang++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  -I /opt/homebrew/opt/sqlite/include -L /opt/homebrew/opt/sqlite/lib \
  tests/group_lookup_feasibility.cpp -lsqlite3 -o artifacts/group-lookup/group-homebrew
artifacts/group-lookup/group-homebrew
```

本机实际运行由外层180秒/1GiB进程树 RSS 采样保护，启动前已确认可用空间约17GiB；
RSS 采样不是硬内存配额，SQL LIMIT/字段限额也不是 SQLite 内存或执行时间上限。
没有增加服务、定时任务或后台重试。微型 WAL 夹具随实验清理；验证结束删除生成的二进制/dSYM，保留小型日志。
真实 Windows、WCDB 3.27.2、SQLCipher 解密、账号归属及安全提示原因均不在离线通过结论中。

## 本次实际结果

- PM SQLite 3.51.0 和已安装的 Homebrew SQLite 3.54.1：各923项断言通过，ASan/UBSan通过。
  断言包含建库、插入和清理检查，不等于923个独立业务场景。
- 原联系人核心在 SQLite 3.51.0 上616项回归通过，ASan/UBSan通过；没有修改该核心。
- 最终群实验编译及运行2.04秒，采样峰值进程树 RSS 155,451,392字节；
  含原核心回归的前一轮4.50秒，采样峰值369,786,880字节。
- 新增13字段的编译器布局/静态指针核对完成；没有执行真实微信 SQLite 函数。
- 真实群 ID 未取得。微信运行时、Windows 原生 ABI、真实 schema 和解密读取均未验证。
- 没有构建 DLL、部署、连接 VW12/VW11、登录操作、发送许可或发送请求，也没有创建间隔发送任务。

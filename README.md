# LXe 配置包门限签封服务（lxe-config-seal）

液氙探测器上线脚本前的配置包门限签封服务。运行组登记的 **2–8 个唯一 P-256
公钥** 与门限共同构成签封组；配置包只有在集齐足额有效审查签名、并且精确
接续当前已确认链头时才会被确认，从而保证任何时刻只有**一条**有效的配置
历史——重试与并发提交都无法制造分叉。

## 签名与摘要的规范字节序列

审查签名覆盖如下拼接的规范 UTF-8 字节序列（ECDSA / P-256 / SHA-256）：

```
DOMAIN_SEPARATOR("LXe-ConfigSeal/v1") || 0x00
|| uint16BE(len(group_id)) || group_id          (UTF-8)
|| prev_digest                                   (32 字节原始值)
|| uint64BE(seq)
|| config                                        (UTF-8)
```

包的确认摘要 `digest = SHA-256(上述字节序列)`（hex）。首包的
`prev_digest` 为 64 个 `'0'`（创世前序）。签名接受 DER 或 64 字节
`r||s` 的 hex 编码；公钥登记接受压缩/未压缩 SEC1 hex 或 PEM，非 P-256
曲线一律拒绝。审查员以其公钥压缩 SEC1 编码的 SHA-256 指纹（`key_id`）
标识。

## 每组 Merkle 日志（RFC 9162 / 原 RFC 6962）

运行组把某次**已确认**配置的摘要（`seq` 与 `digest`，无需配置文本本身）
交给下游后，下游可凭旧序号 + 旧根 + 新根判定当前历史确由该前缀延伸。
每个组拥有一棵独立的仅追加 Merkle 树；每确认一个包，就在包、回执、链头
的**同一个 `BEGIN IMMEDIATE` 提交内**追加一叶并保存可复算累计根。叶输入
同样带域分隔：

```
LEAF_DOMAIN_SEPARATOR("LXe-ConfigSeal-MerkleLog/v1") || 0x00
|| uint16BE(len(group_id)) || group_id     (UTF-8)
|| uint64BE(seq)
|| package_digest                            (32 字节原始值)
```

叶哈希为 `SHA-256(0x00 || 叶输入)`，内部节点为
`SHA-256(0x01 || 左 || 右)`，空前缀根为 `SHA-256("")`（RFC 9162
§2.1）。组标识内嵌于叶输入，跨组证明无法相互验证。

一致性证明遵循 RFC 9162 §2.1.4 的**非平衡分割**（k = 小于 n 的最大二次幂）
生成唯一最小兄弟摘要序列，顺序为规范顺序；验证算法即 §2.1.4.2 原文
（旧大小为二次幂时先把旧根置于路径首位）。证明长度不超过
`ceil(log2(second)) + 1`。

边界情形均有确定结果：`first=0`（空前缀）与 `first=second` 返回空路径
`[]` 与两端根；`first>second` 为 400；任一端超过当前已确认日志大小为
409；未知组为 404。

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 健康检查（Docker HEALTHCHECK 与 Compose 均使用） |
| POST | `/v1/groups` | 建立签封组：`{group_id, threshold, public_keys[2..8]}` → 201 |
| GET | `/v1/groups/{gid}` | 组信息与当前唯一链头 `{seq, digest}`，附带 `log: {size, root_hash}` |
| GET | `/v1/groups/{gid}/packages` | 已确认配置包列表（审计），附带当前 `log: {size, root_hash}` |
| POST | `/v1/groups/{gid}/packages` | 提交配置包 → 201（确认）/ 200（幂等重放），响应附带当前 `log` |
| GET | `/v1/groups/{gid}/consistency?first=m&second=n` | RFC 9162 一致性证明（`0 ≤ m ≤ n ≤ 当前大小`） |

提交配置包请求体：

```json
{
  "op_id": "deploy-2026-09-26-001",          // 稳定操作标识（幂等键）
  "prev_digest": "00…00",                     // 所见前序摘要（必须等于当前链头）
  "seq": 1,                                   // 连续序号（必须为 head.seq + 1）
  "config": "field=1500V\ndrift=…",           // 配置文本（UTF-8，≤1MiB）
  "signatures": [{"key_id": "…", "signature": "…"}, …]
}
```

确认响应：`{group_id, seq, digest, prev_digest, op_id, signers, replay,
log: {size, root_hash}}`。建组/读组/包列表同样附带 `log`。

一致性证明响应：

```json
{
  "group_id": "…",
  "first_size": 3,
  "second_size": 6,
  "first_root_hash": "…",
  "second_root_hash": "…",
  "consistency": ["…", "…", "…", "…"]
}
```

`consistency` 为 RFC 9162 规范顺序的最小兄弟摘要（hex），验证器按
§2.1.4.2 与两端根独立判定前缀关系——服务端无需也不会提供中间配置文本。

### 拒绝语义（均不改变历史）

| 情形 | 状态码 / `error` |
|---|---|
| 公钥数量越界、重复公钥、非 P-256、门限越界 | 400 `bad_key_count` / `duplicate_key` / `bad_key` / `bad_threshold` |
| 重复签署者 | 422 `duplicate_signer` |
| 未登记签署者 | 422 `unknown_signer` |
| 门限不足 | 422 `insufficient_threshold` |
| 无效签名（含篡改、签错字段） | 422 `invalid_signature` |
| 过期前序 / 序号不连续 / 竞争中落败 | 409 `stale_predecessor` |
| 同一 `op_id` 改换载荷 | 409 `op_id_conflict` |
| 重复组建组 | 409 `group_exists` |
| 一致性证明 `first > second` / 参数非非负整数 / 缺参 | 400 `bad_size_order` / `bad_first` / `bad_second` |
| 一致性证明任一端超过当前已确认日志大小 | 409 `log_size_out_of_range` |

### 原子性与恢复

- 确认过程在**同一个 SQLite `BEGIN IMMEDIATE` 事务**内完成：幂等回执查找
  → 当前链头校验 → 写入配置包 → 写入幂等回执 → 条件化移动链头
  （`UPDATE heads … WHERE head_seq=? AND head_digest=?`，并以
  `UNIQUE(group_id, seq)` 兜底）→ **追加 Merkle 叶并更新累计根**。
  竞争同一前序的请求至多一个成功，且包/回执/链头/日志根永远同时移动。
- 同一 `op_id` + 相同载荷重传：返回 200 与已存回执（`replay: true`），
  不产生新历史、不追加叶、根不变；相同 `op_id` + 不同载荷：409 冲突。
  只有**已确认**的包才留下回执与叶，校验失败的尝试不会占用 `op_id`，
  也不会改变根。
- 重启后服务从 `packages` 表中已确认记录**重建唯一链头与 Merkle 日志**
  （日志输出 `recovered chain head: …` 与 `recovered merkle log: …`）：
  叶序列与累计根、以及任一一致性证明都与重启前逐字节相同，随后即可继续续包。

## 运行

### Docker Compose（推荐）

```bash
# 构建 + 启动服务 + 运行 verify 验收（门限不足 / 幂等重传 / 链头竞争 /
# 独立复算 Merkle 根与一致性证明 / 篡改证明失败 / 跨组拒绝 / 旧接口回归），
# verify 的退出码即整条命令的退出码：
docker compose up --build --exit-code-from verify --abort-on-container-exit

# 仅启动服务，宿主端口可配置（默认 8080）：
SEAL_HOST_PORT=9090 docker compose up -d seal
curl http://127.0.0.1:9090/healthz
```

- `seal` 服务：数据持久化在命名卷 `seal-data`（容器内 `/data/seal.db`），
  自带健康检查。
- `verify` 服务：等待 `seal` 健康后执行 `scripts/verify.py`——健康/构建
  冒烟、组建组、门限不足拒绝、篡改签名拒绝、有效首包（摘要/序号/唯一链头
  校验）、幂等重传、`op_id` 冲突、8 路并发分叉（恰好一个赢家）；随后以
  **独立** RFC 9162 实现复算每个根与 3→6 非二次幂边界证明、验证 4→6
  二次幂前缀、空前缀与等大边界的空路径、逐位篡改/截断/伪造旧根必须失败、
  跨组证明拒绝、越界/倒序/未知组拒绝、旧组/包列表/确认接口字段回归、
  以及日志增长后的幂等重放不改变根——全部通过退出 0，否则退出 1。

### Dockerfile 单独使用

```bash
docker build -t lxe-config-seal .
docker run -e SEAL_PORT=8080 -p 8080:8080 -v seal-data:/data lxe-config-seal
```

环境变量：`SEAL_HOST`（默认 `0.0.0.0`）、`SEAL_PORT`（默认 `8080`）、
`SEAL_DB`（默认 `/data/seal.db`）、`SEAL_LOG_LEVEL`。

### 本地开发

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
SEAL_HOST=127.0.0.1 SEAL_PORT=8080 SEAL_DB=./seal.db .venv/bin/python -m app
.venv/bin/python -m pytest tests/ -q        # 45 项验收测试
SEAL_TARGET_PORT=8080 .venv/bin/python scripts/verify.py
```

## 测试覆盖（全部使用临时生成的 P-256 测试密钥）

- `tests/test_seal.py`（16 项）：建组参数校验（数量/重复/非 P-256/门限/
  重复组）、有效首包与续包的摘要·序号·唯一链头、篡改签名、签错字段、
  重复签署者、未知签署者、门限不足、过期前序（重放旧前序与跳号）、
  幂等重传、`op_id` 冲突、8 线程并发分叉（恰好一个确认）、重启后链头
  恢复并继续续包、HTTP 端到端冒烟。
- `tests/test_merkle_log.py`（29 项）：空日志根、逐包累计根独立复算、
  叶不依赖配置文本且跨组不同；幂等重放/校验失败/`op_id` 冲突/竞争落败
  均不改变根；RFC 9162 一致性证明在二次幂与非二次幂边界上由**独立**
  §2.1.4.2 实现验证；证明最小且确定；空前缀、等大、越界、倒序、缺参/
  非整数、未知组的确定结果；逐兄弟篡改/截断/加长/伪造根全部失败；
  跨组证明拒绝；重启后根与证明逐字节一致并可继续续叶；HTTP 端到端
  （含篡改证明失败与旧接口字段回归）。

## 布局

```
app/
  crypto.py    规范字节序列、摘要、P-256 密钥/签名原语
  merkle.py    每组 RFC 9162 Merkle 日志：带域分隔叶、累计根、
               最小一致性证明与 §2.1.4.2 验证器
  store.py     SQLite 持久化：单事务确认（含追加叶/根）、幂等回执、
               链头与 Merkle 日志重建
  service.py   校验与编排（无状态校验 → 单事务提交）、一致性证明接口
  server.py    标准库 HTTP 层
  __main__.py  入口（env 配置、SIGTERM 优雅关闭）
scripts/verify.py   Compose verify 服务的验收脚本（含独立证明验证器）
tests/              pytest 验收套件
Dockerfile / docker-compose.yml / requirements*.txt
```

# LXe 配置包门限签封服务（lxe-config-seal）

液氙探测器上线脚本前的配置包门限签封服务。运行组登记的 **2–8 个唯一 P-256
公钥** 与门限共同构成签封组；配置包只有在集齐足额有效审查签名、并且精确
接续当前已确认链头时才会被确认，从而保证任何时刻只有**一条**有效的配置
历史——重试与并发提交都无法制造分叉。

每个包确认时，服务在同一持久化提交内把 `(group_id, seq, digest)` 追加为
**RFC 6962 Merkle 日志叶**并保存可复算的累计根。下游拿到某次确认时的
`(旧 size, 旧根)` 后，仅凭新的 size、新根和一条**一致性证明**即可独立判定
当前历史确实从该前缀延伸——无需取得任何中间配置文本。

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

## Merkle 日志（RFC 6962）

每个已确认包恰好对应一片日志叶（叶序号 = `seq - 1`），叶输入带独立域分隔：

```
DOMAIN_SEPARATOR("LXe-ConfigSeal-Log/v1") || 0x00
|| uint16BE(len(group_id)) || group_id          (UTF-8)
|| uint64BE(seq)
|| digest                                       (32 字节原始值)
```

哈希规则遵循 RFC 6962 §2.1：叶 `SHA-256(0x00 || leaf_input)`，内部节点
`SHA-256(0x01 || left || right)`，空树根为 `SHA-256("")`
（`e3b0c442…b855`）。组标识编入每片叶子，因此跨组的根与证明必然不同。
叶与**可复算累计根**（按日志大小逐条保存于 `merkle_roots`）与包、回执、
链头在**同一个** `BEGIN IMMEDIATE` 事务内落盘；幂等重传、校验失败与竞争
落败都不会进入该事务的叶追加路径，因此根不会变化。重启后服务从
`packages` 表重放确认链，重建出逐位相同的叶、根与证明
（日志输出 `recovered merkle root: …`）。

确认响应与读取接口均附带当前日志状态 `log: {size, root}`；一致性证明
接口返回两端根与按 RFC 6962 非平衡分割（SUBPROOF）规范排序的最小兄弟
摘要，独立验证器按 RFC 9162 §2.1.4.2 即可判定前缀关系。

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 健康检查（Docker HEALTHCHECK 与 Compose 均使用） |
| POST | `/v1/groups` | 建立签封组：`{group_id, threshold, public_keys[2..8]}` → 201 |
| GET | `/v1/groups/{gid}` | 组信息、当前唯一链头 `{seq, digest}` 与日志状态 `log:{size, root}` |
| GET | `/v1/groups/{gid}/packages` | 已确认配置包列表（审计），附日志状态 |
| POST | `/v1/groups/{gid}/packages` | 提交配置包 → 201（确认）/ 200（幂等重放） |
| GET | `/v1/groups/{gid}/log/consistency?first=M&second=N` | 起止日志大小的一致性证明（RFC 6962） |

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
log:{size, root}}`。幂等重放返回原回执（含确认时刻的 `log`），不产生新叶。

一致性证明响应：

```json
{
  "group_id": "run-2026-09",
  "first": 1, "second": 5,
  "first_root": "…", "second_root": "…",
  "proof": ["…", "…"]
}
```

边界语义（均为确定结果）：`first=0`（空前缀）→ 空证明、`first_root` 为
空树根；`first=second` → 空证明、两端根相同；`first>second`、参数缺失/
非整数 → 400 `bad_range`；`second` 超出已确认日志大小 → 409
`size_out_of_range`；组不存在（证明无法跨组）→ 404 `unknown_group`。

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

### 原子性与恢复

- 确认过程在**同一个 SQLite `BEGIN IMMEDIATE` 事务**内完成：幂等回执查找
  → 当前链头校验 → 写入配置包 → **追加 Merkle 叶并保存累计根** → 写入
  幂等回执 → 条件化移动链头（`UPDATE heads … WHERE head_seq=? AND
  head_digest=?`，并以 `UNIQUE(group_id, seq)` 兜底）。竞争同一前序的请求
  至多一个成功。
- 同一 `op_id` + 相同载荷重传：返回 200 与已存回执（`replay: true`），
  不产生新历史也不移动日志根；相同 `op_id` + 不同载荷：409 冲突。只有
  **已确认**的包才留下回执，校验失败的尝试不会占用 `op_id`，也不会
  触及 Merkle 日志。
- 重启后服务从 `packages` 表中已确认记录**重建唯一链头与 Merkle 日志**
  （日志输出 `recovered chain head: …` 与 `recovered merkle root: …`），
  重建的根与一致性证明与重启前逐位相同，随后即可继续续包。

## 运行

### Docker Compose（推荐）

```bash
# 构建 + 启动服务 + 运行 verify 验收（门限 / 幂等 / 链头竞争 / Merkle 证明），
# verify 的退出码即整条命令的退出码：
docker compose up --build --exit-code-from verify --abort-on-container-exit

# 仅启动服务，宿主端口可配置（默认 8080）：
SEAL_HOST_PORT=9090 docker compose up -d seal
curl http://127.0.0.1:9090/healthz
```

- `seal` 服务：数据持久化在命名卷 `seal-data`（容器内 `/data/seal.db`），
  自带健康检查。
- `verify` 服务：等待 `seal` 健康后执行 `scripts/verify.py`——健康/构建
  冒烟、组建组、门限不足拒绝、篡改签名拒绝（根保持为空）、有效首包
  （摘要/序号/唯一链头/日志大小与根校验）、幂等重传（根不变）、`op_id`
  冲突（根不变）、8 路并发分叉（恰好一个赢家，日志只前进一次）、一致性
  证明（独立 RFC 6962 验证器接受合法证明、**拒绝篡改过的证明**、空前缀/
  相同大小/越界/跨组等边界的确定结果）——全部通过退出 0，否则退出 1。

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
.venv/bin/python -m pytest tests/ -q        # 32 项验收测试
SEAL_TARGET_PORT=8080 .venv/bin/python scripts/verify.py
```

## 测试覆盖（tests/，全部使用临时生成的 P-256 测试密钥）

`test_seal.py`：建组参数校验（数量/重复/非 P-256/门限/重复组）、有效首包
与续包的摘要·序号·唯一链头、篡改签名、签错字段、重复签署者、未知签署者、
门限不足、过期前序（重放旧前序与跳号）、幂等重传、`op_id` 冲突、8 线程
并发分叉（恰好一个确认）、重启后链头恢复并继续续包、HTTP 端到端冒烟；
Merkle 集成：确认即追叶并回报累计根、校验失败/重传/竞争落败根不变、
重启后根与证明逐位重建、一致性证明各边界（空前缀/相同大小/非二次幂/
越界/畸形参数/未知组）、跨组证明不可互验、HTTP 端到端证明与拒绝。

`test_merkle.py`：空树根、域分隔叶格式、非平衡树哈希、SUBPROOF 固定向量、
1..40 全部 `(m, n)` 对的生成-验证往返、篡改/截断/乱序证明与错误根的拒绝。

## 布局

```
app/
  crypto.py    规范字节序列、摘要、P-256 密钥/签名原语
  merkle.py    RFC 6962 Merkle 树：域分隔叶、累计根、一致性证明与验证
  store.py     SQLite 持久化：单事务确认、幂等回执、Merkle 日志、链头重建
  service.py   校验与编排（无状态校验 → 单事务提交）
  server.py    标准库 HTTP 层
  __main__.py  入口（env 配置、SIGTERM 优雅关闭）
scripts/verify.py   Compose verify 服务的验收脚本（含独立 Merkle 验证器）
tests/              pytest 验收套件
Dockerfile / docker-compose.yml / requirements*.txt
```

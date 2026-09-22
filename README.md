# 中央目录证词台（Central Directory Witness）

一个**本地** ZIP 归档审阅工具，用来回答归档分析人员的一个问题：

> 这个 ZIP 只是兼容性古怪，还是在利用「中央目录」与「局部文件头」之间的差异隐藏内容？

工具**从不把成员解压到磁盘**：压缩数据只在内存中流过 `zlib` 以核对 CRC，
所有证词都以**精确字节区间 `[start, end)`** 的形式保留——整包哈希、每一个
EOCD 候选、每个候选形成的中央目录图、中央目录记录、局部头、extra 字段、
压缩数据与 data descriptor。

## 安装

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 演示

```bash
.venv/bin/python -m pytest -q
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 5970
```

浏览器访问 <http://127.0.0.1:5970>，页面标题为 **“中央目录证词台”**。
可以上传任意 ZIP，或一键导入内置样例。所有验证均在本机完成，不依赖账号、
云服务或随机网络时序。

## 它做了什么

### 1. 保留全部 EOCD 候选，拒绝「选最后一个能打开的」

在尾部合法窗口（22 + 65535 字节）内扫描**所有** EOCD 签名，逐个尝试形成
目录图。真实 EOCD 必须紧贴文件尾；藏在注释、数据里的伪签名会被标记排除
原因（如 `eocd_not_at_tail`），但**候选本身保留**。

当尾部出现两个各自自洽、同时贴边的 EOCD（例如第二个 EOCD 藏在第一个的
注释里）时，两个候选目录图都保留并并列展示，并给出
`multiple_valid_directories` 高危提示。

### 2. 普通 + ZIP64 EOCD / locator / extra

* 普通 EOCD 22 字节固定头 + 变长注释，区间完整记录；
* 发现 `0xFFFFFFFF/0xFFFF` 哨兵字段时解析 ZIP64 EOCD record 与 locator；
  有哨兵却找不到 locator、locator 截断、目标不是 ZIP64 EOCD 都会成为
  **候选排除原因**；
* 中央目录与局部头的 extra 字段按子字段解析；子字段头或长度越界记
  `extra_field_truncated`，ZIP64 数据块不完整记 `zip64_extra_truncated`，
  绝不读越界数据。

### 3. 中央目录声明 vs 局部头声明 vs 实际数据

每个成员展示四套证词：

* 中央目录声明的 CRC / 压缩尺寸 / 解压尺寸（含 ZIP64 extra 覆盖）；
* 局部文件头自己声明的 CRC / 尺寸（`local_*` 字段）；
* 按中央目录布局计算出的**实际压缩数据区间**；
* CRC 验证结果：`ok / mismatch / skipped_encrypted / skipped_budget /
  skipped_method / skipped_no_data`。

### 4. bit 3 与 data descriptor

* bit 3（general purpose flag bit 3）置位时，局部头的零 CRC/尺寸被视为
  占位值（记录 `local_zero_placeholder` 信息级提示），**布局只信中央目录**；
* descriptor 是否带 `0x08074b50` 签名字节，不靠猜：分别尝试「无签名 12B」
  与「有签名 16B」两种读法，只有与中央目录的 CRC / 压缩尺寸 / 解压尺寸
  **全部一致**的解读才成立；两种都成立记 `descriptor_signature_ambiguous`，
  都不成立记 `descriptor_inconsistent` 并保留两种字节证据。

### 5. 风险与异常记录

| 代码 | 含义 |
| --- | --- |
| `shared_compressed_range` | 两个中央目录条目共享完全相同的压缩区间（critical） |
| `overlapping_members` | 成员压缩区间互相交叠 |
| `local_header_inside_central_directory` | 目录指向了目录内部 |
| `data_inside_central_directory` | 压缩数据落在中央目录区 |
| `local_header_inside_member_data` | 局部头藏在另一成员的数据中 |
| `integer_wrap_or_oversize` | CD 偏移/尺寸回绕或超大（候选排除） |
| `path_traversal` | `../`、绝对路径、盘符等穿越名 |
| `duplicate_name` | 中央目录中的重复文件名 |
| `encryption_flag_conflict` / `encrypted_members` | 加密位冲突 / 加密成员（CRC 无法核对） |
| `local_central_size_mismatch` / `name_mismatch` / `method_mismatch` | 局部头与中央目录证词冲突 |
| `crc_mismatch` / `crc_decompress_error` / `uncompressed_size_mismatch` | 内容与声明不符 |
| `multidisk_archive` / `multidisk_member` | 多磁盘字段 |
| `zip64_field_conflict` | 普通 EOCD 与 ZIP64 EOCD 数值冲突 |
| `multiple_valid_directories` | 存在多个自洽目录候选（高危） |

### 6. 资源预算（`cdwitness/budget.py`）

默认预算：原始文件 1 GiB、10 万条目、累计解压 2 GiB、单成员解压
512 MiB、1024 个 EOCD 候选。超预算的候选被明确排除或跳过 CRC，
不会为了“能打开”而静默放宽；高压缩比炸弹通过 `decompressobj` 的
`max_length` 有界处理。

## 内置样例（`cdwitness/fixtures.py`，全部确定性字节）

| 文件 | 覆盖点 |
| --- | --- |
| `normal.zip` | stored + deflate 基线，CRC 全通过 |
| `zip64_sentinel.zip` | EOCD/CD 全 ZIP64 哨兵字段 + ZIP64 extra |
| `unsigned_descriptor.zip` | bit 3 + 无签名字节 descriptor（一致性判定） |
| `signed_descriptor.zip` | bit 3 + 带签名 descriptor |
| `fake_eocd_comment.zip` | 真 EOCD 注释里藏伪 EOCD（候选排除原因） |
| `shared_range.zip` | 两个成员共享同一压缩区间 |
| `truncated_extra.zip` | 中央 extra 子字段长度声明越界 |
| `evil_names.zip` | 路径穿越 + 重复文件名 |
| `multidisk.zip` | 多磁盘字段 |
| `twin_eocd.zip` | 尾部两个同时贴边、各自自洽的 EOCD |

测试核对四件事：范围图字节精度、CRC、候选排除原因、资源预算，以及
同一归档重复导入时以 SHA-256 为身份的稳定性（`tests/`）。

## 存储与迁移

* SQLite，默认位于 `data/witness.db`（可用环境变量 `CDWITNESS_DB` 覆盖）；
* 显式版本表 `schema_version`，迁移顺序写在 `cdwitness/storage.py`；
* 整份证词 JSON 原样存入 `archives.report_json`，另建
  `candidate_summaries` / `finding_summaries` 便于列表检索；
* 重复导入相同字节返回同一 `archive_id`（`reused=true`）。

## HTTP API

* `GET /`：Web UI
* `GET /api/health`、`GET /api/fixtures`
* `POST /api/fixtures/{name}/import`：导入内置样例
* `POST /api/archives`：multipart 上传 ZIP
* `GET /api/archives`、`GET /api/archives/{id}`
* `POST /api/archives/{id}/reanalyze`：用自定义预算重新审阅

## 代码结构

```
app.py                     FastAPI 入口（uvicorn app:app）
cdwitness/parser.py        二进制解析、候选目录图、几何检查、CRC
cdwitness/fixtures.py      内置确定性样例
cdwitness/budget.py        资源预算
cdwitness/storage.py       SQLite 迁移与幂等导入
cdwitness/models.py        字节区间/成员/候选/分析结果数据模型
static/index.html, app.js  单页 Web UI
tests/                     pytest 自动化测试
```

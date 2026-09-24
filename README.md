# 中央目录证词台（ZIP 结构取证审阅）

面向归档分析人员的本地审阅工具：判断一个 ZIP 只是兼容性古怪，还是在利用
**中央目录与局部文件头的差异**隐藏内容。导入后保留整包哈希、全部 EOCD
候选、中央目录记录与局部文件头的精确字节区间；**绝不先把内容解压到磁盘**
（CRC 验证仅在内存中进行）。

## 安装与运行

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q                                   # 自动化验证
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 5970          # 演示服务
```

打开 http://127.0.0.1:5970 即可看到「中央目录证词台」。全部验证在本机完成，
不依赖账号、云服务或网络时序。数据库路径可用环境变量 `ZIPREVIEW_DB` 覆盖
（默认 `./zipreview.db`）。

## 审阅模型

- **EOCD 候选**：扫描全文件所有 `PK\x05\x06` 签名（包括藏在注释里的伪造
  EOCD）。每个候选独立解析：普通/ZIP64 EOCD、locator、多磁盘字段。能构成
  目录图的保留为 `primary`/`alternative`，不能的保留为 `excluded` 并记录
  排除原因——**绝不为了"能打开"就只留最后一个目录**。
- **三方对质**：每个成员并列展示中央目录声明、局部头声明、实际压缩数据
  区间 `[data_start, data_end)` 与 CRC 验证结果（ok / mismatch / skipped
  及原因）。
- **bit 3（data descriptor）**：局部头的零尺寸不被当真，以中央目录为准；
  descriptor 是否带 `PK\x07\x08` 签名由一致性约束判定（值须等于中央目录
  声明，且 descriptor 之后必须是合法后继结构或 EOF），判定依据随报告保留。
- **extra field**：逐个解析 `(tag, len)`，声明长度越界的记为截断。
- **UTF-8 flag（bit 11）**：决定文件名按 UTF-8 还是 CP437 解码并单独标注。

## 异常清单

`overlap`（成员压缩区间重叠）、`pointer_into_member_data`（目录指针指向
其他成员数据内部）、`pointer_into_central_directory`、
`central_directory_inside_member_data`、`range_overflow`（整数回绕/截断，
区间越出文件）、`path_traversal`（`../`、绝对路径、盘符）、
`duplicate_name`、`encrypted`（bit 0，CRC 跳过）、`multi_disk`、
`extra_truncated`、`size_mismatch`、`descriptor_inconsistent`。

## 资源预算

`zipforensics.parser.Budgets`：候选数、成员数、单成员/全局解压字节上限。
超限不报错中断，而是记录 budget event 并将对应 CRC 标记为
`skipped: budget`。

## 内置样例

`fixtures/` 下的五个样例由 `zipforensics/fixtures.py` 程序化生成
（`python -m zipforensics.fixtures --out fixtures/` 可重新导出）：

| 样例 | 考察点 |
| --- | --- |
| `zip64-sentinel` | 经典 EOCD 全为 0xFFFF/0xFFFFFFFF 哨兵，真实几何在 ZIP64 EOCD + locator |
| `nosig-descriptor` | bit 3 + 局部头零尺寸 + 无签名 descriptor（须靠一致性判定） |
| `fake-eocd-comment` | 真 EOCD 注释内嵌伪造 EOCD，两个候选都保留，伪造者带排除原因 |
| `shared-range` | 两个成员共享压缩区间（b 的局部头嵌在 a 的数据里） |
| `truncated-extra` | extra field 声明 100 字节实际只有 2 字节 |

## 持久化与身份稳定性

SQLite 迁移在 `zipforensics/store.py` 的 `MIGRATIONS` 中（当前版本 1），
表：`archives`（整包 SHA-256 唯一）、`eocd_candidates`、`cd_records`、
`local_headers`（含数据区间与 descriptor 判定）、`anomalies`。同一归档
重复导入按哈希去重，返回既有 `archive_id`，不产生重复行。

## API

- `GET /` — 审阅页面
- `POST /api/import` — 原始字节导入（`X-Filename` 头可命名）
- `POST /api/import-fixture/{name}` — 导入内置样例
- `GET /api/fixtures` · `GET /api/archives` · `GET /api/archives/{id}`

## 布局

```
app.py                  FastAPI 入口（create_app 可注入测试数据库）
zipforensics/parser.py  字节级结构解析（EOCD/ZIP64/CEN/LFH/extra）
zipforensics/analysis.py 对质、descriptor 判定、CRC、异常与预算
zipforensics/store.py   SQLite 迁移与导入去重
zipforensics/fixtures.py 内置样例生成器
zipforensics/web.py     单页审阅 UI
tests/                  26 个自动化测试
```

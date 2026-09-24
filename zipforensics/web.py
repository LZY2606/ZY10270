"""Single-page review UI served at /."""

INDEX_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>中央目录证词台</title>
<style>
  :root { --bg:#0f1420; --panel:#182034; --line:#2a3552; --fg:#dfe6f5;
          --dim:#8b97b5; --ok:#4ade80; --warn:#fbbf24; --bad:#f87171; --acc:#7aa2ff; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 "SF Mono", Menlo, Consolas, monospace; }
  header { padding:18px 24px; border-bottom:1px solid var(--line); }
  header h1 { margin:0; font-size:22px; letter-spacing:2px; }
  header p { margin:4px 0 0; color:var(--dim); font-size:12px; }
  main { display:grid; grid-template-columns:320px 1fr; gap:16px; padding:16px 24px; }
  .panel { background:var(--panel); border:1px solid var(--line);
           border-radius:8px; padding:14px; margin-bottom:16px; }
  .panel h2 { margin:0 0 10px; font-size:13px; color:var(--acc);
              text-transform:uppercase; letter-spacing:1px; }
  button { background:#24304f; color:var(--fg); border:1px solid var(--line);
           border-radius:6px; padding:6px 10px; cursor:pointer;
           font:inherit; font-size:12px; margin:2px 4px 2px 0; }
  button:hover { border-color:var(--acc); }
  .arch { padding:8px; border:1px solid var(--line); border-radius:6px;
          margin-bottom:8px; cursor:pointer; }
  .arch:hover, .arch.sel { border-color:var(--acc); }
  .arch .hash { color:var(--dim); font-size:11px; word-break:break-all; }
  table { border-collapse:collapse; width:100%; font-size:12px; }
  th, td { border:1px solid var(--line); padding:5px 8px; text-align:left;
           vertical-align:top; }
  th { color:var(--acc); font-weight:600; }
  .tag { display:inline-block; padding:1px 6px; border-radius:4px;
         font-size:11px; margin:1px 2px; }
  .t-ok { background:#14532d; color:var(--ok); }
  .t-warn { background:#4a3413; color:var(--warn); }
  .t-bad { background:#4c1d1d; color:var(--bad); }
  .t-info { background:#1e2a4a; color:var(--acc); }
  .muted { color:var(--dim); }
  .num { text-align:right; }
  .notes { color:var(--dim); font-size:11px; }
  #detail:empty::before { content:"← 导入或选择一个归档"; color:var(--dim); }
  .kv { font-size:12px; margin:2px 0; word-break:break-all; }
  .kv b { color:var(--acc); font-weight:600; }
</style>
</head>
<body>
<header>
  <h1>中央目录证词台</h1>
  <p>ZIP 结构取证审阅 · 保留全部 EOCD 候选 · 不解压落盘 · CRC 仅内存验证</p>
</header>
<main>
  <div>
    <div class="panel">
      <h2>导入</h2>
      <input type="file" id="file" accept=".zip,application/zip">
      <div id="fixtures"></div>
    </div>
    <div class="panel">
      <h2>已归档</h2>
      <div id="archives" class="muted">暂无</div>
    </div>
  </div>
  <div id="detail"></div>
</main>
<script>
const $ = (id) => document.getElementById(id);
const fmtRange = (a, b) => a === null ? "—" : `[${a}, ${b})`;
const hex = (n) => n === null || n === undefined ? "—" : "0x" + n.toString(16).padStart(8, "0");

async function loadFixtures() {
  const names = await (await fetch("/api/fixtures")).json();
  $("fixtures").innerHTML = "<p class='muted'>内置样例：</p>" + names.map(n =>
    `<button onclick="importFixture('${n}')">${n}</button>`).join("");
}

async function loadArchives(selectId) {
  const list = await (await fetch("/api/archives")).json();
  $("archives").innerHTML = list.length ? "" : "暂无";
  for (const a of list) {
    const div = document.createElement("div");
    div.className = "arch" + (a.id === selectId ? " sel" : "");
    div.innerHTML = `<div>#${a.id} ${a.name || "(未命名)"} · ${a.size} B</div>
      <div class="hash">${a.sha256}</div>
      <div class="muted">候选 ${a.candidates} · 异常 ${a.anomalies}</div>`;
    div.onclick = () => showDetail(a.id);
    $("archives").appendChild(div);
  }
}

async function importFixture(name) {
  const r = await (await fetch(`/api/import-fixture/${name}`, {method:"POST"})).json();
  await loadArchives(r.archive_id);
  showDetail(r.archive_id);
}

$("file").addEventListener("change", async (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  const r = await (await fetch("/api/import", {
    method:"POST", body: f,
    headers: {"X-Filename": f.name}
  })).json();
  ev.target.value = "";
  await loadArchives(r.archive_id);
  showDetail(r.archive_id);
});

function crcTag(m) {
  const cls = m.crc_status === "ok" ? "t-ok" :
              m.crc_status === "mismatch" ? "t-bad" : "t-warn";
  return `<span class="tag ${cls}">${m.crc_status}</span>`;
}

function flagTags(m) {
  let t = "";
  if (m.utf8) t += `<span class="tag t-info">UTF-8</span>`;
  if (m.bit3) t += `<span class="tag t-info">bit3</span>`;
  if (m.encrypted) t += `<span class="tag t-bad">加密</span>`;
  if (m.zip64) t += `<span class="tag t-info">ZIP64</span>`;
  return t;
}

function memberRow(m) {
  const cd = m.cd, lo = m.local;
  const localClaim = lo ? `crc ${hex(lo.crc32)}<br>c ${lo.csize} / u ${lo.usize}` : "缺失";
  const desc = m.descriptor
    ? `descriptor @${m.descriptor.offset} 长 ${m.descriptor.length}，` +
      (m.descriptor.has_signature ? "带签名" : "无签名") +
      (m.descriptor.consistent ? "" : ` <span class="tag t-bad">不一致</span>`)
    : "";
  return `<tr>
    <td class="num">${m.index}</td>
    <td>${m.name}<br>${flagTags(m)}</td>
    <td>${m.method}</td>
    <td>crc ${hex(cd.crc32)}<br>c ${cd.csize} / u ${cd.usize}<br>
        <span class="muted">lho ${cd.local_header_offset}</span></td>
    <td>${localClaim}</td>
    <td>${fmtRange(m.data_start, m.data_end)}</td>
    <td>${crcTag(m)}<br><span class="muted">期望 ${hex(m.crc_expected)}</span></td>
    <td class="notes">${m.notes.join("<br>")}${m.notes.length && desc ? "<br>" : ""}${desc}</td>
  </tr>`;
}

async function showDetail(id) {
  const d = await (await fetch(`/api/archives/${id}`)).json();
  document.querySelectorAll(".arch").forEach(e => e.classList.remove("sel"));
  let html = `<div class="panel"><h2>归档 #${d.archive_id} ${d.name || ""}</h2>
    <div class="kv"><b>SHA-256</b> ${d.sha256}</div>
    <div class="kv"><b>大小</b> ${d.size} 字节 · <b>导入于</b> ${d.imported_at}</div>
    ${d.budget_events.map(e => `<div class="kv"><span class="tag t-warn">预算</span>${e}</div>`).join("")}
  </div>`;
  if (d.anomalies.length) {
    html += `<div class="panel"><h2>异常 (${d.anomalies.length})</h2><table>
      <tr><th>候选</th><th>类型</th><th>细节</th></tr>` +
      d.anomalies.map(a => `<tr><td>${a.candidate ?? "—"}</td>
        <td><span class="tag t-warn">${a.kind}</span></td><td>${a.detail}</td></tr>`).join("") +
      `</table></div>`;
  }
  for (const [i, c] of d.candidates.entries()) {
    const statusTag = c.status === "primary" ? "t-ok" :
                      c.status === "excluded" ? "t-bad" : "t-warn";
    html += `<div class="panel"><h2>EOCD 候选 #${i} @${c.offset}
      <span class="tag ${statusTag}">${c.status}</span>
      <span class="tag t-info">${c.kind}</span></h2>
      <div class="kv"><b>目录</b> [${c.cd_offset}, ${c.cd_end}) ·
        ${c.entries_total} 条 · 注释 ${c.comment_len} B
        ${c.comment_text ? `“${c.comment_text}”` : ""}</div>
      ${c.exclusion_reason ? `<div class="kv"><span class="tag t-bad">排除原因</span>${c.exclusion_reason}</div>` : ""}
      ${c.zip64_eocd_offset !== null ? `<div class="kv"><b>ZIP64</b> EOCD @${c.zip64_eocd_offset} · locator @${c.zip64_locator_offset}</div>` : ""}
      ${c.notes.map(n => `<div class="kv muted">${n}</div>`).join("")}`;
    if (c.members.length) {
      html += `<table><tr><th>#</th><th>文件名</th><th>方法</th>
        <th>中央目录声明</th><th>局部头声明</th><th>数据区间</th>
        <th>CRC</th><th>备注</th></tr>` +
        c.members.map(memberRow).join("") + `</table>`;
    }
    html += `</div>`;
  }
  $("detail").innerHTML = html;
}

loadFixtures();
loadArchives();
</script>
</body>
</html>
"""

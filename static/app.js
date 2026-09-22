const SEV_LABEL = {
  info: "信息", low: "低", medium: "中", high: "高", critical: "严重",
};
const EXCLUDE_LABEL = {
  eocd_truncated: "EOCD 记录被截断",
  eocd_not_at_tail: "EOCD 不位于文件尾（伪签名）",
  zip64_sentinel_without_locator: "ZIP64 哨兵字段但缺 locator",
  zip64_locator_truncated: "ZIP64 locator 被截断",
  zip64_eocd_target_bad: "locator 指向的不是 ZIP64 EOCD",
  entry_budget_exceeded: "条目数超过资源预算",
  integer_wrap_or_oversize: "整数回绕或尺寸非法",
  central_directory_out_of_bounds: "中央目录区间越界",
  central_directory_truncated: "中央目录记录被截断",
  central_bad_signature: "中央目录签名错误",
};

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}
function rangeText(r) {
  if (!r) return '<span class="muted">—</span>';
  return `<span class="range mono">[${r.start}, ${r.end}) · ${r.length}B</span>`;
}
function findingsBlock(findings) {
  if (!findings || !findings.length) return "";
  return findings.map((f) => `
    <div class="finding sev-${f.severity}">
      <strong>[${SEV_LABEL[f.severity] || f.severity}]</strong>
      <code>${esc(f.code)}</code> ${esc(f.message)}
      ${f.range ? ` <span class="range">@[${f.range.start},${f.range.end})</span>` : ""}
    </div>`).join("");
}
function crcClass(status) {
  if (status === "ok") return "crc-ok";
  if (status === "mismatch") return "crc-mismatch";
  return "crc-skip";
}
function renderCandidate(c, preferred) {
  const cls = c.valid
    ? (preferred === c.index ? "candidate valid-preferred" : "candidate")
    : "candidate excluded";
  let head = `
    <div class="${cls} card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 style="margin:0">候选目录 #${c.index}
            ${c.valid ? '<span class="pill ok">自洽</span>'
                      : '<span class="pill bad">已排除</span>'}
            ${c.zip64 ? '<span class="pill zip64">ZIP64</span>' : ""}
            ${preferred === c.index ? '<span class="pill pref">证词首选</span>' : ""}
          </h2>
        </div>
        <div class="muted mono">EOCD ${rangeText(c.eocd_range)}</div>
      </div>
      <div class="grid2" style="margin-top:10px">
        <div><span class="tag">EOCD 区间</span>${rangeText(c.eocd_range)}</div>
        <div><span class="tag">注释区间</span>${rangeText(c.comment_range)}（${c.comment_len}B）</div>
        <div><span class="tag">磁盘号/CD磁盘</span>${c.disk_no} / ${c.cd_disk}</div>
        <div><span class="tag">条目数</span>本盘 ${c.entries_disk} · 总计 ${c.entries_total}</div>
        <div><span class="tag">CD 区间</span>${rangeText(c.central_directory_range)}</div>
        <div><span class="tag">ZIP64 EOCD</span>${rangeText(c.zip64_eocd_range)}</div>
        <div><span class="tag">ZIP64 locator</span>${rangeText(c.zip64_locator_range)}</div>
      </div>`;
  if (!c.valid) {
    return head + `
      <div class="banner critical" style="margin-top:12px">
        <strong>排除原因：</strong>
        <code>${esc(c.exclusion_reason)}</code>
        — ${esc(EXCLUDE_LABEL[c.exclusion_reason] || "")}
        <div class="muted" style="margin-top:4px">${esc(c.exclusion_detail || "")}</div>
      </div>
      <div>${findingsBlock(c.findings)}</div>
    </div>`;
  }
  const rows = c.members.map((m) => {
    const desc = m.bit3_descriptor
      ? (m.descriptor_signed === true ? "带签名"
         : m.descriptor_signed === false ? "无签名" : "无法判定")
      : "无 bit3";
    return `<tr>
      <td>${m.index}</td>
      <td class="mono">${esc(m.name)}
        ${m.utf8_flag ? '<span class="pill" style="margin-left:4px">UTF-8</span>' : ""}
        ${m.encrypted ? '<span class="pill bad" style="margin-left:4px">加密</span>' : ""}
      </td>
      <td>${m.method}</td>
      <td>${m.bit3_descriptor ? "1" : "0"}<div class="muted">${desc}${m.descriptor_ambiguous ? " · 歧义" : ""}</div></td>
      <td class="${crcClass(m.crc_status)}">${esc(m.crc_status)}</td>
      <td>
        <div><span class="tag">中央头</span>${rangeText(m.central_header_range)}</div>
        <div><span class="tag">局部头</span>${rangeText(m.local_header_range)}</div>
        <div><span class="tag">压缩数据</span>${rangeText(m.data_range)}</div>
        <div><span class="tag">descriptor</span>${rangeText(m.descriptor_range)}</div>
        <div><span class="tag">局部 extra</span>${rangeText(m.local_extra_range)}</div>
        <div><span class="tag">中央 extra</span>${rangeText(m.central_extra_range)}</div>
      </td>
      <td class="mono">
        <div>CD: crc=0x${(m.central_crc >>> 0).toString(16).padStart(8, "0")}
          comp=${m.central_comp_size} uncomp=${m.central_uncomp_size}</div>
        <div class="muted">LF: ${m.local_crc === null ? "—" :
          `crc=0x${(m.local_crc >>> 0).toString(16).padStart(8, "0")} comp=${m.local_comp_size} uncomp=${m.local_uncomp_size}`}
        </div>
        <div class="muted">offset=${m.local_offset}（${m.local_offset_source}）磁盘${m.disk_start}</div>
      </td>
      <td>${findingsBlock(m.findings)}</td>
    </tr>`;
  }).join("");
  return head + `
    ${findingsBlock(c.findings).length ? `<div style="margin-top:10px">${findingsBlock(c.findings)}</div>` : ""}
    <details open style="margin-top:12px">
      <summary>${c.members.length} 个成员：中央目录声明 / 局部头声明 / 实际压缩数据范围 / CRC</summary>
      <table>
        <thead><tr>
          <th>#</th><th>名称</th><th>方法</th><th>bit3</th>
          <th>CRC</th><th>精确字节区间</th><th>尺寸证词</th><th>成员发现</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </details>
    </div>`;
}
function renderReport(report) {
  const el = document.getElementById("report");
  const banners = report.findings.map((f) =>
    `<div class="banner ${f.severity === "critical" ? "critical" : "high"}">
       <strong>[${SEV_LABEL[f.severity] || f.severity}]</strong>
       <code>${esc(f.code)}</code> ${esc(f.message)}</div>`).join("");
  const cands = report.candidates.map((c) =>
    renderCandidate(c, report.preferred_candidate)).join("");
  el.innerHTML = `
    <section class="card">
      <h2>整包证词</h2>
      <div class="grid2">
        <div><span class="tag">SHA-256</span><span class="mono">${esc(report.sha256)}</span></div>
        <div><span class="tag">大小</span>${report.size} 字节</div>
        <div><span class="tag">EOCD 候选</span>${report.candidates.length} 个
          （${report.candidates.filter((c) => c.valid).length} 个自洽）</div>
        <div><span class="tag">首选候选</span>${
            report.preferred_candidate === null ? "无" : "#" + report.preferred_candidate}</div>
      </div>
      ${banners}
      ${report.rejected ? `<div class="banner critical">已拒绝解析：${esc(report.reject_reason || "")}</div>` : ""}
    </section>
    ${cands}`;
}
async function refreshList() {
  const r = await fetch("/api/archives");
  const data = await r.json();
  const card = document.getElementById("archiveListCard");
  const tbody = document.querySelector("#archiveTable tbody");
  if (!data.archives.length) { card.hidden = true; return; }
  card.hidden = false;
  tbody.innerHTML = data.archives.map((a) => `
    <tr>
      <td>${a.id}</td>
      <td class="mono clickable" onclick="loadArchive(${a.id})">${esc(a.filename)}</td>
      <td>${a.size}</td>
      <td class="mono">${esc(a.sha256.slice(0, 24))}…</td>
      <td class="muted">${esc(a.imported_at)}</td>
    </tr>`).join("");
}
async function loadArchive(id) {
  const r = await fetch(`/api/archives/${id}`);
  renderReport((await r.json()).report);
}
function setStatus(msg, isErr) {
  const s = document.getElementById("status");
  s.textContent = msg;
  s.style.color = isErr ? "var(--high)" : "var(--muted)";
}
document.getElementById("uploadBtn").onclick = async () => {
  const f = document.getElementById("file").files[0];
  if (!f) { setStatus("请先选择 ZIP 文件", true); return; }
  setStatus("审阅中（不向磁盘解压）…");
  const fd = new FormData();
  fd.append("file", f);
  const r = await fetch("/api/archives", { method: "POST", body: fd });
  if (!r.ok) { setStatus(`审阅失败：${await r.text()}`, true); return; }
  const data = await r.json();
  setStatus(data.reused ? `命中既有记录 #${data.archive_id}（整包哈希一致，身份复用）`
                        : `已导入 #${data.archive_id}`);
  renderReport(data.report);
  refreshList();
};
document.getElementById("fixtureBtn").onclick = async () => {
  const name = document.getElementById("fixtureSelect").value;
  setStatus(`导入内置样例 ${name} …`);
  const r = await fetch(`/api/fixtures/${encodeURIComponent(name)}/import`,
                        { method: "POST" });
  const data = await r.json();
  if (!r.ok) { setStatus(`失败：${data.detail || r.status}`, true); return; }
  setStatus(data.reused ? "整包哈希一致，复用既有证词记录" : "新样例已导入");
  renderReport(data.report);
  refreshList();
};
(async function init() {
  const r = await fetch("/api/fixtures");
  const data = await r.json();
  document.getElementById("fixtureSelect").innerHTML =
    data.fixtures.map((f) => `<option>${esc(f.name)}</option>`).join("");
  refreshList();
})();

const form = document.getElementById('scanForm');
const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const loading = document.getElementById('loading');
const error = document.getElementById('error');
const result = document.getElementById('result');

let lastData = null;

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  error.classList.add('hidden');
  result.classList.add('hidden');
  loading.classList.remove('hidden');
  scanBtn.disabled = true;
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: urlInput.value }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Scan fejlede');
    render(data);
  } catch (err) {
    error.textContent = err.message;
    error.classList.remove('hidden');
  } finally {
    loading.classList.add('hidden');
    scanBtn.disabled = false;
  }
});

function render(data) {
  lastData = data;
  // save history
  try {
    const hist = JSON.parse(localStorage.getItem('nis2hist') || '[]');
    hist.unshift({ url: data.url, score: data.score, grade: data.grade, at: data.scannedAt });
    localStorage.setItem('nis2hist', JSON.stringify(hist.slice(0, 10)));
  } catch (e) {}
  const gradeEl = document.getElementById('grade');
  gradeEl.textContent = data.grade;
  gradeEl.className = 'grade grade-' + data.grade;
  document.getElementById('score').textContent = `Score: ${data.score}/100`;
  document.getElementById('meta').textContent = `${data.hostname} · ${data.checks.filter(c=>c.pass).length}/${data.checks.length} checks bestået`;
  const checksEl = document.getElementById('checks');
  checksEl.innerHTML = '';
  data.checks.forEach((c) => {
    const div = document.createElement('div');
    div.className = 'check ' + (c.pass ? 'pass' : 'fail');
    let html = `<div class="cat">${c.category}</div><div class="title">${c.pass ? '✓' : '✗'} ${escapeHtml(c.title)}</div><div class="detail">${escapeHtml(c.detail)}</div>`;
    if (c.suggestion) {
      html += `<div class="suggestion ${c.pass ? 'ok' : ''}"><strong>Forslag:</strong> ${escapeHtml(c.suggestion)}</div>`;
    }
    if (c.reference) {
      html += `<div class="ref">Reference: <a href="${c.reference.url}" target="_blank" rel="noopener">${escapeHtml(c.reference.title)}</a></div>`;
    }
    div.innerHTML = html;
    checksEl.appendChild(div);
  });
  result.classList.remove('hidden');
}

document.getElementById('exportBtn').addEventListener('click', () => {
  if (!lastData) return;
  const blob = new Blob([JSON.stringify(lastData, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'nis2-report.json';
  a.click();
  URL.revokeObjectURL(a.href);
});

document.getElementById('historyBtn').addEventListener('click', () => {
  const el = document.getElementById('history');
  if (!el.classList.contains('hidden')) { el.classList.add('hidden'); return; }
  let hist = [];
  try { hist = JSON.parse(localStorage.getItem('nis2hist') || '[]'); } catch (e) {}
  el.innerHTML = hist.length ? hist.map(h => `<div>${escapeHtml(h.url)} — ${h.score}/100 (${h.grade}) <span style="color:#64748b">${new Date(h.at).toLocaleString()}</span></div>`).join('') : 'Ingen historik endnu.';
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (m) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

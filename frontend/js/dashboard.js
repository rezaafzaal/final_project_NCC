const counts = { total: 0, info: 0, warning: 0, critical: 0 };
let filterSeverity = '';
let filterSource = '';

document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  connectWS();
  loadInitialEvents();
});

async function loadInitialEvents() {
  const res = await fetch('/api/events?limit=50');
  const data = await res.json();
  data.events.forEach(e => addEventRow(e, false));

  const stats = await fetch('/api/stats').then(r => r.json());
  counts.total    = stats.total;
  counts.info     = stats.info;
  counts.warning  = stats.warning;
  counts.critical = stats.critical;
  updateStatCards();
  updateSeverityChart(counts.info, counts.warning, counts.critical);
}

function handleIncomingEvent(event) {
  counts.total++;
  const sev = (event.severity || 'INFO').toLowerCase();
  if (counts[sev] !== undefined) counts[sev]++;
  updateStatCards();
  updateSeverityChart(counts.info, counts.warning, counts.critical);
  pushTimelinePoint(event.severity);
  addEventRow(event, true);
}

function updateStatCards() {
  document.getElementById('stat-total').textContent    = counts.total;
  document.getElementById('stat-info').textContent     = counts.info;
  document.getElementById('stat-warning').textContent  = counts.warning;
  document.getElementById('stat-critical').textContent = counts.critical;
}

function addEventRow(event, prepend = true) {
  if (filterSeverity && event.severity !== filterSeverity) return;
  if (filterSource   && event.source   !== filterSource)   return;

  const tbody = document.getElementById('events-body');
  const tr = document.createElement('tr');

  const sevClass = { INFO: 'sev-info', WARNING: 'sev-warning', CRITICAL: 'sev-critical' }[event.severity] || '';
  const ruleHtml = event.rule_triggered
    ? `<span class="rule-badge">${event.rule_triggered}</span>`
    : '-';

  tr.innerHTML = `
    <td>${event.timestamp ? event.timestamp.replace('T', ' ').slice(0, 19) : '-'}</td>
    <td>${event.source || '-'}</td>
    <td>${event.ip || '-'}</td>
    <td>${event.user || '-'}</td>
    <td>${event.action || '-'}</td>
    <td>${event.status || '-'}</td>
    <td class="${sevClass}">${event.severity || '-'}</td>
    <td>${ruleHtml}</td>
  `;

  if (prepend && tbody.firstChild) {
    tbody.insertBefore(tr, tbody.firstChild);
    // Batasi baris di tabel agar tidak berat
    if (tbody.children.length > 200) tbody.removeChild(tbody.lastChild);
  } else {
    tbody.appendChild(tr);
  }
}

function applyFilter() {
  filterSeverity = document.getElementById('filter-severity').value;
  filterSource   = document.getElementById('filter-source').value;
  document.getElementById('events-body').innerHTML = '';
  loadInitialEvents();
}

function clearEvents() {
  document.getElementById('events-body').innerHTML = '';
}

async function applyLogPath() {
  const path = document.getElementById('log-path-input').value.trim();
  const source = document.getElementById('log-source-select').value;
  const msg = document.getElementById('log-path-msg');
  if (!path) return;
  try {
    const res = await fetch('/api/config/log-path', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source, path }),
    });
    const data = await res.json();
    msg.textContent = data.message;
    msg.style.color = data.status === 'ok' ? '#4ade80' : '#f87171';
  } catch {
    msg.textContent = 'Gagal menghubungi server.';
    msg.style.color = '#f87171';
  }
}

let severityChart, timelineChart;
const timelineData = { labels: [], info: [], warning: [], critical: [] };

const BUCKET_INTERVAL = 30000; // 30 detik per bucket
const MAX_BUCKETS = 30;        // 30 bucket × 30 detik = 15 menit

let _bucket = { info: 0, warning: 0, critical: 0 };
let _bucketLabel = '';
let _bucketTimer = null;

function _flushBucket() {
  if (timelineData.labels.length >= MAX_BUCKETS) {
    timelineData.labels.shift();
    timelineData.info.shift();
    timelineData.warning.shift();
    timelineData.critical.shift();
  }
  timelineData.labels.push(_bucketLabel);
  timelineData.info.push(_bucket.info);
  timelineData.warning.push(_bucket.warning);
  timelineData.critical.push(_bucket.critical);
  timelineChart.update('none');
  _bucket = { info: 0, warning: 0, critical: 0 };
  _bucketLabel = new Date().toLocaleTimeString();
}

function initCharts() {
  const severityCtx = document.getElementById('chart-severity').getContext('2d');
  severityChart = new Chart(severityCtx, {
    type: 'doughnut',
    data: {
      labels: ['INFO', 'WARNING', 'CRITICAL'],
      datasets: [{
        data: [0, 0, 0],
        backgroundColor: ['#3b82f6', '#f59e0b', '#ef4444'],
        borderWidth: 0,
      }]
    },
    options: {
      plugins: { legend: { labels: { color: '#e2e8f0' } } },
      cutout: '65%',
    }
  });

  const timelineCtx = document.getElementById('chart-timeline').getContext('2d');
  timelineChart = new Chart(timelineCtx, {
    type: 'line',
    data: {
      labels: timelineData.labels,
      datasets: [
        { label: 'INFO',     data: timelineData.info,     borderColor: '#3b82f6', tension: 0.3, fill: false },
        { label: 'WARNING',  data: timelineData.warning,  borderColor: '#f59e0b', tension: 0.3, fill: false },
        { label: 'CRITICAL', data: timelineData.critical, borderColor: '#ef4444', tension: 0.3, fill: false },
      ]
    },
    options: {
      plugins: { legend: { labels: { color: '#e2e8f0' } } },
      scales: {
        x: { ticks: { color: '#64748b' }, grid: { color: '#2a2d3a' } },
        y: { ticks: { color: '#64748b' }, grid: { color: '#2a2d3a' }, beginAtZero: true },
      }
    }
  });
}

function updateSeverityChart(info, warning, critical) {
  severityChart.data.datasets[0].data = [info, warning, critical];
  severityChart.update('none');
}

function pushTimelinePoint(severity) {
  const sev = severity.toLowerCase();
  if (_bucket[sev] !== undefined) _bucket[sev]++;

  if (!_bucketTimer) {
    _bucketLabel = new Date().toLocaleTimeString();
    _bucketTimer = setInterval(_flushBucket, BUCKET_INTERVAL);
  }
}

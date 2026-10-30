/* ============================================
   SHIELDSCAN – APP JAVASCRIPT
   ============================================ */

'use strict';

// ============================================
// STATE
// ============================================
const state = {
  scanResults: [],
  filteredResults: [],
  currentFilter: 'all',
  scanning: false,
  selectedFiles: []
};

// ============================================
// PAGE TITLES
// ============================================
const PAGE_META = {
  dashboard: { title: 'Dashboard', subtitle: 'Security Overview' },
  scanner:   { title: 'File Scanner', subtitle: 'Upload & Analyze Files' },
  results:   { title: 'Scan Results', subtitle: 'Full Report Log' },
  about:     { title: 'About ShieldScan', subtitle: 'Features & Setup Guide' }
};

// ============================================
// NAVIGATION
// ============================================
function showSection(name) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const section = document.getElementById('section-' + name);
  const navItem = document.getElementById('nav-' + name);
  if (section) section.classList.add('active');
  if (navItem) navItem.classList.add('active');

  const meta = PAGE_META[name] || { title: name, subtitle: '' };
  document.getElementById('pageTitle').textContent = meta.title;
  document.getElementById('pageSubtitle').textContent = meta.subtitle;

  // Close mobile sidebar
  closeSidebar();
}

// ============================================
// SIDEBAR TOGGLE
// ============================================
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  sidebar.classList.toggle('open');
  overlay.classList.toggle('open');
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebarOverlay').classList.remove('open');
}

// ============================================
// LIVE CLOCK
// ============================================
function updateClock() {
  const now = new Date();
  const h = String(now.getHours()).padStart(2, '0');
  const m = String(now.getMinutes()).padStart(2, '0');
  const s = String(now.getSeconds()).padStart(2, '0');
  const el = document.getElementById('topbarTime');
  if (el) el.textContent = h + ':' + m + ':' + s;
}
setInterval(updateClock, 1000);
updateClock();

// ============================================
// FILE TYPE UTILITIES
// ============================================
const FILE_ICONS = {
  jpg: '🖼', jpeg: '🖼', png: '🖼', gif: '🖼', webp: '🖼', svg: '🖼',
  pdf: '📄', doc: '📝', docx: '📝', txt: '📃', csv: '📊', xlsx: '📊',
  exe: '⚙', bat: '⚙', sh: '⚙', msi: '⚙',
  zip: '🗜', rar: '🗜', gz: '🗜', tar: '🗜',
  mp4: '🎬', avi: '🎬', mkv: '🎬',
  mp3: '🎵', wav: '🎵',
  js:  '📦', py: '🐍', html: '🌐', css: '🎨', json: '{}',
};

function getFileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  return FILE_ICONS[ext] || '📄';
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function getExtension(name) {
  const parts = name.split('.');
  return parts.length > 1 ? parts.pop().toUpperCase() : 'NO_EXT';
}

// ============================================
// MAGIC BYTE DETECTION (Client-side simulation)
// ============================================
const MAGIC_SIGNATURES = {
  JPEG: [0xFF, 0xD8, 0xFF],
  PNG:  [0x89, 0x50, 0x4E, 0x47],
  PDF:  [0x25, 0x50, 0x44, 0x46],
  ZIP:  [0x50, 0x4B, 0x03, 0x04],
  EXE:  [0x4D, 0x5A],
  RAR:  [0x52, 0x61, 0x72, 0x21],
  ELF:  [0x7F, 0x45, 0x4C, 0x46],
};

function detectMagicType(buffer) {
  const bytes = new Uint8Array(buffer);
  for (const [type, sig] of Object.entries(MAGIC_SIGNATURES)) {
    if (sig.every((b, i) => bytes[i] === b)) return type;
  }
  return 'UNKNOWN';
}

// ============================================
// SHA-256 HASHING (Web Crypto API)
// ============================================
async function sha256(buffer) {
  try {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    return 'hash-unavailable-' + Math.random().toString(36).slice(2, 12);
  }
}

// ============================================
// FILE SELECTION & DROP ZONE
// ============================================
function handleFileSelect(event) {
  const files = Array.from(event.target.files);
  addFiles(files);
}

function addFiles(files) {
  state.selectedFiles = [...state.selectedFiles, ...files];
  renderFileList();
}

function renderFileList() {
  const selectedSection = document.getElementById('selectedFiles');
  const dropInner = document.getElementById('dropInner');
  const fileList = document.getElementById('fileList');
  const countEl = document.getElementById('selectedCount');

  if (state.selectedFiles.length === 0) {
    selectedSection.style.display = 'none';
    dropInner.style.display = 'flex';
    return;
  }

  dropInner.style.display = 'none';
  selectedSection.style.display = 'block';
  countEl.textContent = state.selectedFiles.length + ' file' + (state.selectedFiles.length > 1 ? 's' : '') + ' selected';

  fileList.innerHTML = state.selectedFiles.map((f, i) => `
    <li>
      <span class="file-icon">${getFileIcon(f.name)}</span>
      <span class="file-name">${f.name}</span>
      <span class="file-size">${formatSize(f.size)}</span>
    </li>
  `).join('');
}

function clearFiles() {
  state.selectedFiles = [];
  document.getElementById('fileInput').value = '';
  renderFileList();
}

// Drag and drop
const dropZone = document.getElementById('dropZone');
if (dropZone) {
  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const files = Array.from(e.dataTransfer.files);
    addFiles(files);
  });
}

// ============================================
// SCAN ENGINE
// ============================================
async function startScan() {
  if (state.scanning) return;
  if (state.selectedFiles.length === 0) {
    showToast('warning', '⚠', 'No files selected. Please add files to scan.');
    return;
  }

  state.scanning = true;
  const scanBtn = document.getElementById('scanBtn');
  const progressSection = document.getElementById('progressSection');
  const progressFill = document.getElementById('progressFill');
  const progressPct = document.getElementById('progressPct');
  const progressLabel = document.getElementById('progressLabel');
  const progressDetail = document.getElementById('progressDetail');

  scanBtn.disabled = true;
  progressSection.style.display = 'block';

  const results = [];
  const total = state.selectedFiles.length;

  for (let i = 0; i < total; i++) {
    const file = state.selectedFiles[i];
    const pct = Math.round(((i) / total) * 100);
    progressFill.style.width = pct + '%';
    progressPct.textContent = pct + '%';
    progressLabel.textContent = `Analyzing file ${i + 1} of ${total}…`;
    progressDetail.textContent = file.name;

    // Read file bytes
    let buffer;
    try {
      buffer = await file.arrayBuffer();
    } catch (e) {
      buffer = new ArrayBuffer(0);
    }

    const realType = detectMagicType(buffer);
    const claimedExt = getExtension(file.name);
    const hash = await sha256(buffer);

    // Determine status
    let status = 'clean';
    let isSuspicious = false;

    if (realType !== 'UNKNOWN' && claimedExt !== realType) isSuspicious = true;
    if (claimedExt === 'EXE' || realType === 'EXE') isSuspicious = true;

    const vtResult = 'Not checked';

    if (isSuspicious) {
      status = 'suspicious';
    }

    results.push({
      id: Date.now() + i,
      name: file.name,
      claimed: claimedExt,
      actual: realType,
      size: file.size,
      hash: hash,
      vtResult: vtResult,
      status: status,
      timestamp: new Date().toLocaleString()
    });

    // Artificial delay for UX
    await sleep(180);
  }

  // Final progress
  progressFill.style.width = '100%';
  progressPct.textContent = '100%';
  progressLabel.textContent = 'Scan complete!';
  progressDetail.textContent = `${total} file${total > 1 ? 's' : ''} analyzed.`;

  await sleep(600);

  // Commit results
  state.scanResults = [...results, ...state.scanResults];
  state.filteredResults = [...state.scanResults];

  updateDashboard();
  updateResultsTable();
  addActivityItems(results);

  // Reset UI
  state.scanning = false;
  scanBtn.disabled = false;
  progressSection.style.display = 'none';

  const maliciousCount = results.filter(r => r.status === 'malicious').length;
  const suspiciousCount = results.filter(r => r.status === 'suspicious').length;

  if (maliciousCount > 0) {
    showToast('error', '🚨', `Scan complete! ${maliciousCount} malware threat(s) detected!`);
  } else if (suspiciousCount > 0) {
    showToast('warning', '⚠', `Scan complete. ${suspiciousCount} suspicious file(s) found.`);
  } else {
    showToast('success', '✅', `Scan complete. All ${total} file(s) appear clean.`);
  }

  clearFiles();
  showSection('results');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================
// DASHBOARD UPDATE
// ============================================
function updateDashboard() {
  const total = state.scanResults.length;
  const clean = state.scanResults.filter(r => r.status === 'clean').length;
  const suspicious = state.scanResults.filter(r => r.status === 'suspicious').length;
  const malicious = state.scanResults.filter(r => r.status === 'malicious').length;

  animateCounter('statTotalVal', total);
  animateCounter('statCleanVal', clean);
  animateCounter('statSuspiciousVal', suspicious);
  animateCounter('statMaliciousVal', malicious);

  // Update threat level
  const badge = document.getElementById('threatLevelBadge');
  if (malicious > 0) {
    badge.innerHTML = '<span class="threat-dot high"></span><span>Threat: <strong>High</strong></span>';
  } else if (suspicious > 0) {
    badge.innerHTML = '<span class="threat-dot medium"></span><span>Threat: <strong>Medium</strong></span>';
  } else {
    badge.innerHTML = '<span class="threat-dot low"></span><span>Threat: <strong>Low</strong></span>';
  }

  // Donut chart
  updateDonut(total, clean, suspicious, malicious);

  // File type breakdown
  updateTypeBreakdown();

  // Threat table
  updateThreatTable();
}

function animateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  const duration = 600;
  const step = (timestamp) => {
    const progress = Math.min((timestamp - startTime) / duration, 1);
    el.textContent = Math.round(start + (target - start) * easeOut(progress));
    if (progress < 1) requestAnimationFrame(step);
  };
  let startTime;
  requestAnimationFrame(ts => { startTime = ts; step(ts); });
}

function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

function updateDonut(total, clean, suspicious, malicious) {
  const circ = 439.8;
  const totalEl = document.getElementById('donutTotal');
  if (totalEl) totalEl.textContent = total;

  if (total === 0) {
    ['cleanSeg', 'suspiciousSeg', 'maliciousSeg'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.setAttribute('stroke-dasharray', `0 ${circ}`);
    });
    return;
  }

  const cleanArc = (clean / total) * circ;
  const suspArc = (suspicious / total) * circ;
  const malArc = (malicious / total) * circ;

  const cleanEl = document.getElementById('cleanSeg');
  const suspEl = document.getElementById('suspiciousSeg');
  const malEl = document.getElementById('maliciousSeg');

  if (cleanEl) {
    cleanEl.setAttribute('stroke-dasharray', `${cleanArc} ${circ - cleanArc}`);
    cleanEl.setAttribute('stroke-dashoffset', '0');
  }
  if (suspEl) {
    suspEl.setAttribute('stroke-dasharray', `${suspArc} ${circ - suspArc}`);
    suspEl.setAttribute('stroke-dashoffset', `-${cleanArc}`);
  }
  if (malEl) {
    malEl.setAttribute('stroke-dasharray', `${malArc} ${circ - malArc}`);
    malEl.setAttribute('stroke-dashoffset', `-${cleanArc + suspArc}`);
  }
}

function updateTypeBreakdown() {
  const typeList = document.getElementById('typeList');
  if (!typeList) return;

  if (state.scanResults.length === 0) {
    typeList.innerHTML = '<p class="empty-state">No scan data yet.</p>';
    return;
  }

  const typeCounts = {};
  state.scanResults.forEach(r => {
    const t = r.actual !== 'UNKNOWN' ? r.actual : r.claimed;
    typeCounts[t] = (typeCounts[t] || 0) + 1;
  });

  const max = Math.max(...Object.values(typeCounts));
  const sorted = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);

  typeList.innerHTML = sorted.map(([type, count]) => `
    <div class="type-bar-item">
      <div class="type-bar-label">
        <span>${type}</span>
        <strong>${count}</strong>
      </div>
      <div class="type-bar-track">
        <div class="type-bar-fill" style="width: ${(count / max) * 100}%"></div>
      </div>
    </div>
  `).join('');
}

function updateThreatTable() {
  const body = document.getElementById('dashThreatBody');
  if (!body) return;

  const threats = state.scanResults.filter(r => r.status !== 'clean').slice(0, 5);

  if (threats.length === 0) {
    body.innerHTML = '<tr><td colspan="7" class="empty-cell">No threats logged yet. Start a scan.</td></tr>';
    return;
  }

  body.innerHTML = threats.map((r, i) => `
    <tr>
      <td>${i + 1}</td>
      <td class="fname-cell" title="${r.name}">${r.name}</td>
      <td>${r.claimed}</td>
      <td>${r.actual}</td>
      <td class="hash-cell" title="${r.hash}">${r.hash.slice(0, 16)}…</td>
      <td>${r.vtResult}</td>
      <td><span class="status-badge ${r.status}">${statusLabel(r.status)}</span></td>
    </tr>
  `).join('');
}

function statusLabel(status) {
  return { clean: '✅ Clean', suspicious: '⚠ Suspicious', malicious: '🚨 Malware' }[status] || status;
}

// ============================================
// RESULTS TABLE
// ============================================
function updateResultsTable() {
  renderResultsTable(state.filteredResults);
}

function renderResultsTable(data) {
  const body = document.getElementById('resultsBody');
  const footer = document.getElementById('tableFooter');
  if (!body) return;

  if (data.length === 0) {
    body.innerHTML = '<tr><td colspan="9" class="empty-cell">No results match your filter.</td></tr>';
    if (footer) footer.textContent = 'Showing 0 results';
    return;
  }

  body.innerHTML = data.map((r, i) => `
    <tr data-status="${r.status}">
      <td>${i + 1}</td>
      <td class="fname-cell" title="${r.name}">${r.name}</td>
      <td>${r.claimed}</td>
      <td>${r.actual}</td>
      <td>${formatSize(r.size)}</td>
      <td class="hash-cell" title="${r.hash}">${r.hash.slice(0, 16)}…</td>
      <td>${r.vtResult}</td>
      <td><span class="status-badge ${r.status}">${statusLabel(r.status)}</span></td>
      <td>
        <div class="action-cell">
          <button class="row-btn" onclick="copyHash('${r.hash}')">Copy Hash</button>
          <button class="row-btn del" onclick="deleteResult(${r.id})">Remove</button>
        </div>
      </td>
    </tr>
  `).join('');

  if (footer) footer.textContent = `Showing ${data.length} result${data.length !== 1 ? 's' : ''}`;
}

function copyHash(hash) {
  navigator.clipboard.writeText(hash).then(() => {
    showToast('info', '📋', 'SHA-256 hash copied to clipboard!');
  }).catch(() => {
    showToast('warning', '⚠', 'Could not copy to clipboard.');
  });
}

function deleteResult(id) {
  state.scanResults = state.scanResults.filter(r => r.id !== id);
  applyFilter();
  updateDashboard();
  showToast('info', '🗑', 'Entry removed from results.');
}

// ============================================
// FILTER & SEARCH
// ============================================
function filterResults(filter) {
  state.currentFilter = filter;

  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  const btn = document.getElementById('filter-' + filter);
  if (btn) btn.classList.add('active');

  applyFilter();
}

function applyFilter() {
  const query = (document.getElementById('searchInput')?.value || '').toLowerCase();
  let data = state.scanResults;

  if (state.currentFilter !== 'all') {
    data = data.filter(r => r.status === state.currentFilter);
  }
  if (query) {
    data = data.filter(r =>
      r.name.toLowerCase().includes(query) ||
      r.hash.toLowerCase().includes(query) ||
      r.actual.toLowerCase().includes(query)
    );
  }

  state.filteredResults = data;
  renderResultsTable(data);
}

function searchResults() {
  applyFilter();
}

// ============================================
// EXPORT CSV
// ============================================
function exportResults() {
  if (state.scanResults.length === 0) {
    showToast('warning', '⚠', 'No results to export.');
    return;
  }

  const headers = ['#', 'Filename', 'Claimed', 'Actual', 'Size (bytes)', 'SHA-256', 'VirusTotal', 'Status', 'Timestamp'];
  const rows = state.scanResults.map((r, i) => [
    i + 1, r.name, r.claimed, r.actual, r.size, r.hash, r.vtResult, r.status, r.timestamp
  ]);

  const csv = [headers, ...rows].map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');

  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `shieldscan_report_${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);

  showToast('success', '📥', 'Report exported as CSV!');
}

// ============================================
// CLEAR ALL
// ============================================
function clearAllResults() {
  if (state.scanResults.length === 0) {
    showToast('info', 'ℹ', 'Nothing to clear.');
    return;
  }
  state.scanResults = [];
  state.filteredResults = [];
  updateDashboard();
  updateResultsTable();
  showToast('info', '🗑', 'All scan history cleared.');
}

// ============================================
// ACTIVITY FEED
// ============================================
function addActivityItems(results) {
  const feed = document.getElementById('activityFeed');
  if (!feed) return;

  const existing = feed.innerHTML.includes('empty-state') ? '' : feed.innerHTML;

  const newItems = results.slice(0, 3).map(r => {
    const color = r.status === 'malicious' ? 'var(--danger-red)' : r.status === 'suspicious' ? 'var(--warn-amber)' : 'var(--accent-green)';
    return `<div class="activity-item">
      <span class="act-dot" style="background:${color}"></span>
      <span>${r.name} — ${statusLabel(r.status)}</span>
    </div>`;
  }).join('');

  feed.innerHTML = newItems + existing;
}

// ============================================
// TOAST NOTIFICATIONS
// ============================================
function showToast(type, icon, message) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span class="toast-icon">${icon}</span><span class="toast-msg">${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(40px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ============================================
// DEMO DATA (load sample results on first visit)
// ============================================
function loadDemoData() {
  const demo = [
    { id: 1001, name: 'invoice_2024.pdf.exe', claimed: 'EXE', actual: 'EXE', size: 1245184, hash: 'a4b8c2d1e6f3970a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4', vtResult: '⚠ MALWARE DETECTED (7 flags)', status: 'malicious', timestamp: new Date().toLocaleString() },
    { id: 1002, name: 'photo_vacation.jpg.png', claimed: 'PNG', actual: 'JPEG', size: 2097152, hash: 'b5c9d3e7f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6', vtResult: 'Not checked', status: 'suspicious', timestamp: new Date().toLocaleString() },
    { id: 1003, name: 'document.pdf', claimed: 'PDF', actual: 'PDF', size: 512000, hash: 'c6d0e4f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7', vtResult: '✅ Clean on VirusTotal', status: 'clean', timestamp: new Date().toLocaleString() },
    { id: 1004, name: 'script_update.bat', claimed: 'BAT', actual: 'UNKNOWN', size: 4096, hash: 'd7e1f5a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9', vtResult: '❔ Unknown (new file)', status: 'suspicious', timestamp: new Date().toLocaleString() },
    { id: 1005, name: 'image_asset.png', claimed: 'PNG', actual: 'PNG', size: 768000, hash: 'e8f2a6b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0', vtResult: 'Skipped (no API key)', status: 'clean', timestamp: new Date().toLocaleString() },
    { id: 1006, name: 'archive.zip', claimed: 'ZIP', actual: 'ZIP', size: 10485760, hash: 'f9a3b7c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1', vtResult: 'Skipped (no API key)', status: 'clean', timestamp: new Date().toLocaleString() },
  ];

  state.scanResults = demo;
  state.filteredResults = demo;
  updateDashboard();
  updateResultsTable();
}

// ============================================
// INIT
// ============================================
document.addEventListener('DOMContentLoaded', () => {
  loadDemoData();
  updateClock();

  // Add keyboard shortcut: Escape closes sidebar
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeSidebar();
  });
});

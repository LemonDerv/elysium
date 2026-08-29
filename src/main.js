// Tauri API helper
function getInvoke() {
  if (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke) {
    return window.__TAURI__.core.invoke;
  }
  if (window.__TAURI__ && window.__TAURI__.invoke) {
    return window.__TAURI__.invoke;
  }
  return null;
}

async function invoke(cmd, args = {}) {
  const fn = getInvoke();
  if (!fn) {
    console.warn('Tauri API not ready yet for command:', cmd);
    throw new Error('Tauri API not initialized');
  }
  return await fn(cmd, args);
}

// ── Page Navigation ──
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  const navBtn = document.querySelector(`[data-page="${name}"]`);
  if (navBtn) navBtn.classList.add('active');
}

// ── Toast ──
function showToast(msg, type = 'info') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast ' + type;
  setTimeout(() => t.classList.add('hidden'), 3000);
}

// ── Create Room ──
async function createRoom() {
  const btn = document.getElementById('createBtn');
  btn.disabled = true;
  btn.textContent = 'Creating...';
  try {
    const code = await invoke('create_room');
    document.getElementById('generatedCode').textContent = code;
    document.getElementById('roomCreatedInfo').classList.remove('hidden');
    btn.textContent = '✅ Room Created';
    showToast('Room created! Share the code with friends.', 'success');
    refreshStatus();
  } catch (e) {
    showToast('Failed: ' + e, 'error');
    btn.disabled = false;
    btn.textContent = '⚡ Create Room';
  }
}

// ── Join Room ──
async function joinRoom() {
  const code = document.getElementById('joinCodeInput').value.trim().toUpperCase();
  if (!code) { showToast('Enter an invite code', 'error'); return; }

  const btn = document.getElementById('joinBtn');
  const status = document.getElementById('joinStatus');
  btn.disabled = true;
  btn.textContent = 'Joining...';
  status.classList.add('hidden');

  try {
    const ip = await invoke('join_room', { code });
    status.textContent = `Connected! Your IP: ${ip}`;
    status.className = 'status-message success';
    btn.textContent = '✅ Joined';
    showToast('Joined room ' + code, 'success');
    refreshStatus();
    setTimeout(() => showPage('dashboard'), 1000);
  } catch (e) {
    status.textContent = 'Failed: ' + e;
    status.className = 'status-message error';
    btn.disabled = false;
    btn.textContent = 'Join';
  }
}

// ── Leave Room ──
async function leaveRoom() {
  try {
    await invoke('leave_room');
    showToast('Left room', 'info');
    // Reset create page
    document.getElementById('createBtn').disabled = false;
    document.getElementById('createBtn').textContent = '⚡ Create Room';
    document.getElementById('roomCreatedInfo').classList.add('hidden');
    // Reset join page
    document.getElementById('joinBtn').disabled = false;
    document.getElementById('joinBtn').textContent = 'Join';
    document.getElementById('joinCodeInput').value = '';
    document.getElementById('joinStatus').classList.add('hidden');
    refreshStatus();
  } catch (e) {
    showToast('Error: ' + e, 'error');
  }
}

// ── Copy Code ──
function copyCode() {
  const code = document.getElementById('generatedCode').textContent;
  navigator.clipboard.writeText(code);
  showToast('Code copied!', 'success');
}

// ── Refresh Status ──
async function refreshStatus() {
  try {
    const s = await invoke('get_status');

    // Update dashboard cards
    document.getElementById('statusValue').textContent = s.connected ? '🟢 Connected' : '⚫ Offline';
    document.getElementById('nodeNameValue').textContent = s.node_name;
    document.getElementById('virtualIpValue').textContent = s.virtual_ip || '—';
    document.getElementById('roomCodeValue').textContent = s.room_code || '—';

    // Connection indicator
    const dot = document.getElementById('connectionDot');
    const txt = document.getElementById('connectionText');
    dot.className = s.connected ? 'status-indicator connected' : 'status-indicator';
    txt.textContent = s.connected ? 'Connected' : 'Disconnected';

    // Settings page
    document.getElementById('settingsNodeName').textContent = s.node_name;
    document.getElementById('settingsPublicKey').textContent = s.public_key;

    // Active room section
    if (s.connected && s.peers.length > 0) {
      document.getElementById('activeRoomSection').classList.remove('hidden');
      document.getElementById('noRoomSection').classList.add('hidden');
      renderPeers(s.peers);
    } else {
      document.getElementById('activeRoomSection').classList.add('hidden');
      document.getElementById('noRoomSection').classList.remove('hidden');
    }
  } catch (e) {
    console.error('Status refresh failed:', e);
  }
}

// ── Render Peers ──
function renderPeers(peers) {
  const list = document.getElementById('peerList');
  list.innerHTML = peers.map(p => `
    <div class="peer-card">
      <div class="peer-status ${p.connected ? 'online' : 'offline'}"></div>
      <div class="peer-info">
        <div class="peer-name">${escapeHtml(p.node_name)}</div>
        <div class="peer-ip">${escapeHtml(p.virtual_ip)}</div>
      </div>
      <div class="peer-latency">${p.latency_ms != null ? escapeHtml(p.latency_ms.toFixed(1)) + ' ms' : '—'}</div>
    </div>
  `).join('');
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ── Init ──
window.addEventListener('DOMContentLoaded', () => {
  // Bind events
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => showPage(btn.getAttribute('data-page')));
  });
  
  const createBtn = document.getElementById('createBtn');
  if (createBtn) createBtn.addEventListener('click', createRoom);
  
  const joinBtn = document.getElementById('joinBtn');
  if (joinBtn) joinBtn.addEventListener('click', joinRoom);
  
  const leaveBtn = document.querySelector('#activeRoomSection .btn-danger');
  if (leaveBtn) leaveBtn.addEventListener('click', leaveRoom);
  
  const copyBtn = document.querySelector('.invite-code .btn-icon');
  if (copyBtn) copyBtn.addEventListener('click', copyCode);
  
  const createNavBtn = document.querySelector('.empty-actions .btn-primary');
  if (createNavBtn) createNavBtn.addEventListener('click', () => showPage('create'));
  
  const joinNavBtn = document.querySelector('.empty-actions .btn-secondary');
  if (joinNavBtn) joinNavBtn.addEventListener('click', () => showPage('join'));

  refreshStatus();
  // Refresh status every 3 seconds
  setInterval(refreshStatus, 3000);
});

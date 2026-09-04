// ── Elysium — Virtual LAN — Client Engine & UI Controller ──

// Tauri API invoke helper
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
    console.warn('Tauri API not ready for command:', cmd);
    throw new Error('Tauri API not initialized');
  }
  return await fn(cmd, args);
}

// ── State Cache & Concurrency Locks ──
let lastStatusJson = null;
let currentStatus = null;
let toastTimeout = null;
let isStatusRefreshing = false;
let isCreating = false;
let isJoining = false;
let isLeaving = false;
let lastConnectedState = null;

// ── Page Navigation ──
function showPage(name) {
  const targetPage = document.getElementById('page-' + name);
  if (!targetPage) {
    console.warn(`Attempted to navigate to nonexistent page: page-${name}`);
    return;
  }
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  
  targetPage.classList.add('active');
  
  const navBtn = document.querySelector(`.nav-btn[data-page="${name}"]`);
  if (navBtn) {
    navBtn.classList.add('active');
  }

  if (name === 'join') {
    loadKnownRooms();
  }
}

// ── Toast Notification System ──
function showToast(msg, type = 'info') {
  const toast = document.getElementById('toast');
  const toastMsg = document.getElementById('toastMessage');
  const toastIcon = document.getElementById('toastIcon');
  if (!toast || !toastMsg) return;

  if (toastTimeout) {
    clearTimeout(toastTimeout);
  }

  toastMsg.textContent = msg;
  toast.className = `toast ${type}`;

  if (toastIcon) {
    let iconHref = '#icon-info';
    if (type === 'success') iconHref = '#icon-check';
    if (type === 'error') iconHref = '#icon-alert';
    toastIcon.innerHTML = `<use href="${iconHref}"></use>`;
  }

  toastTimeout = setTimeout(() => {
    toast.classList.add('hidden');
  }, 3500);
}

// ── Clipboard Copy Helper with Visual Feedback & Re-entrancy Protection ──
function copyToClipboard(text, successMsg = 'Copied to clipboard', btnEl = null) {
  if (!text || text === '—') return;
  if (btnEl && btnEl.classList.contains('btn-copied')) return;

  if (!navigator.clipboard?.writeText) {
    showToast('Clipboard API unavailable', 'error');
    return;
  }

  navigator.clipboard.writeText(text).then(() => {
    showToast(successMsg, 'success');
    if (btnEl) {
      const originalHtml = btnEl.dataset.originalHtml || btnEl.innerHTML;
      btnEl.dataset.originalHtml = originalHtml;
      btnEl.classList.add('btn-copied');
      btnEl.innerHTML = '<svg class="icon icon-sm" style="color: var(--status-connected);"><use href="#icon-check"></use></svg>';
      setTimeout(() => {
        if (btnEl.dataset.originalHtml) {
          btnEl.innerHTML = btnEl.dataset.originalHtml;
        }
        btnEl.classList.remove('btn-copied');
      }, 1500);
    }
  }).catch(err => {
    console.error('Copy failed:', err);
    showToast('Failed to copy', 'error');
  });
}

// ── Load Previously Known Rooms from Config ──
async function loadKnownRooms() {
  try {
    const rooms = await invoke('get_known_rooms');
    const container = document.getElementById('knownRoomsContainer');
    const list = document.getElementById('knownRoomsList');
    if (!container || !list) return;

    if (Array.isArray(rooms) && rooms.length > 0) {
      list.innerHTML = rooms.map(r => `
        <div class="known-room-item" data-code="${escapeHtml(r)}" title="Click to use this room token">
          <span class="known-room-code">${escapeHtml(r)}</span>
          <span class="badge-tag mono" style="font-size: 10px;">Select</span>
        </div>
      `).join('');
      container.classList.remove('hidden');

      list.querySelectorAll('.known-room-item').forEach(item => {
        item.addEventListener('click', () => {
          const code = item.getAttribute('data-code');
          const input = document.getElementById('joinCodeInput');
          if (input && code) {
            input.value = code;
            input.focus();
            showToast('Room token loaded into input', 'info');
          }
        });
      });
    } else {
      container.classList.add('hidden');
    }
  } catch (e) {
    console.debug('Could not load known rooms:', e);
  }
}

// ── Create Room Action ──
async function createRoom() {
  if (isCreating) return;
  if (currentStatus && currentStatus.connected) {
    showToast('Please disconnect from your current network first', 'error');
    return;
  }

  const btn = document.getElementById('createBtn');
  if (!btn) return;

  isCreating = true;
  btn.disabled = true;
  const originalHtml = btn.innerHTML;
  btn.innerHTML = '<svg class="icon icon-sm" style="animation: spin 1s linear infinite;"><use href="#icon-loader"></use></svg> <span>Creating Mesh...</span>';

  try {
    const code = await invoke('create_room');
    const codeEl = document.getElementById('generatedCode');
    if (codeEl) codeEl.textContent = code;

    const infoEl = document.getElementById('roomCreatedInfo');
    if (infoEl) infoEl.classList.remove('hidden');

    btn.innerHTML = '<svg class="icon icon-sm" style="color: var(--status-connected);"><use href="#icon-check"></use></svg> <span>Network Created</span>';
    showToast('Mesh network created successfully', 'success');
    await refreshStatus(true);
  } catch (e) {
    showToast('Failed to create network: ' + e, 'error');
    btn.disabled = false;
    btn.innerHTML = originalHtml;
  } finally {
    isCreating = false;
  }
}

// ── Join Room Action ──
async function joinRoom() {
  if (isJoining) return;
  if (currentStatus && currentStatus.connected) {
    showToast('Please disconnect from your current network first', 'error');
    return;
  }

  const input = document.getElementById('joinCodeInput');
  const code = input ? input.value.replace(/\s+/g, '') : '';
  if (!code) {
    showToast('Please paste a valid room invite token', 'error');
    if (input) input.focus();
    return;
  }

  const btn = document.getElementById('joinBtn');
  const status = document.getElementById('joinStatus');
  if (!btn || !status) return;

  isJoining = true;
  btn.disabled = true;
  if (input) input.disabled = true;
  const originalHtml = btn.innerHTML;
  btn.innerHTML = '<svg class="icon icon-sm" style="animation: spin 1s linear infinite;"><use href="#icon-loader"></use></svg> <span>Connecting...</span>';
  status.classList.add('hidden');

  try {
    const ip = await invoke('join_room', { code });
    status.innerHTML = `<svg class="icon icon-sm"><use href="#icon-check"></use></svg> <span>Connected to virtual LAN! Allocated IP: <strong>${escapeHtml(ip)}</strong></span>`;
    status.className = 'status-message success';
    status.classList.remove('hidden');

    btn.innerHTML = '<svg class="icon icon-sm"><use href="#icon-check"></use></svg> <span>Connected</span>';
    showToast(`Connected with Virtual IP ${ip}`, 'success');
    await refreshStatus(true);

    setTimeout(() => {
      showPage('dashboard');
    }, 800);
  } catch (e) {
    status.innerHTML = `<svg class="icon icon-sm"><use href="#icon-alert"></use></svg> <span>Connection failed: ${escapeHtml(e)}</span>`;
    status.className = 'status-message error';
    status.classList.remove('hidden');

    btn.disabled = false;
    btn.innerHTML = originalHtml;
  } finally {
    isJoining = false;
    if (input) input.disabled = false;
  }
}

// ── Leave Room Action ──
async function leaveRoom() {
  if (isLeaving) return;
  isLeaving = true;
  try {
    await invoke('leave_room');
    showToast('Disconnected from virtual network', 'info');

    // Reset Create Room Page
    const createBtn = document.getElementById('createBtn');
    if (createBtn) {
      createBtn.disabled = false;
      createBtn.innerHTML = '<svg class="icon"><use href="#icon-plus"></use></svg> <span>Initialize &amp; Create Network</span>';
    }
    const createdInfo = document.getElementById('roomCreatedInfo');
    if (createdInfo) createdInfo.classList.add('hidden');

    // Reset Join Room Page
    const joinBtn = document.getElementById('joinBtn');
    if (joinBtn) {
      joinBtn.disabled = false;
      joinBtn.innerHTML = '<svg class="icon icon-sm"><use href="#icon-link"></use></svg> <span>Connect</span>';
    }
    const joinInput = document.getElementById('joinCodeInput');
    if (joinInput) joinInput.value = '';
    const joinStatus = document.getElementById('joinStatus');
    if (joinStatus) joinStatus.classList.add('hidden');

    // Clear peer table
    const tbody = document.getElementById('peerList');
    if (tbody) tbody.innerHTML = '';
    const badge = document.getElementById('peerCountBadge');
    if (badge) badge.textContent = '0 active';

    await refreshStatus(true);
  } catch (e) {
    showToast('Error leaving network: ' + e, 'error');
  } finally {
    isLeaving = false;
  }
}

// ── Refresh Status (Synchronous DOM Update) ──
async function refreshStatus(force = false) {
  if (isStatusRefreshing && !force) return;
  isStatusRefreshing = true;

  try {
    const s = await invoke('get_status');
    const jsonStr = JSON.stringify(s);

    if (!force && jsonStr === lastStatusJson) {
      return;
    }
    lastStatusJson = jsonStr;
    currentStatus = s;

    // Sidebar Node Name & Connection Status
    const sidebarNode = document.getElementById('sidebarNodeName');
    if (sidebarNode) sidebarNode.textContent = s.node_name || 'Local Node';

    const connDot = document.getElementById('connectionDot');
    const connTxt = document.getElementById('connectionText');
    if (connDot && connTxt) {
      if (s.connected) {
        connDot.className = 'status-badge connected';
        connTxt.textContent = 'Connected';
      } else {
        connDot.className = 'status-badge';
        connTxt.textContent = 'Standby';
      }
    }

    const sidebarIp = document.getElementById('sidebarIpPreview');
    if (sidebarIp) {
      sidebarIp.textContent = s.virtual_ip || '10.7.0.0/24';
    }

    // Dashboard Header Subhead
    const subhead = document.getElementById('dashboardSubhead');
    if (subhead) {
      if (s.connected) {
        subhead.textContent = `Connected to virtual network (${s.peers.length} ${s.peers.length === 1 ? 'node' : 'nodes'} active)`;
      } else {
        subhead.textContent = 'Virtual LAN status and mesh topology details';
      }
    }

    // Dashboard Top Header Quick Actions (only rebuild when connection state toggles to prevent dropping user clicks)
    const headerActions = document.getElementById('dashboardHeaderActions');
    if (headerActions && (lastConnectedState !== s.connected || force)) {
      lastConnectedState = s.connected;
      if (s.connected) {
        headerActions.innerHTML = `
          <button class="btn btn-secondary btn-sm" id="quickCopyInviteBtn">
            <svg class="icon icon-sm"><use href="#icon-copy"></use></svg>
            <span>Copy Invite</span>
          </button>
          <button class="btn btn-danger btn-sm" id="quickLeaveBtn">
            <svg class="icon icon-sm"><use href="#icon-power"></use></svg>
            <span>Disconnect</span>
          </button>
        `;
        const qCopy = document.getElementById('quickCopyInviteBtn');
        if (qCopy) qCopy.addEventListener('click', function() {
          if (s.room_code) copyToClipboard(s.room_code, 'Invite code copied to clipboard', this);
        });
        const qLeave = document.getElementById('quickLeaveBtn');
        if (qLeave) qLeave.addEventListener('click', leaveRoom);
      } else {
        headerActions.innerHTML = `
          <button class="btn btn-secondary btn-sm" id="quickJoinBtn">
            <svg class="icon icon-sm"><use href="#icon-link"></use></svg>
            <span>Join</span>
          </button>
          <button class="btn btn-primary btn-sm" id="quickCreateBtn">
            <svg class="icon icon-sm"><use href="#icon-plus"></use></svg>
            <span>Create Network</span>
          </button>
        `;
        const qJoin = document.getElementById('quickJoinBtn');
        if (qJoin) qJoin.addEventListener('click', () => showPage('join'));
        const qCreate = document.getElementById('quickCreateBtn');
        if (qCreate) qCreate.addEventListener('click', () => showPage('create'));
      }
    }

    // Dashboard Interface Summary Metrics
    const summaryStatus = document.getElementById('summaryStatusBadge');
    const statusVal = document.getElementById('statusValue');
    if (summaryStatus && statusVal) {
      if (s.connected) {
        summaryStatus.className = 'status-badge connected';
        statusVal.textContent = 'Connected';
      } else {
        summaryStatus.className = 'status-badge';
        statusVal.textContent = 'Standby';
      }
    }

    const nodeNameVal = document.getElementById('nodeNameValue');
    if (nodeNameVal) nodeNameVal.textContent = s.node_name || '—';

    const virtualIpVal = document.getElementById('virtualIpValue');
    if (virtualIpVal) virtualIpVal.textContent = s.virtual_ip || '—';

    const roomCodeVal = document.getElementById('roomCodeValue');
    if (roomCodeVal) {
      if (s.room_code) {
        roomCodeVal.textContent = s.room_code.length > 16 
          ? s.room_code.substring(0, 10) + '...' + s.room_code.slice(-6)
          : s.room_code;
        roomCodeVal.title = s.room_code;
      } else {
        roomCodeVal.textContent = '—';
        roomCodeVal.title = '';
      }
    }

    // Settings Page Fields
    const settingsNode = document.getElementById('settingsNodeName');
    if (settingsNode) settingsNode.textContent = s.node_name || '—';

    const settingsPk = document.getElementById('settingsPublicKey');
    if (settingsPk) {
      settingsPk.textContent = s.public_key || '—';
      settingsPk.title = s.public_key || '';
    }

    // Create Room & Join Room Notice State
    const createNotice = document.getElementById('createConnectedNotice');
    const createBtn = document.getElementById('createBtn');
    if (createNotice && createBtn) {
      if (s.connected) {
        createNotice.classList.remove('hidden');
        createBtn.disabled = true;
        createBtn.title = 'Disconnect from current network to create a new one';
      } else {
        createNotice.classList.add('hidden');
        createBtn.disabled = false;
        createBtn.title = '';
      }
    }

    const joinNotice = document.getElementById('joinConnectedNotice');
    const joinBtn = document.getElementById('joinBtn');
    if (joinNotice && joinBtn) {
      if (s.connected) {
        joinNotice.classList.remove('hidden');
        joinBtn.disabled = true;
        joinBtn.title = 'Disconnect from current network to join another';
      } else {
        joinNotice.classList.add('hidden');
        joinBtn.disabled = false;
        joinBtn.title = '';
      }
    }

    // Active Room vs Standby Section
    const activeSection = document.getElementById('activeRoomSection');
    const noRoomSection = document.getElementById('noRoomSection');
    const peerCountBadge = document.getElementById('peerCountBadge');

    if (s.connected) {
      if (activeSection) activeSection.classList.remove('hidden');
      if (noRoomSection) noRoomSection.classList.add('hidden');
      if (peerCountBadge) {
        peerCountBadge.textContent = `${s.peers.length} active`;
      }
      renderPeers(s.peers, s.node_name, s.virtual_ip);
    } else {
      if (activeSection) activeSection.classList.add('hidden');
      if (noRoomSection) noRoomSection.classList.remove('hidden');
      const tbody = document.getElementById('peerList');
      if (tbody) tbody.innerHTML = '';
      if (peerCountBadge) peerCountBadge.textContent = '0 active';
    }
  } catch (e) {
    console.error('Status refresh error:', e);
  } finally {
    isStatusRefreshing = false;
  }
}

// ── Render Peer Table ──
function renderPeers(peers, localNodeName, localVirtualIp) {
  const tbody = document.getElementById('peerList');
  if (!tbody) return;

  if (!peers || peers.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">
          Waiting for peers to join this network session...
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = peers.map(p => {
    // Precise self-identification based on cryptographic IP allocation
    const isSelf = Boolean(localVirtualIp && p.virtual_ip === localVirtualIp);
    const isHost = p.virtual_ip === '10.7.0.1';

    let latencyHtml = '<span class="peer-latency-badge text-muted">—</span>';
    if (!isSelf && p.latency_ms != null && p.latency_ms > 0) {
      const lat = p.latency_ms;
      let latencyClass = 'good';
      if (lat > 80) latencyClass = 'moderate';
      if (lat > 150) latencyClass = 'text-muted';

      const jitterVal = p.jitter_ms != null ? p.jitter_ms : 0.0;
      const lossVal = p.packet_loss_pct != null ? p.packet_loss_pct : 0.0;
      const hasLoss = lossVal > 0.0;

      latencyHtml = `
        <div class="peer-latency-metrics">
          <span class="peer-latency-badge ${latencyClass}" title="RTT: ${lat.toFixed(1)}ms | Jitter: ${jitterVal.toFixed(1)}ms | Loss: ${lossVal.toFixed(1)}%">
            <svg class="icon icon-sm"><use href="#icon-activity"></use></svg>
            <span>${lat < 1.0 ? '<1 ms' : `${lat.toFixed(1)} ms`}</span>
          </span>
          <span class="peer-jitter-subtext ${hasLoss ? 'has-loss' : ''}">
            ±${jitterVal.toFixed(1)}ms jitter${lossVal > 0 ? ` · ${lossVal.toFixed(0)}% loss` : ''}
          </span>
        </div>
      `;
    }

    let protocolLabel = 'WireGuard P2P';
    if (!isSelf) {
      if (localVirtualIp === '10.7.0.1') {
        protocolLabel = 'Direct Mesh';
      } else if (isHost) {
        protocolLabel = 'Direct Gateway';
      } else {
        protocolLabel = 'Relayed (Mesh)';
      }
    }

    // CSP-compliant: Uses data-ip attribute instead of inline onclick handlers
    return `
      <tr>
        <td>
          <div class="peer-node-cell">
            <span class="peer-status-dot ${p.connected ? 'online' : ''}" title="${p.connected ? 'Connected' : 'Offline'}"></span>
            <div class="peer-node-details">
              <span class="peer-node-name" title="${escapeHtml(p.node_name)}">
                ${escapeHtml(p.node_name)}
                ${isSelf ? '<span class="peer-tag">This Device</span>' : ''}
                ${isHost && !isSelf ? '<span class="peer-tag" style="background: var(--bg-surface-elevated); color: var(--text-secondary); border-color: var(--border-subtle);">Host</span>' : ''}
              </span>
            </div>
          </div>
        </td>
        <td>
          <button class="peer-ip-badge copy-peer-ip" data-ip="${escapeHtml(p.virtual_ip)}" title="Click to copy IP">
            <span>${escapeHtml(p.virtual_ip)}</span>
            <svg class="icon icon-sm"><use href="#icon-copy"></use></svg>
          </button>
        </td>
        <td>
          <span class="peer-protocol-badge">${protocolLabel}</span>
        </td>
        <td>
          ${latencyHtml}
        </td>
        <td style="text-align: right;">
          <button class="btn-icon copy-peer-ip" data-ip="${escapeHtml(p.virtual_ip)}" title="Copy Virtual IP">
            <svg class="icon icon-sm"><use href="#icon-copy"></use></svg>
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

// ── HTML Escape Utility ──
function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ── Initialize Event Listeners ──
window.addEventListener('DOMContentLoaded', () => {
  // Navigation tabs
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const page = btn.getAttribute('data-page');
      if (page) showPage(page);
    });
  });

  // Delegated click listener for peer list (Complies with strict CSP: no inline onclick)
  const peerList = document.getElementById('peerList');
  if (peerList) {
    peerList.addEventListener('click', (e) => {
      const btn = e.target.closest('.copy-peer-ip');
      if (btn && btn.dataset.ip) {
        copyToClipboard(btn.dataset.ip, 'Virtual IP copied to clipboard', btn);
      }
    });
  }

  // Delegated click listener for header action buttons
  const headerActions = document.getElementById('dashboardHeaderActions');
  if (headerActions) {
    headerActions.addEventListener('click', (e) => {
      if (e.target.closest('#quickJoinBtn')) showPage('join');
      else if (e.target.closest('#quickCreateBtn')) showPage('create');
      else if (e.target.closest('#quickLeaveBtn')) leaveRoom();
      else if (e.target.closest('#quickCopyInviteBtn')) {
        if (currentStatus?.room_code) {
          copyToClipboard(currentStatus.room_code, 'Invite code copied to clipboard', e.target.closest('#quickCopyInviteBtn'));
        }
      }
    });
  }

  // Standby Action Buttons
  const standbyCreateBtn = document.getElementById('standbyCreateBtn');
  if (standbyCreateBtn) standbyCreateBtn.addEventListener('click', () => showPage('create'));

  const standbyJoinBtn = document.getElementById('standbyJoinBtn');
  if (standbyJoinBtn) standbyJoinBtn.addEventListener('click', () => showPage('join'));

  const goToDashboardAfterCreate = document.getElementById('goToDashboardAfterCreate');
  if (goToDashboardAfterCreate) goToDashboardAfterCreate.addEventListener('click', () => showPage('dashboard'));

  // Disconnect buttons in Create/Join notices
  const createDisconnectBtn = document.getElementById('createDisconnectBtn');
  if (createDisconnectBtn) createDisconnectBtn.addEventListener('click', leaveRoom);

  const joinDisconnectBtn = document.getElementById('joinDisconnectBtn');
  if (joinDisconnectBtn) joinDisconnectBtn.addEventListener('click', leaveRoom);

  // Create Room
  const createBtn = document.getElementById('createBtn');
  if (createBtn) createBtn.addEventListener('click', createRoom);

  const copyCreatedCodeBtn = document.getElementById('copyCreatedCodeBtn');
  if (copyCreatedCodeBtn) {
    copyCreatedCodeBtn.addEventListener('click', function() {
      const code = document.getElementById('generatedCode').textContent;
      copyToClipboard(code, 'Invite code copied to clipboard', this);
    });
  }

  // Join Room
  const joinBtn = document.getElementById('joinBtn');
  if (joinBtn) joinBtn.addEventListener('click', joinRoom);

  const joinInput = document.getElementById('joinCodeInput');
  if (joinInput) {
    joinInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        joinRoom();
      }
    });
  }

  // Leave Room / Disconnect
  const leaveRoomBtn = document.getElementById('leaveRoomBtn');
  if (leaveRoomBtn) leaveRoomBtn.addEventListener('click', leaveRoom);

  // Copy Room Code / Invite
  const copyRoomCodeBtn = document.getElementById('copyRoomCodeBtn');
  if (copyRoomCodeBtn) {
    copyRoomCodeBtn.addEventListener('click', function() {
      if (currentStatus && currentStatus.room_code) {
        copyToClipboard(currentStatus.room_code, 'Mesh room token copied', this);
      }
    });
  }

  const shareRoomBtn = document.getElementById('shareRoomBtn');
  if (shareRoomBtn) {
    shareRoomBtn.addEventListener('click', function() {
      if (currentStatus && currentStatus.room_code) {
        copyToClipboard(currentStatus.room_code, 'Invite code copied to clipboard', this);
      }
    });
  }

  // Copy Node Name
  const copyNodeNameBtn = document.getElementById('copyNodeNameBtn');
  if (copyNodeNameBtn) {
    copyNodeNameBtn.addEventListener('click', function() {
      if (currentStatus && currentStatus.node_name) {
        copyToClipboard(currentStatus.node_name, 'Node name copied', this);
      }
    });
  }

  // Copy Virtual IP
  const copyVirtualIpBtn = document.getElementById('copyVirtualIpBtn');
  if (copyVirtualIpBtn) {
    copyVirtualIpBtn.addEventListener('click', function() {
      if (currentStatus && currentStatus.virtual_ip) {
        copyToClipboard(currentStatus.virtual_ip, 'Virtual IP copied', this);
      }
    });
  }

  // Copy Settings Public Key
  const copySettingsPublicKeyBtn = document.getElementById('copySettingsPublicKeyBtn');
  if (copySettingsPublicKeyBtn) {
    copySettingsPublicKeyBtn.addEventListener('click', function() {
      if (currentStatus && currentStatus.public_key) {
        copyToClipboard(currentStatus.public_key, 'Public key copied to clipboard', this);
      }
    });
  }

  // Copy Diagnostics
  const copyDiagnosticsBtn = document.getElementById('copyDiagnosticsBtn');
  if (copyDiagnosticsBtn) {
    copyDiagnosticsBtn.addEventListener('click', function() {
      if (currentStatus) {
        const diag = {
          client: 'Elysium v0.1.0-alpha',
          timestamp: new Date().toISOString(),
          status: currentStatus,
          userAgent: navigator.userAgent
        };
        copyToClipboard(JSON.stringify(diag, null, 2), 'Diagnostics JSON copied', this);
      }
    });
  }

  // Initial queries and status refresh loop
  refreshStatus(true);
  loadKnownRooms();
  setInterval(() => refreshStatus(false), 2500);
});

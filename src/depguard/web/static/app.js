const loginView = document.querySelector('#login-view');
const workspaceView = document.querySelector('#workspace-view');
const loginMessage = document.querySelector('#login-message');
const registerMessage = document.querySelector('#register-message');
const scanMessage = document.querySelector('#scan-message');
const identity = document.querySelector('#identity');
let csrfToken = '';

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  const response = await fetch(`/api/v1${path}`, { ...options, headers, credentials: 'same-origin' });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
  return payload;
}

function showWorkspace(username) {
  identity.textContent = username;
  loginView.classList.add('hidden');
  workspaceView.classList.remove('hidden');
  document.querySelector('#logout').classList.remove('hidden');
  refreshScans();
}

function textCell(value, className = '') {
  const cell = document.createElement('td');
  if (className) cell.className = className;
  cell.textContent = value;
  return cell;
}

async function refreshScans() {
  try {
    const scans = await api('/scans');
    const rows = document.querySelector('#scan-rows');
    rows.replaceChildren();
    document.querySelector('#scan-count').textContent = `${scans.length} scan${scans.length === 1 ? '' : 's'}`;
    if (!scans.length) {
      const row = document.createElement('tr');
      const empty = textCell('No scans yet.');
      empty.colSpan = 5;
      empty.className = 'empty';
      row.append(empty);
      rows.append(row);
      return;
    }
    for (const scan of scans) {
      const row = document.createElement('tr');
      const target = document.createElement('td');
      const link = document.createElement('button');
      link.type = 'button';
      link.className = 'scan-target';
      link.textContent = `Scan #${scan.scan_id}`;
      link.addEventListener('click', () => showFindings(scan.scan_id));
      target.append(link);
      row.append(target, textCell(new Date(scan.scan_date).toLocaleString()));
      const status = textCell(scan.status, `status ${scan.status}`);
      row.append(status, textCell(`${scan.risk_score.toFixed(1)} · ${scan.risk_level}`), textCell('View'));
      rows.append(row);
    }
    if (scans.some(scan => ['queued', 'running'].includes(scan.status))) {
      window.setTimeout(refreshScans, 2500);
    }
  } catch (error) {
    scanMessage.textContent = error.message;
  }
}

async function showFindings(scanId) {
  const panel = document.querySelector('#finding-view');
  panel.replaceChildren();
  try {
    const scan = await api(`/scans/${scanId}`);
    const heading = document.createElement('h2');
    heading.textContent = `Scan #${scan.scan_id} · ${scan.status}`;
    panel.append(heading);
    if (!scan.findings.length) {
      const note = document.createElement('p');
      note.textContent = 'No findings are available for this scan.';
      panel.append(note);
    }
    for (const item of scan.findings) {
      const article = document.createElement('article');
      article.className = 'finding';
      const title = document.createElement('strong');
      title.textContent = `${item.severity} · ${item.title}`;
      const evidence = document.createElement('p');
      evidence.textContent = item.evidence;
      const remediation = document.createElement('p');
      remediation.textContent = `Remediation: ${item.remediation}`;
      article.append(title, evidence, remediation);
      panel.append(article);
    }
    panel.classList.remove('hidden');
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (error) {
    scanMessage.textContent = error.message;
  }
}

document.querySelector('#login-form').addEventListener('submit', async event => {
  event.preventDefault();
  loginMessage.textContent = '';
  const form = new FormData(event.currentTarget);
  try {
    const result = await api('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: form.get('username'), password: form.get('password') }),
    });
    csrfToken = result.csrf_token;
    const user = await api('/auth/me');
    showWorkspace(user.username);
  } catch (error) {
    loginMessage.textContent = error.message;
  }
});

document.querySelector('#register-toggle').addEventListener('click', () => {
  document.querySelector('#login-form').classList.add('hidden');
  document.querySelector('#register-form').classList.remove('hidden');
});

document.querySelector('#login-toggle').addEventListener('click', () => {
  document.querySelector('#register-form').classList.add('hidden');
  document.querySelector('#login-form').classList.remove('hidden');
});

document.querySelector('#register-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  registerMessage.textContent = '';
  try {
    await api('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        username: document.querySelector('#register-username').value,
        email: document.querySelector('#register-email').value,
        password: document.querySelector('#register-password').value,
      }),
    });
    registerMessage.textContent = 'Account created. Sign in to continue.';
    form.reset();
  } catch (error) {
    registerMessage.textContent = error.message;
  }
});

document.querySelector('#scan-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  scanMessage.textContent = '';
  try {
    await api('/scans', {
      method: 'POST',
      body: JSON.stringify({
        target_url: document.querySelector('#target-url').value,
        authorization_confirmed: document.querySelector('#authorization').checked,
        profile: document.querySelector('#profile').value,
      }),
    });
    scanMessage.textContent = 'Scan queued.';
    form.reset();
    refreshScans();
  } catch (error) {
    scanMessage.textContent = error.message;
  }
});

document.querySelector('#refresh').addEventListener('click', refreshScans);
document.querySelector('#logout').addEventListener('click', async () => {
  try { await api('/auth/logout', { method: 'POST' }); } catch { /* Local view still resets. */ }
  csrfToken = '';
  workspaceView.classList.add('hidden');
  loginView.classList.remove('hidden');
  document.querySelector('#logout').classList.add('hidden');
  identity.textContent = 'Not signed in';
});

api('/auth/me').then(user => {
  csrfToken = user.csrf_token;
  showWorkspace(user.username);
}).catch(() => {});

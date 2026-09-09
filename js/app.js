// ============================================
//   0923 · 给你的信 — 应用逻辑
//   Token 用密码加密存储在 config.js
//   输入密码后自动解密，无需手动输入 token
// ============================================

// ---------- 全局状态 ----------
let notes = [];
let currentNoteId = null;
let editingNoteId = null;
let isSyncing = false;
let currentFileSha = null;
let decryptedToken = null; // 解密后的 token（内存中）

// ---------- SHA-256 ----------
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------- Token 加密/解密（AES-GCM）----------
async function deriveKey(password) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: new TextEncoder().encode('0923'), iterations: 100000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptToken(token, password) {
    const key = await deriveKey(password);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        new TextEncoder().encode(token)
    );
    const ivBase64 = btoa(String.fromCharCode(...iv));
    const encBase64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    return `${ivBase64}:${encBase64}`;
}

async function decryptToken(encryptedToken, password) {
    try {
        const [ivBase64, encBase64] = encryptedToken.split(':');
        const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
        const encrypted = Uint8Array.from(atob(encBase64), c => c.charCodeAt(0));
        const key = await deriveKey(password);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            encrypted
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        throw new Error('解密失败，密码错误');
    }
}

// ---------- GitHub API ----------
function getConfig() {
    if (typeof GITHUB_CONFIG === 'undefined') {
        console.error('config.js 未加载');
        return null;
    }
    return GITHUB_CONFIG;
}

function githubHeaders() {
    if (!decryptedToken) return {};
    return {
        'Authorization': `Bearer ${decryptedToken}`,
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json'
    };
}

// 读取 GitHub 文件
async function githubReadFile(filePath) {
    const config = getConfig();
    const url = `https://api.github.com/repos/${config.owner}/${config.repo}/contents/${filePath}?ref=${config.branch}`;
    const resp = await fetch(url, { headers: githubHeaders() });

    if (resp.status === 404) return { content: '[]', sha: null };
    if (!resp.ok) throw new Error(`读取失败 (${resp.status})`);

    const data = await resp.json();
    const rawContent = atob(data.content);
    const content = decodeURIComponent(escape(rawContent));
    return { content, sha: data.sha };
}

// 创建 Issue
async function githubCreateIssue(title, body) {
    const config = getConfig();
    const url = `https://api.github.com/repos/${config.owner}/${config.repo}/issues`;

    const resp = await fetch(url, {
        method: 'POST',
        headers: githubHeaders(),
        body: JSON.stringify({ title, body })
    });

    if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(`创建同步请求失败 (${resp.status}): ${err.message || ''}`);
    }

    return resp.json();
}

// ---------- Token 设置界面 ----------
function showTokenSetup() {
    const overlay = document.createElement('div');
    overlay.id = 'tokenOverlay';
    overlay.className = 'token-overlay';
    overlay.innerHTML = `
        <div class="token-modal">
            <div class="token-title">🔑 首次设置 Token</div>
            <div class="token-desc">
                请输入你的 GitHub Token<br>
                <span class="token-hint">Token 会用密码加密后存储在 config.js 中</span>
            </div>
            <input type="password" class="token-input" id="tokenInput" placeholder="粘贴你的 Token">
            <div class="token-error" id="tokenError"></div>
            <button class="token-btn" id="tokenBtn">加密并保存</button>
        </div>
    `;
    document.body.appendChild(overlay);

    const handleSave = async () => {
        const input = document.getElementById('tokenInput');
        const error = document.getElementById('tokenError');
        const token = input.value.trim();

        if (!token) {
            error.textContent = '请输入 Token';
            error.classList.add('show');
            return;
        }

        // 验证 Token（尝试读取文件）
        decryptedToken = token;
        try {
            await githubReadFile('data/letters.json');
        } catch (e) {
            if (e.message.includes('401') || e.message.includes('403')) {
                error.textContent = 'Token 无效或权限不足';
                error.classList.add('show');
                decryptedToken = null;
                return;
            }
        }

        // Token 有效，加密
        const password = '20040923';
        const encrypted = await encryptToken(token, password);

        // 生成新的 config.js 内容
        const newConfig = `/**
 * ============================================
 *   0923 · 给你的信 — 配置文件
 * ============================================
 */

const GITHUB_CONFIG = {
    owner: '${getConfig().owner}',
    repo: '${getConfig().repo}',
    branch: '${getConfig().branch}',
    encryptedToken: '${encrypted}',
    passwordHash: '${getConfig().passwordHash}'
};
`;

        // 显示结果
        overlay.innerHTML = `
            <div class="token-modal">
                <div class="token-title">✅ 加密成功</div>
                <div class="token-desc">
                    请复制以下代码，替换你的 <code>config.js</code> 文件内容，然后 push 到 GitHub：
                </div>
                <textarea class="token-textarea" id="configOutput" readonly>${newConfig}</textarea>
                <button class="token-btn" id="copyBtn">复制代码</button>
                <div class="token-skip">
                    <span class="token-hint">替换后刷新页面，输入密码即可使用</span>
                </div>
            </div>
        `;

        document.getElementById('copyBtn').addEventListener('click', () => {
            const textarea = document.getElementById('configOutput');
            textarea.select();
            document.execCommand('copy');
            document.getElementById('copyBtn').textContent = '已复制 ✓';
        });
    };

    document.getElementById('tokenBtn').addEventListener('click', handleSave);
    document.getElementById('tokenInput').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleSave();
    });
}

// ---------- 密码验证界面 ----------
function showPasswordScreen() {
    const config = getConfig();
    const hasEncryptedToken = config && config.encryptedToken;

    const passwordInput = document.getElementById('passwordInput');
    const passwordError = document.getElementById('passwordError');
    const passwordScreen = document.getElementById('passwordScreen');
    const app = document.getElementById('app');

    passwordInput.addEventListener('input', async (e) => {
        const value = e.target.value;
        if (value.length === 8) {
            const inputHash = await sha256(value);
            if (inputHash === config.passwordHash) {
                // 密码正确，尝试解密 token
                if (hasEncryptedToken && !decryptedToken) {
                    try {
                        decryptedToken = await decryptToken(config.encryptedToken, value);
                    } catch (e) {
                        passwordError.textContent = 'Token 解密失败';
                        passwordError.classList.add('show');
                        passwordInput.value = '';
                        setTimeout(() => passwordError.classList.remove('show'), 2000);
                        return;
                    }
                }

                passwordScreen.classList.add('hidden');
                setTimeout(() => {
                    app.classList.add('visible');
                    renderNotesList();
                    if (notes.length > 0) {
                        selectNote(notes[0].id);
                    }
                }, 300);
            } else {
                passwordError.classList.add('show');
                passwordInput.value = '';
                setTimeout(() => {
                    passwordError.classList.remove('show');
                }, 2000);
            }
        }
    });

    passwordInput.focus();
}

// ---------- 信件数据 ----------
const STORAGE_KEY = 'birthday_letters_0923';

// 从 GitHub 加载信件（三级降级：GitHub → 本地文件 → 空数组）
async function loadNotes() {
    if (!decryptedToken) {
        // 没有 token，直接读本地
        return loadNotesLocal();
    }

    showSyncStatus('loading', '正在加载信件...');

    // 1. 先尝试从 GitHub 读取（加时间戳防缓存）
    try {
        const config = getConfig();
        const url = `https://api.github.com/repos/${config.owner}/${config.repo}/contents/data/letters.json?_t=${Date.now()}`;
        const resp = await fetch(url, { 
            headers: githubHeaders(),
            cache: 'no-store'
        });
        
        if (resp.status === 404) {
            console.log('[DEBUG] GitHub 上 letters.json 不存在 (404)');
            throw new Error('文件不存在');
        }
        if (!resp.ok) {
            throw new Error(`GitHub 读取失败 (${resp.status})`);
        }
        
        const data = await resp.json();
        const rawContent = atob(data.content);
        const content = decodeURIComponent(escape(rawContent));
        console.log('[DEBUG] GitHub 返回的内容:', content.substring(0, 200));
        
        const parsed = content.trim() ? JSON.parse(content) : [];
        notes = parsed;
        currentFileSha = data.sha;
        localStorage.setItem(STORAGE_KEY, JSON.stringify(notes));
        showSyncStatus('success', `从 GitHub 加载 ${notes.length} 封信 ✓`);
        setTimeout(hideSyncStatus, 2000);
        return;
    } catch (e) {
        console.log('[DEBUG] GitHub 读取失败:', e.message);
    }

    // 2. GitHub 失败，读本地
    await loadNotesLocal();
}

async function loadNotesLocal() {
    try {
        const resp = await fetch('data/letters.json');
        if (resp.ok) {
            const text = await resp.text();
            if (text.trim()) {
                notes = JSON.parse(text);
            } else {
                notes = [];
            }
            localStorage.setItem(STORAGE_KEY, JSON.stringify(notes));
            showSyncStatus('offline', '本地模式');
            setTimeout(hideSyncStatus, 2000);
            return;
        }
    } catch (e) {
        console.log('本地文件读取失败', e.message);
    }

    notes = [];
}

// 同步到 GitHub（通过 Issue → Actions 自动处理）
async function syncToGitHub(action, letter) {
    if (!decryptedToken) {
        showSyncStatus('error', '未设置 Token，无法同步');
        setTimeout(hideSyncStatus, 3000);
        return;
    }

    if (isSyncing) return;
    isSyncing = true;
    showSyncStatus('saving', '正在同步到 GitHub...');

    try {
        const body = JSON.stringify({ action, letter });
        const title = `[0923] ${action}-${Date.now()}`;

        await githubCreateIssue(title, body);
        showSyncStatus('success', '已同步 ✓ 对方刷新即可看到');
    } catch (e) {
        console.error('同步失败', e);
        showSyncStatus('error', '同步失败: ' + e.message);
    }

    isSyncing = false;
    setTimeout(hideSyncStatus, 3000);
}

// ---------- 同步状态 UI ----------
function showSyncStatus(type, message) {
    let bar = document.getElementById('syncBar');
    if (!bar) {
        bar = document.createElement('div');
        bar.id = 'syncBar';
        document.body.appendChild(bar);
    }
    bar.className = 'sync-bar sync-' + type;
    bar.textContent = message;
    bar.classList.add('show');
}

function hideSyncStatus() {
    const bar = document.getElementById('syncBar');
    if (bar) bar.classList.remove('show');
}

// ---------- 信件列表 ----------
const notesList = document.getElementById('notesList');
const letterContainer = document.getElementById('letterContainer');

function renderNotesList() {
    notesList.innerHTML = '';

    notes.forEach(note => {
        const item = document.createElement('div');
        item.className = 'note-item';
        if (note.id === currentNoteId) {
            item.classList.add('active');
        }
        item.innerHTML = `
            <div class="note-item-title">${note.title || '未命名'}</div>
        `;
        item.addEventListener('click', () => {
            selectNote(note.id);
            closeSidebar();
        });
        notesList.appendChild(item);
    });

    document.getElementById('currentYear').textContent = new Date().getFullYear();
}

function selectNote(noteId) {
    currentNoteId = noteId;
    const note = notes.find(n => n.id === noteId);
    if (!note) return;

    letterContainer.innerHTML = `
        <div class="letter-header">
            <div class="letter-title">${note.title || ''}</div>
        </div>
        <div class="letter-content">
            <div class="letter-text">${escapeHtml(note.content)}</div>
            <div class="letter-footer">♡ ${escapeHtml(note.signature || '永远爱你')} ♡</div>
        </div>
    `;

    renderNotesList();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ---------- 弹窗（写信/编辑） ----------
const modal = document.getElementById('modal');
const modalTitle = document.getElementById('modalTitle');
const noteTitle = document.getElementById('noteTitle');
const noteContent = document.getElementById('noteContent');
const noteSignature = document.getElementById('noteSignature');
const saveBtn = document.getElementById('saveBtn');
const cancelBtn = document.getElementById('cancelBtn');
const deleteBtn = document.getElementById('deleteBtn');
const addNoteBtn = document.getElementById('addNoteBtn');

addNoteBtn.addEventListener('click', () => {
    editingNoteId = null;
    modalTitle.textContent = '写一封新信';
    noteTitle.value = '';
    noteContent.value = '';
    noteSignature.value = '';
    deleteBtn.style.display = 'none';
    modal.classList.add('show');
});

cancelBtn.addEventListener('click', () => {
    modal.classList.remove('show');
});

saveBtn.addEventListener('click', () => {
    const title = noteTitle.value.trim();
    const content = noteContent.value.trim();
    const signature = noteSignature.value.trim();

    if (!content) {
        alert('请填写内容哦~');
        return;
    }

    if (editingNoteId) {
        const note = notes.find(n => n.id === editingNoteId);
        if (note) {
            note.title = title;
            note.content = content;
            note.signature = signature;
        }
        syncToGitHub('edit', { id: editingNoteId, title, content, signature });
    } else {
        const newNote = {
            id: Date.now(),
            title,
            content,
            signature
        };
        notes.push(newNote);
        currentNoteId = newNote.id;
        syncToGitHub('add', newNote);
    }

    localStorage.setItem(STORAGE_KEY, JSON.stringify(notes));
    renderNotesList();
    selectNote(currentNoteId);
    modal.classList.remove('show');
});

deleteBtn.addEventListener('click', () => {
    if (!editingNoteId) return;
    if (!confirm('确定要删除这封信吗？')) return;

    const deletedId = editingNoteId;
    notes = notes.filter(n => n.id !== deletedId);

    if (currentNoteId === deletedId) {
        currentNoteId = notes.length > 0 ? notes[0].id : null;
    }

    renderNotesList();
    if (currentNoteId) {
        selectNote(currentNoteId);
    } else {
        letterContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">♡</div>
                <div class="empty-state-text">还没有信哦，快来写一封吧~</div>
            </div>
        `;
    }

    modal.classList.remove('show');
    syncToGitHub('delete', { id: deletedId });
    localStorage.setItem(STORAGE_KEY, JSON.stringify(notes));
});

// 双击编辑
letterContainer.addEventListener('dblclick', () => {
    if (!currentNoteId) return;
    const note = notes.find(n => n.id === currentNoteId);
    if (!note) return;

    editingNoteId = currentNoteId;
    modalTitle.textContent = '编辑这封信';
    noteTitle.value = note.title || '';
    noteContent.value = note.content;
    noteSignature.value = note.signature || '';
    deleteBtn.style.display = 'block';
    modal.classList.add('show');
});

// ---------- 移动端侧边栏 ----------
const menuToggle = document.getElementById('menuToggle');
const sidebar = document.getElementById('sidebar');

menuToggle.addEventListener('click', () => {
    sidebar.classList.toggle('open');
});

function closeSidebar() {
    if (window.innerWidth <= 768) {
        sidebar.classList.remove('open');
    }
}

// 点击弹窗外关闭
modal.addEventListener('click', (e) => {
    if (e.target === modal) {
        modal.classList.remove('show');
    }
});

// ---------- 初始化 ----------
function initApp() {
    loadNotes().then(() => {
        showPasswordScreen();
    });
}

// 启动
(function boot() {
    const config = getConfig();
    if (!config) {
        alert('config.js 未加载');
        return;
    }

    if (config.encryptedToken) {
        // 已有加密 token，直接显示密码界面
        initApp();
    } else {
        // 没有 token，显示设置界面
        showTokenSetup();
    }
})();

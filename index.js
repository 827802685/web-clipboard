addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const authed = await isAuthenticated(request);
  if (!authed && path !== '/login' && !(path.startsWith('/s/') && request.method === 'GET') && path !== '/manifest.json') {
    return new Response(loginHTML, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
    });
  }

  if (path === '/') {
    return new Response(htmlTemplate, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
    });
  } else if (path === '/login') {
    if (request.method === 'GET') {
      return new Response(loginHTML, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    } else if (request.method === 'POST') {
      const bodyText = await request.text();
      let pwd = bodyText;
      try {
        const parsed = JSON.parse(bodyText);
        if (parsed && typeof parsed.password === 'string') pwd = parsed.password;
      } catch (_) {}
      const ok = await verifyPassword(pwd);
      if (!ok) {
        return new Response('密码错误', { status: 401 });
      }
      const token = await getPasswordToken();
      const cookie = `auth=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`;
      return new Response('登录成功', {
        headers: { 'Set-Cookie': cookie, 'Content-Type': 'text/plain;charset=UTF-8' },
      });
    } else {
      return new Response('方法不被允许', { status: 405 });
    }
  } else if (path === '/save' && request.method === 'POST') {
    // 保存剪贴板内容
    const content = await request.text();
    if (content) {
      await JTB.put("clipboard", content); // 使用 "clipboard" 作为固定的键名
      return new Response('好的');
    } else {
      return new Response('内容为空', { status: 400 });
    }
  } else if (path === '/read' && request.method === 'GET') {
    const content = await JTB.get("clipboard");
    if (content) {
      return new Response(content);
    } else {
      return new Response('剪贴板为空', { status: 404 });
    }
  } else if (path === '/items' && request.method === 'POST') {
    const body = await request.json();
    const id = generateUUID();
    const note = body.note || '';
    const tags = Array.isArray(body.tags) ? body.tags : (typeof body.tags === 'string' ? body.tags.split(',').map(t=>t.trim()).filter(Boolean) : []);
    const item = { id, content: body.content || '', note, tags, createdAt: Date.now(), updatedAt: Date.now() };
    await JTB.put('item:' + id, JSON.stringify(item));
    return new Response(JSON.stringify({ id }), { headers: { 'Content-Type': 'application/json' } });
  } else if (path === '/items' && request.method === 'GET') {
    const listed = await JTB.list({ prefix: 'item:' });
    const keys = listed.keys || [];
    const items = await Promise.all(keys.map(k => JTB.get(k.name).then(v => { try { const o = JSON.parse(v); return { id: o.id, note: o.note, tags: o.tags, createdAt: o.createdAt, updatedAt: o.updatedAt }; } catch (e) { return null; } } )));
    return new Response(JSON.stringify(items.filter(Boolean)), { headers: { 'Content-Type': 'application/json' } });
  } else if (path.startsWith('/items/')) {
    const id = path.substring('/items/'.length);
    const key = 'item:' + id;
    if (request.method === 'GET') {
      const v = await JTB.get(key);
      if (!v) return new Response('未找到', { status: 404 });
      return new Response(v, { headers: { 'Content-Type': 'application/json' } });
    } else if (request.method === 'PUT') {
      const body = await request.json();
      const v = await JTB.get(key);
      if (!v) return new Response('未找到', { status: 404 });
      const o = JSON.parse(v);
      if (typeof body.content === 'string') o.content = body.content;
      if (typeof body.note === 'string') o.note = body.note;
      if (Array.isArray(body.tags)) o.tags = body.tags; else if (typeof body.tags === 'string') o.tags = body.tags.split(',').map(t=>t.trim()).filter(Boolean);
      o.updatedAt = Date.now();
      await JTB.put(key, JSON.stringify(o));
      return new Response('已更新');
    } else if (request.method === 'DELETE') {
      await JTB.delete(key);
      return new Response('已删除');
    } else {
      return new Response('方法不被允许', { status: 405 });
    }
  } else if (path === '/manifest.json') {
    return new Response(manifestContent, {
      headers: { 'Content-Type': 'application/json' },
    });
  } else if (path === '/share' && request.method === 'POST') {
    const body = await request.json();
    let content;
    if (body && body.id) {
      const v = await JTB.get('item:' + body.id);
      if (!v) return new Response('条目不存在', { status: 404 });
      try { content = JSON.parse(v).content; } catch (e) { content = null; }
    } else {
      content = await JTB.get('clipboard');
    }
    if (!content) {
      return new Response('剪贴板为空', { status: 400 });
    }
    const maxViews = body.maxViews;
    const validMinutes = body.validMinutes;
    const shareId = generateUUID();
    const expireAt = validMinutes ? Date.now() + validMinutes * 60 * 1000 : null;
    await JTB.put(shareId, JSON.stringify({ content, maxViews, expireAt, views: 0 }), { expirationTtl: validMinutes ? validMinutes * 60 : undefined });
    const shareUrl = url.origin + '/s/' + shareId;
    return new Response(JSON.stringify({ shareUrl }));
  } else if (path.startsWith('/s/') && request.method === 'GET') {
    // 查看分享的剪贴板内容
    const shareId = path.substring(3);
    const data = await JTB.get(shareId);

    if (!data) {
      return new Response('分享链接无效或已过期', { status: 404 });
    }

    const { content, maxViews, expireAt, views } = JSON.parse(data);

    if (expireAt && Date.now() > expireAt) {
      await JTB.delete(shareId); // 过期则删除
      return new Response('分享链接已过期', { status: 403 });
    }

    if (maxViews && views >= maxViews) {
      await JTB.delete(shareId); // 达到最大查看次数则删除
      return new Response('分享链接已达到最大查看次数', { status: 403 });
    }

    // 更新查看次数
    await JTB.put(shareId, JSON.stringify({ content, maxViews, expireAt, views: views + 1 }));

    return new Response(renderSharePage(content, { shareId, maxViews, expireAt, views: views + 1 }), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  // 其他路径返回 404
  return new Response('未找到', { status: 404 });
}

// 生成 UUID
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

let __PASSWORD_TOKEN__;
async function getPasswordToken() {
  if (typeof PASSWORD === 'undefined' || !PASSWORD) return null;
  if (!__PASSWORD_TOKEN__) {
    __PASSWORD_TOKEN__ = await sha256Hex(PASSWORD);
  }
  return __PASSWORD_TOKEN__;
}

async function isAuthenticated(request) {
  const token = await getPasswordToken();
  if (!token) return true;
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;)\s*auth=([^;]+)/);
  return !!(m && m[1] === token);
}

async function verifyPassword(inputPwd) {
  if (typeof PASSWORD === 'undefined' || !PASSWORD) return true;
  return inputPwd === PASSWORD;
}

const loginHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>登录</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body{display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;background:#f5f7fa}
    .box{background:#fff;padding:24px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1);width:320px}
    input{width:100%;padding:12px;margin:8px 0;border:1px solid #ccc;border-radius:8px}
    button{width:100%;padding:12px;background:#2980b9;color:#fff;border:none;border-radius:8px;cursor:pointer}
    button:hover{background:#3498db}
    .msg{color:#c0392b;margin-top:8px}
  </style>
</head>
<body>
  <div class="box">
    <h2>请输入密码</h2>
    <input id="pwd" type="password" placeholder="密码">
    <button id="loginBtn">登录</button>
    <div id="msg" class="msg"></div>
  </div>
  <script>
    document.getElementById('loginBtn').addEventListener('click', async () => {
      const password = document.getElementById('pwd').value;
      const res = await fetch('/login', { method: 'POST', body: JSON.stringify({ password }), headers: { 'Content-Type': 'application/json' } });
      if (res.ok) {
        location.href = '/';
      } else {
        document.getElementById('msg').textContent = '密码错误';
      }
    });
  </script>
</body>
</html>
`;

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c;
  });
}

function renderSharePage(content, meta) {
  const isURL = /^https?:\/\/\S+$/i.test((content || '').trim());
  const viewsLeft = meta && typeof meta.maxViews === 'number' ? Math.max(0, meta.maxViews - (meta.views || 0)) : null;
  const expireText = meta && meta.expireAt ? new Date(meta.expireAt).toLocaleString('zh-CN') : '永久';
  const displayHTML = isURL
    ? `<a class="link" href="${escapeHTML(content)}" target="_blank">${escapeHTML(content)}</a>`
    : `<pre class="content">${escapeHTML(content)}</pre>`;
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>分享内容</title>
  <style>
    body{margin:0;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.35) url('https://t.alcy.cc/ysz') center/cover no-repeat fixed;}
    .card{background:rgba(255,255,255,0.92);backdrop-filter:saturate(180%) blur(6px);border-radius:16px;box-shadow:0 10px 24px rgba(0,0,0,.15);max-width:860px;width:92%;padding:22px;}
    h1{margin:0 0 12px 0;font-size:22px;color:#2c3e50}
    .meta{display:flex;gap:14px;color:#666;font-size:13px;margin-bottom:12px;flex-wrap:wrap}
    .content{white-space:pre-wrap;word-break:break-word;background:#f8fafc;border:1px solid #e6ecf2;border-radius:10px;padding:14px;font-size:15px;color:#2d3436}
    .actions{display:flex;gap:10px;margin-top:12px}
    .btn{flex:0 0 auto;padding:10px 14px;border:none;border-radius:10px;background:linear-gradient(135deg,#3498db 0%,#2980b9 100%);color:#fff;cursor:pointer}
    .btn:hover{background:linear-gradient(135deg,#2980b9 0%,#3498db 100%)}
    .link{display:inline-block;word-break:break-all;color:#2980b9}
  </style>
</head>
<body>
  <div class="card">
    <h1>分享内容</h1>
    <div class="meta"><div>链接编号: ${meta && meta.shareId ? escapeHTML(meta.shareId) : '-'}</div><div>有效期: ${escapeHTML(expireText)}</div><div>剩余查看: ${viewsLeft===null?'无限':viewsLeft}</div></div>
    ${displayHTML}
    <div class="actions"><button class="btn" id="copyBtn">复制内容</button><button class="btn" id="openBtn" ${isURL?'':'style="display:none"'}>打开链接</button></div>
  </div>
  <script>
    const text = ${JSON.stringify(content)};
    document.getElementById('copyBtn').addEventListener('click',()=>{
      if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(()=>alert('已复制内容'))}else{const t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);alert('已复制内容');}
    });
    const openBtn=document.getElementById('openBtn'); if(openBtn){openBtn.addEventListener('click',()=>{try{window.open(text,'_blank');}catch(e){}})}
  </script>
</body>
</html>`;
}

const manifestContent = `{
  "name": "在线剪贴板",
  "short_name": "剪贴板",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#f4f4f4",
  "theme_color": "#007bff",
  "icons": [
    {
      "src": "https://img.xwyue.com/i/2025/01/06/677b63d2572db.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "https://img.xwyue.com/i/2025/01/06/677b63d2572db.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ]
}`;

const htmlTemplate = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <title>在线剪贴板</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="https://img.xwyue.com/i/2025/01/06/677b63d2572db.png">

  <!-- iOS 添加到主屏幕的相关设置 -->
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="在线剪贴板">
  <link rel="apple-touch-icon" href="https://img.xwyue.com/i/2025/01/06/677b63d2572db.png">
  <link rel="manifest" href="/manifest.json">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css">

  <style>
    body {
      font-family: 'Helvetica Neue', 'Arial', 'PingFang SC', 'Microsoft YaHei', sans-serif;
      margin: 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100vh;
      background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
      transition: background-color 0.5s ease;
    }
    body.dark-mode {
      background: linear-gradient(135deg, #333 0%, #222 100%);
    }
    h1 {
      color: #2980b9;
      margin-bottom: 20px;
      font-size: 2.5em;
      font-weight: 600;
      opacity: 0;
      animation: fadeIn 1s ease-in-out forwards;
    }
    .dark-mode h1 {
      color: #74a7d2;
    }
    .container {
      background-color: rgba(255, 255, 255, 0.85);
      border-radius: 15px;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
      padding: 28px 32px;
      width: 92%;
      max-width: 1100px;
      transition: background-color 0.5s ease;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='4' height='4' viewBox='0 0 4 4'%3E%3Cpath fill='%239C92AC' fill-opacity='0.1' d='M1 3h1v1H1V3zm2-2h1v1H3V1z'%3E%3C/path%3E%3C/svg%3E");
    }
    .dark-mode .container {
      background-color: rgba(51, 51, 51, 0.85);
      box-shadow: 0 4px 10px rgba(255, 255, 255, 0.1);
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='4' height='4' viewBox='0 0 4 4'%3E%3Cpath fill='%23CCCCCC' fill-opacity='0.1' d='M1 3h1v1H1V3zm2-2h1v1H3V1z'%3E%3C/path%3E%3C/svg%3E");
    }
    textarea {
      width: calc(100% - 30px);
      height: 250px;
      margin-bottom: 20px;
      padding: 15px;
      border: none;
      border-radius: 10px;
      font-size: 18px;
      resize: vertical;
      color: #333;
      box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1);
      background-color: #fff;
      overflow: auto;
      transition: box-shadow 0.3s ease; /* 添加过渡效果 */
    }
    .dark-mode textarea {
      color: #eee;
      box-shadow: inset 0 2px 4px rgba(255, 255, 255, 0.1);
      background-color: #444;
    }
    textarea:focus {
      outline: none;
      box-shadow: 0 0 5px 2px #2980b9; /* 聚焦时添加更明显的阴影 */
    }
    .dark-mode textarea:focus {
      box-shadow: 0 0 5px 2px #74a7d2; /* 暗黑模式聚焦时添加更明显的阴影 */
    }
    button {
      background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
      color: white;
      border: 1px solid #2980b9; /* 添加细边框 */
      padding: 15px 30px;
      margin: 10px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 18px;
      transition: all 0.2s ease-in-out; /* 更快的过渡 */
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); /* 移除悬停时的阴影 */
    }
    button:hover {
      background: linear-gradient(135deg, #2980b9 0%, #3498db 100%);
      transform: scale(1.05); /* 放大效果 */
    }
    button:active {
      transform: scale(0.95); /* 点击时缩小 */
      box-shadow: none;
    }
    button i {
      margin-right: 10px;
      font-size: 20px; /* 增大图标 */
    }
    .layout { display: grid; grid-template-columns: 320px 1fr; gap: 18px; align-items: start; }
    .sidebar { display: flex; flex-direction: column; gap: 12px; }
    .sidebar .filters { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .items-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 10px; max-height: 60vh; overflow: auto; }
    .item-card { background: rgba(255,255,255,0.9); border: 1px solid #e6ecf2; border-radius: 10px; padding: 10px 12px; cursor: pointer; display: grid; grid-template-columns: 1fr auto; align-items: center; }
    .item-card:hover { border-color: #d0d6dc; box-shadow: 0 2px 6px rgba(0,0,0,0.06); }
    .item-title { font-size: 14px; color: #2c3e50; }
    .item-tags { font-size: 12px; color: #888; }
    .content { display: flex; flex-direction: column; }
    .toolbar { display: flex; flex-direction: column; gap: 12px; width: 100%; }
    .controls { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; align-items: center; }
    .actions { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; align-items: stretch; }
    .actions .tile {
      height: 90px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      border-radius: 12px;
      font-size: 16px;
      width: 100%;
      margin: 0;
    }
    .actions .tile i {
      margin: 0 0 8px 0;
      font-size: 22px;
    }

    /* 媒体查询：针对小屏幕设备 (例如手机) */
    @media (max-width: 1024px) { .layout { grid-template-columns: 260px 1fr; } }
    @media (max-width: 768px) {
      .container { padding: 20px; }
      .layout { grid-template-columns: 1fr; }
      textarea { height: 200px; font-size: 16px; }
      button { padding: 12px 18px; font-size: 15px; }
      h1 { font-size: 2em; }
      .sidebar { display: none; }
      .controls { grid-template-columns: 1fr; }
      .actions { grid-template-columns: 1fr; }
    }

    /* 自定义滚动条 */
    ::-webkit-scrollbar {
      width: 10px;
    }
    ::-webkit-scrollbar-track {
      background: #f1f1f1;
      border-radius: 10px;
    }
    ::-webkit-scrollbar-thumb {
      background: #888;
      border-radius: 10px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: #555;
    }
    .dark-mode ::-webkit-scrollbar-track {
      background: #333;
    }
    .dark-mode ::-webkit-scrollbar-thumb {
      background: #666;
    }
    .dark-mode ::-webkit-scrollbar-thumb:hover {
      background: #999;
    }

    /* 加载动画 */
    .loading {
      position: relative;
    }
    .loading::after {
      content: '';
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      width: 30px;
      height: 30px;
      border-radius: 50%;
      border: 4px solid #fff;
      border-color: #fff transparent #fff transparent;
      animation: loading 1.2s linear infinite;
    }
    @keyframes loading {
      0% {
        transform: translate(-50%, -50%) rotate(0deg);
      }
      100% {
        transform: translate(-50%, -50%) rotate(360deg);
      }
    }
    .dark-mode .loading::after {
      border-color: #eee transparent #eee transparent;
    }

    /* 标题动画 */
    @keyframes fadeIn {
      0% {
        opacity: 0;
        transform: translateY(-20px);
      }
      100% {
        opacity: 1;
        transform: translateY(0);
      }
    }
    /*分享*/
    .modal {
      display: none;
      position: fixed;
      z-index: 1;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow: auto;
      background-color: rgba(0, 0, 0, 0.4);
    }
    .modal-content {
      background-color: #fff;
      margin: 8% auto;
      padding: 0;
      width: 90%;
      max-width: 520px;
      border-radius: 14px;
      box-shadow: 0 10px 24px rgba(0,0,0,0.15);
      overflow: hidden;
      border: 1px solid rgba(0,0,0,0.08);
    }
    .dark-mode .modal-content { background-color: #3b3b3b; color: #eee; border: 1px solid #555; }
    .modal-header { display:flex; align-items:center; justify-content:space-between; padding:14px 18px; background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color:#fff; }
    .modal-header h2 { margin:0; font-size:18px; }
    .close { color:#fff; font-size:24px; font-weight:bold; cursor:pointer; }
    .modal-body { padding:16px 18px 18px; }
    .form-field { margin-bottom:12px; }
    .form-field label { display:block; font-size:14px; color:#666; margin-bottom:6px; }
    .dark-mode .form-field label { color:#ccc; }
    .form-field input { width:100%; padding:10px 12px; border:1px solid #ccc; border-radius:8px; font-size:14px; }
    .dark-mode .form-field input { background:#333; color:#fff; border:1px solid #666; }
    .share-actions { display:flex; gap:10px; }
    .share-actions button { flex:1; padding:12px; border:none; border-radius:10px; background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color:#fff; cursor:pointer; }
    .share-actions button:hover { background: linear-gradient(135deg, #2980b9 0%, #3498db 100%); }
    .link-box { display:none; grid-template-columns: 1fr auto; gap:10px; align-items:center; margin-top:10px; }
    .link-input { width:100%; padding:10px 12px; border:1px solid #ccc; border-radius:8px; font-size:14px; }
    .dark-mode .link-input { background:#333; color:#fff; border:1px solid #666; }
    .copy-btn { padding:10px 16px; border:none; border-radius:8px; background:#2ecc71; color:#fff; cursor:pointer; }
    .copy-btn:hover { background:#27ae60; }
    .helper { margin-top:8px; font-size:12px; color:#888; }
    .dark-mode .helper { color:#aaa; }
    #shareLink { margin-top: 6px; word-break: break-all; }
  </style>
</head>
<body>
  <div class="container">
    <h1>在线剪贴板</h1>
    <div class="layout">
      <aside class="sidebar">
        <div class="filters">
          <input id="searchInput" placeholder="搜索备注或内容">
          <input id="tagFilterInput" placeholder="标签筛选（逗号分隔）">
        </div>
        <ul id="itemsList" class="items-list"></ul>
      </aside>
      <main class="content">
        <div class="toolbar">
          <div class="controls">
            <input id="noteInput" placeholder="备注（可选）">
            <input id="tagsInput" placeholder="标签（逗号分隔，可选）">
            <select id="itemsSelect"><option value="">选择条目...</option></select>
          </div>
          <div class="actions">
            <button id="saveBtn" class="tile"><i class="fas fa-cloud-upload-alt"></i>保存条目</button>
            <button id="readBtn" class="tile"><i class="fas fa-cloud-download-alt"></i>读取选中</button>
            <button id="deleteBtn" class="tile"><i class="fas fa-trash-alt"></i>删除选中</button>
            <button id="copyBtn" class="tile"><i class="fas fa-copy"></i>复制到本地</button>
            <button id="shareBtn" class="tile"><i class="fas fa-share-alt"></i>分享选中</button>
            <button id="refreshBtn" class="tile"><i class="fas fa-sync"></i>刷新列表</button>
          </div>
        </div>
        <textarea id="clipboard" placeholder="在此处粘贴内容..."></textarea>
      </main>
    </div>
  </div>
  <div id="shareModal" class="modal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>分享设置</h2>
        <span class="close">&times;</span>
      </div>
      <div class="modal-body">
        <div class="form-field">
          <label for="maxViews">最大查看次数</label>
          <input type="number" id="maxViews" placeholder="留空为无限">
        </div>
        <div class="form-field">
          <label for="validMinutes">有效时间 (分钟)</label>
          <input type="number" id="validMinutes" placeholder="留空为永久">
        </div>
        <div class="share-actions">
          <button id="generateShareLink">生成链接</button>
        </div>
        <div class="link-box" id="linkBox">
          <input id="shareLinkInput" class="link-input" placeholder="分享链接" readonly>
          <button id="copyShareLinkBtn" class="copy-btn">复制</button>
        </div>
        <div class="helper">提示：分享链接可设置有效期和最大查看次数</div>
        <div id="shareLink"></div>
      </div>
    </div>
  </div>
  <script>
    const clipboardTextarea = document.getElementById('clipboard');
    const noteInput = document.getElementById('noteInput');
    const tagsInput = document.getElementById('tagsInput');
    const itemsSelect = document.getElementById('itemsSelect');
    const itemsList = document.getElementById('itemsList');
    const searchInput = document.getElementById('searchInput');
    const tagFilterInput = document.getElementById('tagFilterInput');
    const saveBtn = document.getElementById('saveBtn');
    const readBtn = document.getElementById('readBtn');
    const deleteBtn = document.getElementById('deleteBtn');
    const refreshBtn = document.getElementById('refreshBtn');
    const copyBtn = document.getElementById('copyBtn');
    const shareBtn = document.getElementById('shareBtn');
    const shareModal = document.getElementById('shareModal');
    const closeModalBtn = document.querySelector('.close');
    const generateShareLinkBtn = document.getElementById('generateShareLink');
    const shareLinkDiv = document.getElementById('shareLink');
    const shareLinkInput = document.getElementById('shareLinkInput');
    const copyShareLinkBtn = document.getElementById('copyShareLinkBtn');
    const linkBox = document.getElementById('linkBox');

    // 自动检测暗黑模式
    function checkDarkMode() {
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.body.classList.add('dark-mode');
      } else {
        document.body.classList.remove('dark-mode');
      }
    }
    checkDarkMode();
    window.matchMedia('(prefers-color-scheme: dark)').addListener(checkDarkMode);

    let itemsCache = [];
    function renderItems(list){
      if (!itemsList) return;
      itemsList.innerHTML = list.map(function(i){
        var title = i.note || ('条目 ' + (i.id || '').slice(0,8));
        var tags = (i.tags || []).join(',');
        return '<li class="item-card" data-id="' + i.id + '"><div class="item-title">' + title + '</div><div class="item-tags">' + (tags || '') + '</div></li>';
      }).join('');
    }
    function filterAndRender(){
      var q = (searchInput && searchInput.value || '').trim().toLowerCase();
      var tagStr = (tagFilterInput && tagFilterInput.value || '').trim().toLowerCase();
      var tagSet = tagStr ? tagStr.split(',').map(function(t){return t.trim();}).filter(Boolean) : [];
      var list = itemsCache.filter(function(i){
        var matchesQ = !q || (String(i.note||'').toLowerCase().includes(q) || String(i.id||'').toLowerCase().includes(q));
        var matchesTag = tagSet.length===0 || (Array.isArray(i.tags) && tagSet.every(function(t){ return i.tags.map(function(x){return String(x).toLowerCase();}).includes(t); }));
        return matchesQ && matchesTag;
      });
      renderItems(list);
    }
    async function refreshItems() {
      const res = await fetch('/items');
      if (res.ok) {
        itemsCache = await res.json();
        itemsSelect.innerHTML = '<option value="">选择条目...</option>' + itemsCache.map(function(i){ return '<option value="' + i.id + '">' + (i.note || ('条目 ' + i.id.slice(0,8))) + '</option>'; }).join('');
        filterAndRender();
      }
    }
    refreshItems();

    if (itemsList) {
      itemsList.addEventListener('click', async function(e){
        var li = e.target.closest('.item-card');
        if (!li) return;
        var id = li.getAttribute('data-id');
        if (id) { itemsSelect.value = id; }
        readBtn.click();
      });
    }
    if (searchInput) { searchInput.addEventListener('input', filterAndRender); }
    if (tagFilterInput) { tagFilterInput.addEventListener('input', filterAndRender); }

    saveBtn.addEventListener('click', async () => {
      const content = clipboardTextarea.value;
      const note = noteInput.value;
      const tags = tagsInput.value.split(',').map(function(t){return t.trim();}).filter(Boolean);
      if (content) {
        saveBtn.classList.add('loading');
        const response = await fetch('/items', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content, note, tags }) });
        saveBtn.classList.remove('loading');
        if (response.ok) {
          alert('已保存条目！');
          noteInput.value = '';
          tagsInput.value = '';
          await refreshItems();
        } else {
          alert('保存失败！');
        }
      } else {
        alert('内容为空！');
      }
    });

    readBtn.addEventListener('click', async () => {
      const id = itemsSelect.value;
      readBtn.classList.add('loading');
      if (id) {
        const response = await fetch('/items/' + id);
        readBtn.classList.remove('loading');
        if (response.ok) {
          const item = await response.json();
          clipboardTextarea.value = item.content || '';
          noteInput.value = item.note || '';
          tagsInput.value = (item.tags || []).join(',');
        } else {
          alert('读取失败或条目不存在！');
        }
      } else {
        const response = await fetch('/read');
        readBtn.classList.remove('loading');
        if (response.ok) {
          const content = await response.text();
          clipboardTextarea.value = content;
        } else {
          alert('读取失败或剪贴板为空！');
        }
      }
    });

    copyBtn.addEventListener('click', () => {
      clipboardTextarea.select();
      document.execCommand('copy');
      alert('已复制到本地剪贴板！');
    });

    deleteBtn.addEventListener('click', async () => {
      const id = itemsSelect.value;
      if (!id) { alert('请先选择条目'); return; }
      if (!confirm('确认删除选中条目？')) return;
      deleteBtn.classList.add('loading');
      const res = await fetch('/items/' + id, { method: 'DELETE' });
      deleteBtn.classList.remove('loading');
      if (res.ok) { alert('已删除'); await refreshItems(); } else { alert('删除失败'); }
    });

    refreshBtn.addEventListener('click', refreshItems);

    if (copyShareLinkBtn) {
      copyShareLinkBtn.addEventListener('click', () => {
        const v = shareLinkInput && shareLinkInput.value;
        if (!v) { alert('请先生成链接'); return; }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(v).then(() => alert('已复制链接'));
        } else {
          const tmp = document.createElement('textarea');
          tmp.value = v; document.body.appendChild(tmp); tmp.select(); document.execCommand('copy'); document.body.removeChild(tmp);
          alert('已复制链接');
        }
      });
    }

    shareBtn.addEventListener('click', () => {
      shareModal.style.display = 'block';
    });

    closeModalBtn.addEventListener('click', () => {
      shareModal.style.display = 'none';
    });

    generateShareLinkBtn.addEventListener('click', async () => {
      const maxViews = document.getElementById('maxViews').value;
      const validMinutes = document.getElementById('validMinutes').value;
      const id = itemsSelect.value || null;

      const response = await fetch('/share', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          id: id,
          maxViews: maxViews ? parseInt(maxViews) : null,
          validMinutes: validMinutes ? parseInt(validMinutes) : null
        })
      });

      if (response.ok) {
        const data = await response.json();
        const shareUrl = data.shareUrl;
        if (shareLinkInput) {
          shareLinkInput.value = shareUrl;
          if (linkBox) linkBox.style.display = 'grid';
        }
        shareLinkDiv.innerHTML = '';
      } else {
        alert('生成分享链接失败！');
      }
    });

    window.onclick = function(event) {
      if (event.target == shareModal) {
        shareModal.style.display = "none";
      }
    }
  </script>
</body>
</html>
`;

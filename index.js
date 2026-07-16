export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  }
};

// Tolerant env accessor: some bindings were created with trailing spaces in
// their names (e.g. "GITHUB_CLIENT_SECRET "). This helper transparently falls
// back to the trailing-space variant so the code always reads the right value.
function envVal(env, name) {
  if (env[name] != null) return env[name];
  if (env[name + ' '] != null) return env[name + ' '];
  return undefined;
}

function getOAuthConfig(provider, env) {
  const configs = {
    github: {
      authUrl: 'https://github.com/login/oauth/authorize',
      tokenUrl: 'https://github.com/login/oauth/access_token',
      apiUrl: 'https://api.github.com/user',
      scope: 'read:user user:email',
      clientId: envVal(env, 'GITHUB_CLIENT_ID'),
      clientSecret: envVal(env, 'GITHUB_CLIENT_SECRET'),
      adminId: envVal(env, 'GITHUB_ADMIN_ID'),
    },
    google: {
      authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      apiUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
      scope: 'openid email profile',
      clientId: envVal(env, 'GOOGLE_CLIENT_ID'),
      clientSecret: envVal(env, 'GOOGLE_CLIENT_SECRET'),
      adminId: envVal(env, 'GOOGLE_ADMIN_ID'),
    },
    wechat: {
      authUrl: 'https://open.weixin.qq.com/connect/qrconnect',
      tokenUrl: 'https://api.weixin.qq.com/sns/oauth2/access_token',
      apiUrl: 'https://api.weixin.qq.com/sns/userinfo',
      scope: 'snsapi_login',
      clientId: envVal(env, 'WECHAT_APP_ID'),
      clientSecret: envVal(env, 'WECHAT_APP_SECRET'),
      adminId: envVal(env, 'WECHAT_ADMIN_ID'),
    },
    qq: {
      authUrl: 'https://graph.qq.com/oauth2.0/authorize',
      tokenUrl: 'https://graph.qq.com/oauth2.0/token',
      apiUrl: 'https://graph.qq.com/user/get_user_info',
      scope: 'get_user_info',
      clientId: envVal(env, 'QQ_APP_ID'),
      clientSecret: envVal(env, 'QQ_APP_SECRET'),
      adminId: envVal(env, 'QQ_ADMIN_ID'),
    },
  };
  return configs[provider];
}

function generateState() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function storeState(env, state, provider) {
  const now = Date.now();
  await env.DB.prepare('DELETE FROM oauth_state WHERE created_at < ?').bind(now - 600000).run();
  await env.DB.prepare('INSERT INTO oauth_state (state, provider, created_at) VALUES (?, ?, ?)').bind(state, provider, now).run();
}

async function verifyAndConsumeState(env, state) {
  const row = await env.DB.prepare('SELECT provider FROM oauth_state WHERE state = ?').bind(state).first();
  if (!row) return null;
  await env.DB.prepare('DELETE FROM oauth_state WHERE state = ?').bind(state).run();
  return { provider: row.provider };
}

async function exchangeCodeForToken(provider, code, redirectUri, env) {
  const config = getOAuthConfig(provider, env);
  if (!config) return null;

  const clientId = config.clientId;
  const clientSecret = config.clientSecret;
  if (!clientId || !clientSecret) return null;

  let tokenRes;
  if (provider === 'github') {
    tokenRes = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code: code,
        redirect_uri: redirectUri,
      }),
    });
  } else if (provider === 'google') {
    tokenRes = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code: code,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }).toString(),
    });
  } else if (provider === 'wechat') {
    tokenRes = await fetch(`${config.tokenUrl}?appid=${clientId}&secret=${clientSecret}&code=${code}&grant_type=authorization_code`);
  } else if (provider === 'qq') {
    tokenRes = await fetch(`${config.tokenUrl}?grant_type=authorization_code&client_id=${clientId}&client_secret=${clientSecret}&code=${code}&redirect_uri=${encodeURIComponent(redirectUri)}`);
  }

  if (!tokenRes || !tokenRes.ok) return null;
  return await tokenRes.json();
}

async function getOAuthUserInfo(provider, tokenData, env) {
  const config = getOAuthConfig(provider, env);
  if (!config) return null;

  let userInfo;
  if (provider === 'github') {
    const res = await fetch(config.apiUrl, {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` },
    });
    if (!res.ok) return null;
    userInfo = await res.json();
    return { id: String(userInfo.id), name: userInfo.login, email: userInfo.email };
  } else if (provider === 'google') {
    const res = await fetch(config.apiUrl, {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` },
    });
    if (!res.ok) return null;
    userInfo = await res.json();
    return { id: userInfo.id, name: userInfo.name, email: userInfo.email };
  } else if (provider === 'wechat') {
    const res = await fetch(`${config.apiUrl}?access_token=${tokenData.access_token}&openid=${tokenData.openid}`);
    if (!res.ok) return null;
    userInfo = await res.json();
    return { id: tokenData.openid, name: userInfo.nickname, email: null };
  } else if (provider === 'qq') {
    const openidRes = await fetch(`https://graph.qq.com/oauth2.0/me?access_token=${tokenData.access_token}`);
    if (!openidRes.ok) return null;
    const openidText = await openidRes.text();
    const openidMatch = openidText.match(/"openid":"([^"]+)"/);
    if (!openidMatch) return null;
    const openid = openidMatch[1];
    const res = await fetch(`${config.apiUrl}?access_token=${tokenData.access_token}&oauth_consumer_key=${config.clientId}&openid=${openid}`);
    if (!res.ok) return null;
    userInfo = await res.json();
    return { id: openid, name: userInfo.nickname, email: null };
  }
  return null;
}

function isOAuthAdmin(provider, userId, env) {
  const config = getOAuthConfig(provider, env);
  if (!config) return false;
  const adminId = config.adminId;
  return adminId && String(userId) === String(adminId);
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const authed = await isAuthenticated(request, env);
  if (!authed && path !== '/login' && !path.startsWith('/oauth/') && !(path.startsWith('/s/') && request.method === 'GET') && path !== '/manifest.json' && path !== '/debug-env') {
    return new Response(loginHTML, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
    });
  }

  if (path === '/debug-env') {
    const envStatus = {
      github: {
        clientId: envVal(env, 'GITHUB_CLIENT_ID') ? '已配置' : '未配置',
        clientSecret: envVal(env, 'GITHUB_CLIENT_SECRET') ? '已配置' : '未配置',
        adminId: envVal(env, 'GITHUB_ADMIN_ID') ? '已配置' : '未配置',
      },
      google: {
        clientId: envVal(env, 'GOOGLE_CLIENT_ID') ? '已配置' : '未配置',
        clientSecret: envVal(env, 'GOOGLE_CLIENT_SECRET') ? '已配置' : '未配置',
        adminId: envVal(env, 'GOOGLE_ADMIN_ID') ? '已配置' : '未配置',
      },
      wechat: {
        appId: envVal(env, 'WECHAT_APP_ID') ? '已配置' : '未配置',
        appSecret: envVal(env, 'WECHAT_APP_SECRET') ? '已配置' : '未配置',
        adminId: envVal(env, 'WECHAT_ADMIN_ID') ? '已配置' : '未配置',
      },
      qq: {
        appId: envVal(env, 'QQ_APP_ID') ? '已配置' : '未配置',
        appSecret: envVal(env, 'QQ_APP_SECRET') ? '已配置' : '未配置',
        adminId: envVal(env, 'QQ_ADMIN_ID') ? '已配置' : '未配置',
      },
      adminEmail: envVal(env, 'ADMIN_EMAIL') ? '已配置' : '未配置',
      adminPassword: envVal(env, 'ADMIN_PASSWORD') ? '已配置' : '未配置',
      d1: env.DB ? '已配置' : '未配置',
    };
    return new Response(JSON.stringify(envStatus, null, 2), {
      headers: { 'Content-Type': 'application/json;charset=UTF-8' },
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
      let email = '', pwd = '';
      try {
        const parsed = JSON.parse(bodyText);
        if (parsed) { email = parsed.email || ''; pwd = parsed.password || ''; }
      } catch (_) { pwd = bodyText; }
      const ok = await verifyCredentials(email, pwd, env);
      if (!ok) {
        return new Response('邮箱或密码错误', { status: 401 });
      }
      const token = await getAuthToken(env);
      const cookie = `auth=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`;
      return new Response('登录成功', {
        headers: { 'Set-Cookie': cookie, 'Content-Type': 'text/plain;charset=UTF-8' },
      });
    } else {
      return new Response('方法不被允许', { status: 405 });
    }
  } else if (path.startsWith('/oauth/')) {
    const parts = path.split('/');
    const provider = parts[2];
    const action = parts[3];

    const config = getOAuthConfig(provider, env);
    if (!config) {
      return new Response('不支持的登录方式', { status: 400 });
    }

    const clientId = config.clientId;
    const clientSecret = config.clientSecret;

    if (!clientId || !clientSecret) {
      return new Response(`${provider} 登录未配置`, { status: 400 });
    }

    if (!action) {
      const state = generateState();
      await storeState(env, state, provider);
      const redirectUri = `${url.origin}/oauth/${provider}/callback`;
      let authUrl;
      if (provider === 'github') {
        authUrl = `${config.authUrl}?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(config.scope)}&state=${state}`;
      } else if (provider === 'google') {
        authUrl = `${config.authUrl}?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(config.scope)}&state=${state}`;
      } else if (provider === 'wechat') {
        authUrl = `${config.authUrl}?appid=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${config.scope}&state=${state}#wechat_redirect`;
      } else if (provider === 'qq') {
        authUrl = `${config.authUrl}?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${config.scope}&state=${state}`;
      }
      return Response.redirect(authUrl, 302);
    } else if (action === 'callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code || !state) {
        return new Response('无效的回调请求', { status: 400 });
      }

      const stateData = await verifyAndConsumeState(env, state);
      if (!stateData || stateData.provider !== provider) {
        return new Response('无效的 state 参数', { status: 400 });
      }

      const redirectUri = `${url.origin}/oauth/${provider}/callback`;
      const tokenData = await exchangeCodeForToken(provider, code, redirectUri, env);
      if (!tokenData || tokenData.error) {
        return new Response(`获取令牌失败: ${tokenData?.error_description || tokenData?.error || '未知错误'}`, { status: 400 });
      }

      const userInfo = await getOAuthUserInfo(provider, tokenData, env);
      if (!userInfo) {
        return new Response('获取用户信息失败', { status: 400 });
      }

      if (!isOAuthAdmin(provider, userInfo.id, env)) {
        return new Response('您不是管理员，无法登录', { status: 403 });
      }

      const token = await getAuthToken(env);
      const cookie = `auth=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`;
      return new Response(`<html><head><meta charset="utf-8"><title>登录成功</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(-45deg,#667eea,#764ba2,#6b8dd6,#8e6fb5);background-size:400% 400%;animation:gs 14s ease infinite}@keyframes gs{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}.box{text-align:center;color:#fff;animation:fi .6s ease both}@keyframes fi{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}.ic{width:80px;height:80px;margin:0 auto 20px;border-radius:50%;background:rgba(255,255,255,0.2);display:flex;align-items:center;justify-content:center;font-size:40px;backdrop-filter:blur(10px)}p{font-size:18px;opacity:.9}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#fff;margin:0 3px;animation:b 1.4s infinite both}.dot:nth-child(2){animation-delay:.2s}.dot:nth-child(3){animation-delay:.4s}@keyframes b{0%,80%,100%{opacity:.3}40%{opacity:1}}</style></head><body><div class="box"><div class="ic">&#10003;</div><p>登录成功，正在跳转<span class="dot"></span><span class="dot"></span><span class="dot"></span></p></div><script>setTimeout(function(){location.href='/';},800);</script></body></html>`, {
        headers: { 'Set-Cookie': cookie, 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }
  } else if (path === '/save' && request.method === 'POST') {
    const content = await request.text();
    if (content) {
      await env.DB.prepare('INSERT OR REPLACE INTO clipboard (key, content) VALUES (?, ?)').bind('main', content).run();
      return new Response('好的');
    } else {
      return new Response('内容为空', { status: 400 });
    }
  } else if (path === '/read' && request.method === 'GET') {
    const row = await env.DB.prepare('SELECT content FROM clipboard WHERE key = ?').bind('main').first();
    if (row && row.content) {
      return new Response(row.content);
    } else {
      return new Response('剪贴板为空', { status: 404 });
    }
  } else if (path === '/items' && request.method === 'POST') {
    const body = await request.json();
    const id = generateUUID();
    const note = body.note || '';
    const tags = Array.isArray(body.tags) ? body.tags : (typeof body.tags === 'string' ? body.tags.split(',').map(t=>t.trim()).filter(Boolean) : []);
    const now = Date.now();
    await env.DB.prepare('INSERT INTO items (id, content, note, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id, body.content || '', note, JSON.stringify(tags), now, now).run();
    return new Response(JSON.stringify({ id }), { headers: { 'Content-Type': 'application/json' } });
  } else if (path === '/items' && request.method === 'GET') {
    const result = await env.DB.prepare('SELECT id, note, tags, created_at, updated_at FROM items ORDER BY created_at DESC').all();
    const items = (result.results || []).map(r => ({
      id: r.id, note: r.note,
      tags: (() => { try { return JSON.parse(r.tags); } catch(e) { return []; } })(),
      createdAt: r.created_at, updatedAt: r.updated_at
    }));
    return new Response(JSON.stringify(items), { headers: { 'Content-Type': 'application/json' } });
  } else if (path.startsWith('/items/')) {
    const id = path.substring('/items/'.length);
    if (request.method === 'GET') {
      const row = await env.DB.prepare('SELECT * FROM items WHERE id = ?').bind(id).first();
      if (!row) return new Response('未找到', { status: 404 });
      const item = { id: row.id, content: row.content, note: row.note, tags: (() => { try { return JSON.parse(row.tags); } catch(e) { return []; } })(), createdAt: row.created_at, updatedAt: row.updated_at };
      return new Response(JSON.stringify(item), { headers: { 'Content-Type': 'application/json' } });
    } else if (request.method === 'PUT') {
      const body = await request.json();
      const row = await env.DB.prepare('SELECT * FROM items WHERE id = ?').bind(id).first();
      if (!row) return new Response('未找到', { status: 404 });
      const content = typeof body.content === 'string' ? body.content : row.content;
      const note = typeof body.note === 'string' ? body.note : row.note;
      let tags;
      if (Array.isArray(body.tags)) tags = body.tags;
      else if (typeof body.tags === 'string') tags = body.tags.split(',').map(t=>t.trim()).filter(Boolean);
      else { try { tags = JSON.parse(row.tags); } catch(e) { tags = []; } }
      await env.DB.prepare('UPDATE items SET content = ?, note = ?, tags = ?, updated_at = ? WHERE id = ?')
        .bind(content, note, JSON.stringify(tags), Date.now(), id).run();
      return new Response('已更新');
    } else if (request.method === 'DELETE') {
      await env.DB.prepare('DELETE FROM items WHERE id = ?').bind(id).run();
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
      const row = await env.DB.prepare('SELECT content FROM items WHERE id = ?').bind(body.id).first();
      if (!row) return new Response('条目不存在', { status: 404 });
      content = row.content;
    } else {
      const row = await env.DB.prepare('SELECT content FROM clipboard WHERE key = ?').bind('main').first();
      content = row ? row.content : null;
    }
    if (!content) {
      return new Response('剪贴板为空', { status: 400 });
    }
    const maxViews = body.maxViews || null;
    const validMinutes = body.validMinutes;
    const shareId = generateUUID();
    const expireAt = validMinutes ? Date.now() + validMinutes * 60 * 1000 : null;
    await env.DB.prepare('INSERT INTO shares (id, content, max_views, expire_at, views, created_at) VALUES (?, ?, ?, ?, 0, ?)')
      .bind(shareId, content, maxViews, expireAt, Date.now()).run();
    const shareUrl = url.origin + '/s/' + shareId;
    return new Response(JSON.stringify({ shareUrl }));
  } else if (path.startsWith('/s/') && request.method === 'GET') {
    const shareId = path.substring(3);
    const row = await env.DB.prepare('SELECT * FROM shares WHERE id = ?').bind(shareId).first();

    if (!row) {
      return new Response('分享链接无效或已过期', { status: 404 });
    }

    if (row.expire_at && Date.now() > row.expire_at) {
      await env.DB.prepare('DELETE FROM shares WHERE id = ?').bind(shareId).run();
      return new Response('分享链接已过期', { status: 403 });
    }

    if (row.max_views && row.views >= row.max_views) {
      await env.DB.prepare('DELETE FROM shares WHERE id = ?').bind(shareId).run();
      return new Response('分享链接已达到最大查看次数', { status: 403 });
    }

    await env.DB.prepare('UPDATE shares SET views = views + 1 WHERE id = ?').bind(shareId).run();

    return new Response(renderSharePage(row.content, { shareId, maxViews: row.max_views, expireAt: row.expire_at, views: row.views + 1 }), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  return new Response('未找到', { status: 404 });
}

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

let __AUTH_TOKEN__;
async function getAuthToken(env) {
  const email = envVal(env, 'ADMIN_EMAIL');
  const pwd = envVal(env, 'ADMIN_PASSWORD');
  if (!email || !pwd) return null;
  if (!__AUTH_TOKEN__) {
    __AUTH_TOKEN__ = await sha256Hex(email + ':' + pwd);
  }
  return __AUTH_TOKEN__;
}

async function isAuthenticated(request, env) {
  const token = await getAuthToken(env);
  if (!token) return true;
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;)\s*auth=([^;]+)/);
  return !!(m && m[1] === token);
}

async function verifyCredentials(email, pwd, env) {
  const adminEmail = envVal(env, 'ADMIN_EMAIL');
  const adminPwd = envVal(env, 'ADMIN_PASSWORD');
  if (!adminEmail || !adminPwd) return true;
  return email === adminEmail && pwd === adminPwd;
}

const loginHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>登录 · 在线剪贴板</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <link rel="icon" href="https://img.xwyue.com/i/2025/01/06/677b63d2572db.png">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg1: #667eea; --bg2: #764ba2; --bg3: #6b8dd6;
      --card-bg: rgba(255,255,255,0.75);
      --text: #2c3e50; --text-muted: #8a94a6;
      --border: rgba(255,255,255,0.6);
      --primary: #667eea; --primary-d: #5568d3;
      --input-bg: rgba(255,255,255,0.65);
      --github-bg: #24292e; --github-d: #1a1e22;
      --danger: #e74c3c;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --card-bg: rgba(40,44,52,0.72);
        --text: #e8eaed; --text-muted: #9aa0a6;
        --border: rgba(255,255,255,0.12);
        --input-bg: rgba(255,255,255,0.08);
      }
    }
    html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; height: 100%; }
    body {
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Microsoft YaHei', sans-serif;
      padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
      overflow: hidden; position: relative;
      background: linear-gradient(-45deg, #667eea, #764ba2, #6b8dd6, #8e6fb5);
      background-size: 400% 400%;
      animation: gradientShift 14s ease infinite;
    }
    @keyframes gradientShift { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
    .orb { position: fixed; border-radius: 50%; filter: blur(60px); opacity: 0.35; pointer-events: none; z-index: 0; }
    .orb-1 { width: 320px; height: 320px; background: #a78bfa; top: -60px; left: -40px; animation: float1 9s ease-in-out infinite; }
    .orb-2 { width: 280px; height: 280px; background: #60a5fa; bottom: -50px; right: -30px; animation: float2 11s ease-in-out infinite; }
    .orb-3 { width: 200px; height: 200px; background: #f472b6; top: 40%; right: 15%; animation: float1 13s ease-in-out infinite reverse; }
    @keyframes float1 { 0%,100%{transform:translate(0,0)} 50%{transform:translate(30px,40px)} }
    @keyframes float2 { 0%,100%{transform:translate(0,0)} 50%{transform:translate(-25px,-30px)} }
    .card {
      position: relative; z-index: 1; width: 400px; max-width: 92%;
      background: var(--card-bg);
      backdrop-filter: blur(24px) saturate(180%); -webkit-backdrop-filter: blur(24px) saturate(180%);
      border: 1px solid var(--border); border-radius: 24px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.2), inset 0 1px 0 rgba(255,255,255,0.4);
      padding: 40px 36px; text-align: center;
      animation: cardIn 0.7s cubic-bezier(0.22,1,0.36,1) both;
    }
    @supports not ((backdrop-filter: blur(24px)) or (-webkit-backdrop-filter: blur(24px))) { .card { background: rgba(255,255,255,0.96); } @media (prefers-color-scheme: dark){ .card{ background: rgba(40,44,52,0.96);} } }
    @keyframes cardIn { 0%{opacity:0;transform:translateY(30px) scale(0.96)} 100%{opacity:1;transform:translateY(0) scale(1)} }
    .icon-wrap {
      width: 72px; height: 72px; margin: 0 auto 18px;
      border-radius: 20px; display: flex; align-items: center; justify-content: center;
      background: linear-gradient(135deg, var(--primary), var(--bg2));
      box-shadow: 0 8px 24px rgba(102,126,234,0.4);
      animation: iconPop 0.8s cubic-bezier(0.34,1.56,0.64,1) 0.2s both;
    }
    @keyframes iconPop { 0%{opacity:0;transform:scale(0)} 100%{opacity:1;transform:scale(1)} }
    .icon-wrap i { font-size: 32px; color: #fff; }
    .card h2 { color: var(--text); font-size: 26px; font-weight: 700; margin-bottom: 6px; }
    .card .sub { color: var(--text-muted); font-size: 14px; margin-bottom: 28px; }
    .input-group { position: relative; margin-bottom: 16px; text-align: left; }
    .input-group i { position: absolute; left: 16px; top: 50%; transform: translateY(-50%); color: var(--text-muted); font-size: 15px; }
    .input-group input {
      width: 100%; padding: 14px 16px 14px 44px; border: 1px solid var(--border);
      border-radius: 14px; font-size: 16px; background: var(--input-bg); color: var(--text);
      transition: border-color 0.25s, box-shadow 0.25s;
    }
    .input-group input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 4px rgba(102,126,234,0.15); }
    .input-group input::placeholder { color: var(--text-muted); }
    .btn { display: flex; align-items: center; justify-content: center; width: 100%; padding: 14px;
      border: none; border-radius: 14px; cursor: pointer; font-size: 16px; font-weight: 600;
      text-decoration: none; transition: transform 0.18s, box-shadow 0.18s, background 0.18s; }
    .btn:active { transform: scale(0.97); }
    .btn-primary { background: linear-gradient(135deg, var(--primary), var(--primary-d)); color: #fff;
      box-shadow: 0 6px 18px rgba(102,126,234,0.35); margin-bottom: 6px; }
    .btn-primary:hover { box-shadow: 0 8px 24px rgba(102,126,234,0.5); transform: translateY(-1px); }
    .divider { display: flex; align-items: center; margin: 22px 0; color: var(--text-muted); font-size: 13px; }
    .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: var(--border); }
    .divider::before { margin-right: 14px; } .divider::after { margin-left: 14px; }
    .btn-github { background: var(--github-bg); color: #fff; box-shadow: 0 6px 18px rgba(36,41,46,0.3); }
    .btn-github:hover { background: var(--github-d); box-shadow: 0 8px 24px rgba(36,41,46,0.45); transform: translateY(-1px); }
    .btn-github i { margin-right: 10px; font-size: 20px; }
    .oauth-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
    .oauth-grid .btn { padding: 12px; font-size: 0; border: 1px solid var(--border); background: var(--input-bg); color: var(--text); }
    .oauth-grid .btn i { font-size: 20px; margin: 0; }
    .oauth-grid .btn:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.12); }
    .oauth-grid .btn-google i { color: #4285f4; }
    .oauth-grid .btn-wechat i { color: #07c160; }
    .oauth-grid .btn-qq i { color: #12b7f5; }
    .msg { color: var(--danger); margin-top: 14px; font-size: 14px; min-height: 20px; }
    .powered { margin-top: 26px; color: var(--text-muted); font-size: 12px; }
    .powered i { margin-right: 4px; }
  </style>
</head>
<body>
  <div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div>
  <div class="card" role="main">
    <div class="icon-wrap"><i class="fas fa-clipboard"></i></div>
    <h2>在线剪贴板</h2>
    <p class="sub">登录以同步你的剪贴内容</p>
    <div class="input-group">
      <i class="fas fa-envelope"></i>
      <input id="email" type="email" placeholder="请输入邮箱" aria-label="邮箱">
    </div>
    <div class="input-group">
      <i class="fas fa-lock"></i>
      <input id="pwd" type="password" placeholder="请输入密码" aria-label="密码">
    </div>
    <button id="loginBtn" class="btn btn-primary">登录</button>
    <div class="divider">或使用第三方登录</div>
    <a href="/oauth/github" class="btn btn-github"><i class="fab fa-github"></i>使用 GitHub 登录</a>
    <div class="oauth-grid" style="margin-top:12px">
      <a href="/oauth/google" class="btn btn-google" aria-label="Google 登录"><i class="fab fa-google"></i></a>
      <a href="/oauth/wechat" class="btn btn-wechat" aria-label="微信登录"><i class="fab fa-weixin"></i></a>
      <a href="/oauth/qq" class="btn btn-qq" aria-label="QQ 登录"><i class="fab fa-qq"></i></a>
    </div>
    <div id="msg" class="msg" role="alert" aria-live="polite"></div>
    <div class="powered"><i class="fas fa-bolt"></i>Powered by Cloudflare Workers</div>
  </div>
  <script>
    const loginBtn = document.getElementById('loginBtn');
    const emailInput = document.getElementById('email');
    const pwdInput = document.getElementById('pwd');
    const msgEl = document.getElementById('msg');
    async function doLogin() {
      const email = emailInput.value.trim();
      const password = pwdInput.value;
      if (!email) { msgEl.textContent = '请输入邮箱'; emailInput.focus(); return; }
      if (!password) { msgEl.textContent = '请输入密码'; pwdInput.focus(); return; }
      loginBtn.textContent = '登录中...'; loginBtn.style.opacity = '0.7';
      try {
        const res = await fetch('/login', { method: 'POST', body: JSON.stringify({ email, password }), headers: { 'Content-Type': 'application/json' } });
        if (res.ok) { location.href = '/'; }
        else { msgEl.textContent = '邮箱或密码错误'; loginBtn.textContent = '登录'; loginBtn.style.opacity = '1'; pwdInput.select(); }
      } catch(e) { msgEl.textContent = '网络错误，请重试'; loginBtn.textContent = '登录'; loginBtn.style.opacity = '1'; }
    }
    loginBtn.addEventListener('click', doLogin);
    pwdInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });
    emailInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') pwdInput.focus(); });
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
    ? `<a class="link" href="${escapeHTML(content)}" target="_blank" rel="noopener">${escapeHTML(content)}</a>`
    : `<pre class="content">${escapeHTML(content)}</pre>`;
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>分享内容 · 在线剪贴板</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root { --text:#2c3e50; --muted:#8a94a6; --primary:#667eea; --border:rgba(0,0,0,0.08); --bg:rgba(255,255,255,0.92); }
    @media (prefers-color-scheme: dark) { :root { --text:#e8eaed; --muted:#9aa0a6; --border:rgba(255,255,255,0.1); --bg:rgba(40,44,52,0.85); } }
    body { min-height:100vh; display:flex; align-items:center; justify-content:center; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'PingFang SC','Microsoft YaHei',sans-serif; background:linear-gradient(-45deg,#667eea,#764ba2,#6b8dd6,#8e6fb5); background-size:400% 400%; animation:gs 14s ease infinite; padding:env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left); }
    @keyframes gs { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
    .card { background:var(--bg); backdrop-filter:blur(20px) saturate(180%); -webkit-backdrop-filter:blur(20px) saturate(180%); border:1px solid var(--border); border-radius:24px; box-shadow:0 20px 60px rgba(0,0,0,0.2); max-width:860px; width:92%; padding:32px; animation:ci .6s cubic-bezier(0.22,1,0.36,1) both; }
    @keyframes ci { 0%{opacity:0;transform:translateY(24px) scale(0.97)} 100%{opacity:1;transform:translateY(0) scale(1)} }
    .head { display:flex; align-items:center; gap:14px; margin-bottom:18px; }
    .head .ic { width:48px; height:48px; border-radius:14px; background:linear-gradient(135deg,#667eea,#764ba2); display:flex; align-items:center; justify-content:center; color:#fff; font-size:22px; flex-shrink:0; }
    h1 { font-size:22px; color:var(--text); }
    .meta { display:flex; flex-wrap:wrap; gap:18px; color:var(--muted); font-size:13px; margin-bottom:16px; }
    .meta i { margin-right:5px; }
    .content { white-space:pre-wrap; word-break:break-word; background:rgba(102,126,234,0.06); border:1px solid var(--border); border-radius:14px; padding:18px; font-size:15px; color:var(--text); overflow:auto; max-height:50vh; line-height:1.6; font-family:'SF Mono',Consolas,Monaco,monospace; }
    .link { display:inline-block; word-break:break-all; color:var(--primary); text-decoration:none; font-size:15px; }
    .link:hover { text-decoration:underline; }
    .actions { display:flex; gap:12px; margin-top:18px; flex-wrap:wrap; }
    .btn { display:flex; align-items:center; gap:8px; padding:12px 22px; border:none; border-radius:12px; cursor:pointer; font-size:15px; font-weight:600; transition:transform .18s,box-shadow .18s; }
    .btn:active { transform:scale(0.97); }
    .btn-primary { background:linear-gradient(135deg,#667eea,#5568d3); color:#fff; box-shadow:0 6px 18px rgba(102,126,234,0.35); }
    .btn-primary:hover { transform:translateY(-1px); box-shadow:0 8px 24px rgba(102,126,234,0.5); }
    .btn-ghost { background:rgba(255,255,255,0.5); color:var(--text); border:1px solid var(--border); }
    @media (prefers-color-scheme: dark) { .btn-ghost { background:rgba(255,255,255,0.08); } }
    .btn-ghost:hover { transform:translateY(-1px); box-shadow:0 4px 12px rgba(0,0,0,0.12); }
  </style>
</head>
<body>
  <div class="card" role="main">
    <div class="head"><div class="ic"><i class="fas fa-share-alt"></i></div><h1>分享内容</h1></div>
    <div class="meta" aria-label="分享信息">
      <div><i class="fas fa-hashtag"></i>${meta && meta.shareId ? escapeHTML(meta.shareId) : '-'}</div>
      <div><i class="far fa-clock"></i>${escapeHTML(expireText)}</div>
      <div><i class="far fa-eye"></i>剩余查看: ${viewsLeft===null?'无限':viewsLeft}</div>
    </div>
    ${displayHTML}
    <div class="actions" role="toolbar" aria-label="操作按钮">
      <button class="btn btn-primary" id="copyBtn"><i class="fas fa-copy"></i>复制内容</button>
      <button class="btn btn-ghost" id="openBtn" ${isURL?'':'style="display:none"'}><i class="fas fa-external-link-alt"></i>打开链接</button>
    </div>
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, user-scalable=no">
  <link rel="icon" href="https://img.xwyue.com/i/2025/01/06/677b63d2572db.png">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="在线剪贴板">
  <link rel="apple-touch-icon" href="https://img.xwyue.com/i/2025/01/06/677b63d2572db.png">
  <link rel="manifest" href="/manifest.json">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #f0f2f5; --bg-grad1: #e8ecf3; --bg-grad2: #d5dce8;
      --surface: rgba(255,255,255,0.82); --surface-solid: #fff;
      --text: #1a202c; --text-muted: #718096; --text-light: #a0aec0;
      --border: rgba(0,0,0,0.08); --border-hover: rgba(0,0,0,0.14);
      --primary: #667eea; --primary-d: #5568d3; --primary-light: rgba(102,126,234,0.1);
      --accent: #764ba2; --success: #48bb78; --danger: #f56565;
      --input-bg: #fff; --shadow: 0 4px 20px rgba(0,0,0,0.06);
      --shadow-lg: 0 12px 40px rgba(0,0,0,0.1);
      --radius: 16px; --radius-sm: 10px;
    }
    body.dark {
      --bg: #1a1b26; --bg-grad1: #1a1b26; --bg-grad2: #161720;
      --surface: rgba(40,42,54,0.8); --surface-solid: #282a36;
      --text: #e8eaed; --text-muted: #9aa0a6; --text-light: #6b7280;
      --border: rgba(255,255,255,0.1); --border-hover: rgba(255,255,255,0.2);
      --primary-light: rgba(102,126,234,0.15);
      --input-bg: #2a2c3a; --shadow: 0 4px 20px rgba(0,0,0,0.3);
      --shadow-lg: 0 12px 40px rgba(0,0,0,0.4);
    }
    html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; height: 100%; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Microsoft YaHei', sans-serif;
      background: linear-gradient(135deg, var(--bg-grad1), var(--bg-grad2));
      color: var(--text); min-height: 100vh; transition: background 0.4s;
      -webkit-tap-highlight-color: transparent; -webkit-touch-callout: none;
      padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
    }
    .orb { position: fixed; border-radius: 50%; filter: blur(80px); opacity: 0.2; pointer-events: none; z-index: 0; }
    .orb-1 { width: 400px; height: 400px; background: var(--primary); top: -120px; right: -80px; }
    .orb-2 { width: 350px; height: 350px; background: var(--accent); bottom: -100px; left: -60px; }
    .wrap { position: relative; z-index: 1; max-width: 1180px; margin: 0 auto; padding: 20px 16px 40px; }
    header {
      display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px;
      animation: fadeDown 0.6s ease both;
    }
    @keyframes fadeDown { from { opacity: 0; transform: translateY(-16px); } to { opacity: 1; transform: translateY(0); } }
    .brand { display: flex; align-items: center; gap: 14px; }
    .brand .logo {
      width: 48px; height: 48px; border-radius: 14px;
      background: linear-gradient(135deg, var(--primary), var(--accent));
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 6px 18px rgba(102,126,234,0.35); flex-shrink: 0;
    }
    .brand .logo i { color: #fff; font-size: 22px; }
    .brand h1 { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
    .brand .sub { font-size: 13px; color: var(--text-muted); }
    .header-actions { display: flex; align-items: center; gap: 10px; }
    .icon-btn {
      width: 42px; height: 42px; border-radius: 12px; border: 1px solid var(--border);
      background: var(--surface); backdrop-filter: blur(12px); color: var(--text);
      cursor: pointer; display: flex; align-items: center; justify-content: center;
      font-size: 17px; transition: all 0.2s;
    }
    .icon-btn:hover { border-color: var(--border-hover); box-shadow: var(--shadow); transform: translateY(-1px); }
    .container {
      background: var(--surface); backdrop-filter: blur(24px) saturate(180%);
      -webkit-backdrop-filter: blur(24px) saturate(180%);
      border: 1px solid var(--border); border-radius: var(--radius);
      box-shadow: var(--shadow-lg); padding: 24px;
      animation: fadeUp 0.6s ease 0.1s both;
    }
    @keyframes fadeUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    @supports not ((backdrop-filter: blur(24px)) or (-webkit-backdrop-filter: blur(24px))) { .container { background: var(--surface-solid); } }
    .layout { display: grid; grid-template-columns: 300px 1fr; gap: 24px; align-items: start; }
    .sidebar { display: flex; flex-direction: column; gap: 14px; }
    .sidebar-section { display: flex; flex-direction: column; gap: 10px; }
    .section-label { font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; padding-left: 4px; }
    .input-field {
      width: 100%; padding: 11px 14px; border: 1px solid var(--border);
      border-radius: var(--radius-sm); font-size: 14px; background: var(--input-bg);
      color: var(--text); transition: border-color 0.2s, box-shadow 0.2s;
    }
    .input-field:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-light); }
    .input-field::placeholder { color: var(--text-light); }
    .items-list { list-style: none; display: flex; flex-direction: column; gap: 8px; max-height: 52vh; overflow-y: auto; padding-right: 4px; }
    .item-card {
      background: var(--input-bg); border: 1px solid var(--border); border-radius: var(--radius-sm);
      padding: 12px 14px; cursor: pointer; transition: all 0.2s; display: flex; flex-direction: column; gap: 4px;
    }
    .item-card:hover { border-color: var(--primary); box-shadow: 0 4px 12px var(--primary-light); transform: translateX(2px); }
    .item-card.active { border-color: var(--primary); background: var(--primary-light); }
    .item-title { font-size: 14px; font-weight: 500; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .item-tags { font-size: 12px; color: var(--text-muted); display: flex; gap: 6px; flex-wrap: wrap; }
    .tag-chip { background: var(--primary-light); color: var(--primary); padding: 2px 8px; border-radius: 6px; font-size: 11px; }
    .empty-list { text-align: center; color: var(--text-light); font-size: 13px; padding: 24px 0; }
    .main-content { display: flex; flex-direction: column; gap: 16px; }
    .controls-row { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }
    .controls-row select { cursor: pointer; }
    textarea {
      width: 100%; height: 280px; padding: 16px; border: 1px solid var(--border);
      border-radius: var(--radius); font-size: 15px; resize: vertical; min-height: 180px;
      background: var(--input-bg); color: var(--text); transition: border-color 0.2s, box-shadow 0.2s;
      font-family: 'SF Mono', 'Consolas', Monaco, monospace; line-height: 1.6;
    }
    textarea:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-light); }
    textarea::placeholder { color: var(--text-light); }
    .actions-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; }
    .action-btn {
      display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;
      padding: 16px 8px; border: 1px solid var(--border); border-radius: var(--radius-sm);
      background: var(--input-bg); color: var(--text); cursor: pointer; font-size: 13px; font-weight: 500;
      transition: all 0.2s; position: relative; overflow: hidden;
    }
    .action-btn i { font-size: 20px; color: var(--primary); transition: transform 0.2s; }
    .action-btn:hover { border-color: var(--primary); background: var(--primary-light); transform: translateY(-2px); box-shadow: var(--shadow); }
    .action-btn:hover i { transform: scale(1.15); }
    .action-btn:active { transform: scale(0.96); }
    .action-btn.danger i { color: var(--danger); }
    .action-btn.danger:hover { border-color: var(--danger); background: rgba(245,101,101,0.08); }
    .action-btn.loading { pointer-events: none; opacity: 0.6; }
    .action-btn.loading::after {
      content: ''; position: absolute; top: 50%; left: 50%; width: 24px; height: 24px;
      margin: -12px 0 0 -12px; border: 3px solid var(--primary); border-top-color: transparent;
      border-radius: 50%; animation: spin 0.7s linear infinite;
    }
    .action-btn.loading i, .action-btn.loading span { opacity: 0; }
    @keyframes spin { to { transform: rotate(360deg); } }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border-hover); border-radius: 10px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--text-light); }
    .modal { display: none; position: fixed; z-index: 100; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background: rgba(0,0,0,0.5); backdrop-filter: blur(4px); }
    .modal.show { display: flex; align-items: center; justify-content: center; animation: fadeIn 0.2s ease; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    .modal-content {
      background: var(--surface-solid); border: 1px solid var(--border); border-radius: 20px;
      width: 92%; max-width: 480px; box-shadow: 0 24px 60px rgba(0,0,0,0.25);
      overflow: hidden; animation: modalIn 0.35s cubic-bezier(0.22,1,0.36,1) both;
    }
    @keyframes modalIn { from { opacity: 0; transform: scale(0.94) translateY(20px); } to { opacity: 1; transform: scale(1) translateY(0); } }
    .modal-header { display: flex; align-items: center; justify-content: space-between; padding: 18px 22px; background: linear-gradient(135deg, var(--primary), var(--accent)); color: #fff; }
    .modal-header h2 { font-size: 18px; font-weight: 600; }
    .modal-header .close { font-size: 24px; cursor: pointer; opacity: 0.8; transition: opacity 0.2s; background: none; border: none; color: #fff; }
    .modal-header .close:hover { opacity: 1; }
    .modal-body { padding: 22px; }
    .form-field { margin-bottom: 16px; }
    .form-field label { display: block; font-size: 14px; font-weight: 500; color: var(--text-muted); margin-bottom: 6px; }
    .form-field input { width: 100%; padding: 12px 14px; border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: 14px; background: var(--input-bg); color: var(--text); }
    .form-field input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-light); }
    .btn { display: flex; align-items: center; justify-content: center; gap: 8px; width: 100%; padding: 13px; border: none; border-radius: var(--radius-sm); cursor: pointer; font-size: 15px; font-weight: 600; transition: all 0.2s; }
    .btn:active { transform: scale(0.97); }
    .btn-primary { background: linear-gradient(135deg, var(--primary), var(--primary-d)); color: #fff; box-shadow: 0 6px 18px rgba(102,126,234,0.3); }
    .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 8px 24px rgba(102,126,234,0.45); }
    .link-box { display: none; grid-template-columns: 1fr auto; gap: 10px; align-items: center; margin-top: 14px; }
    .link-input { width: 100%; padding: 11px 14px; border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: 13px; background: var(--input-bg); color: var(--text); }
    .copy-btn { padding: 11px 18px; border: none; border-radius: var(--radius-sm); background: var(--success); color: #fff; cursor: pointer; font-weight: 600; font-size: 14px; white-space: nowrap; transition: opacity 0.2s; }
    .copy-btn:hover { opacity: 0.88; }
    .helper { margin-top: 10px; font-size: 12px; color: var(--text-light); }
    .toast {
      position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(100px);
      background: var(--surface-solid); border: 1px solid var(--border); color: var(--text);
      padding: 14px 24px; border-radius: 12px; box-shadow: var(--shadow-lg); font-size: 15px;
      z-index: 200; display: flex; align-items: center; gap: 10px; transition: transform 0.3s cubic-bezier(0.22,1,0.36,1); pointer-events: none;
    }
    .toast.show { transform: translateX(-50%) translateY(0); }
    .toast i { color: var(--success); font-size: 18px; }
    .toast.error i { color: var(--danger); }
    @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } .sidebar { order: 2; } .main-content { order: 1; } .items-list { max-height: 300px; } }
    @media (max-width: 600px) {
      .wrap { padding: 12px 10px 30px; }
      .container { padding: 16px; }
      .brand h1 { font-size: 20px; }
      .brand .sub { display: none; }
      .controls-row { grid-template-columns: 1fr; }
      .actions-grid { grid-template-columns: repeat(3, 1fr); }
      textarea { height: 220px; font-size: 14px; }
    }
  </style>
</head>
<body>
  <div class="orb orb-1"></div>
  <div class="orb orb-2"></div>
  <div class="wrap">
    <header>
      <div class="brand">
        <div class="logo"><i class="fas fa-clipboard"></i></div>
        <div>
          <h1>在线剪贴板</h1>
          <div class="sub">随时同步你的剪贴内容</div>
        </div>
      </div>
      <div class="header-actions">
        <button class="icon-btn" id="darkToggle" aria-label="切换主题"><i class="fas fa-moon"></i></button>
        <button class="icon-btn" id="logoutBtn" aria-label="退出登录"><i class="fas fa-sign-out-alt"></i></button>
      </div>
    </header>
    <div class="container" role="main">
      <div class="layout">
        <aside class="sidebar" aria-label="条目列表">
          <div class="sidebar-section">
            <div class="section-label">搜索与筛选</div>
            <input id="searchInput" class="input-field" placeholder="搜索备注或内容" aria-label="搜索">
            <input id="tagFilterInput" class="input-field" placeholder="标签筛选（逗号分隔）" aria-label="标签筛选">
          </div>
          <div class="sidebar-section">
            <div class="section-label">已保存条目</div>
            <ul id="itemsList" class="items-list" role="listbox" aria-label="已保存的条目"></ul>
          </div>
        </aside>
        <main class="main-content">
          <div class="controls-row">
            <input id="noteInput" class="input-field" placeholder="备注（可选）" aria-label="备注">
            <input id="tagsInput" class="input-field" placeholder="标签（逗号分隔）" aria-label="标签">
            <select id="itemsSelect" class="input-field" aria-label="选择条目"><option value="">选择条目...</option></select>
          </div>
          <textarea id="clipboard" placeholder="在此处粘贴或输入内容..." aria-label="剪贴板内容"></textarea>
          <div class="actions-grid" role="toolbar" aria-label="操作按钮">
            <button id="saveBtn" class="action-btn" aria-label="保存条目"><i class="fas fa-cloud-upload-alt"></i><span>保存条目</span></button>
            <button id="readBtn" class="action-btn" aria-label="读取选中"><i class="fas fa-cloud-download-alt"></i><span>读取选中</span></button>
            <button id="copyBtn" class="action-btn" aria-label="复制到本地"><i class="fas fa-copy"></i><span>复制到本地</span></button>
            <button id="shareBtn" class="action-btn" aria-label="分享选中"><i class="fas fa-share-alt"></i><span>分享选中</span></button>
            <button id="refreshBtn" class="action-btn" aria-label="刷新列表"><i class="fas fa-sync"></i><span>刷新列表</span></button>
            <button id="deleteBtn" class="action-btn danger" aria-label="删除选中"><i class="fas fa-trash-alt"></i><span>删除选中</span></button>
          </div>
        </main>
      </div>
    </div>
  </div>
  <div id="shareModal" class="modal" role="dialog" aria-labelledby="shareModalTitle" aria-modal="true">
    <div class="modal-content">
      <div class="modal-header">
        <h2 id="shareModalTitle"><i class="fas fa-share-alt"></i> 分享设置</h2>
        <button class="close" role="button" tabindex="0" aria-label="关闭">&times;</button>
      </div>
      <div class="modal-body">
        <div class="form-field">
          <label for="maxViews">最大查看次数</label>
          <input type="number" id="maxViews" placeholder="留空为无限" aria-describedby="maxViewsDesc">
        </div>
        <div class="form-field">
          <label for="validMinutes">有效时间 (分钟)</label>
          <input type="number" id="validMinutes" placeholder="留空为永久">
        </div>
        <button id="generateShareLink" class="btn btn-primary"><i class="fas fa-link"></i> 生成分享链接</button>
        <div class="link-box" id="linkBox">
          <input id="shareLinkInput" class="link-input" placeholder="分享链接" readonly aria-label="分享链接">
          <button id="copyShareLinkBtn" class="copy-btn"><i class="fas fa-copy"></i> 复制</button>
        </div>
        <div class="helper" id="maxViewsDesc">提示：分享链接可设置有效期和最大查看次数，对方无需登录即可查看</div>
        <div id="shareLink"></div>
      </div>
    </div>
  </div>
  <div id="toast" class="toast" role="status" aria-live="polite"><i class="fas fa-check-circle"></i><span id="toastText"></span></div>
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
    const darkToggle = document.getElementById('darkToggle');
    const darkIcon = darkToggle.querySelector('i');

    // ---- Toast helper ----
    const toastEl = document.getElementById('toast');
    const toastText = document.getElementById('toastText');
    let toastTimer;
    function showToast(msg, isError) {
      clearTimeout(toastTimer);
      toastText.textContent = msg;
      toastEl.classList.toggle('error', !!isError);
      toastEl.querySelector('i').className = isError ? 'fas fa-exclamation-circle' : 'fas fa-check-circle';
      toastEl.classList.add('show');
      toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2400);
    }

    // ---- Dark mode ----
    function applyDark(dark) {
      document.body.classList.toggle('dark', dark);
      darkIcon.className = dark ? 'fas fa-sun' : 'fas fa-moon';
      try { localStorage.setItem('jtb_dark', dark ? '1' : '0'); } catch(e) {}
    }
    (function initTheme() {
      let saved;
      try { saved = localStorage.getItem('jtb_dark'); } catch(e) {}
      if (saved !== null) { applyDark(saved === '1'); }
      else { applyDark(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches); }
    })();
    darkToggle.addEventListener('click', () => applyDark(!document.body.classList.contains('dark')));
    var darkMQ = window.matchMedia('(prefers-color-scheme: dark)');
    if (darkMQ && darkMQ.addEventListener) darkMQ.addEventListener('change', e => { try { if (localStorage.getItem('jtb_dark') === null) applyDark(e.matches); } catch(_) {} });

    // ---- Logout ----
    document.getElementById('logoutBtn').addEventListener('click', () => {
      document.cookie = 'auth=; Path=/; Max-Age=0';
      location.href = '/login';
    });

    // ---- Items ----
    let itemsCache = [];
    let currentItemId = null;
    function renderItems(list) {
      if (!itemsList) return;
      if (!list.length) { itemsList.innerHTML = '<li class="empty-list">暂无条目</li>'; return; }
      itemsList.innerHTML = list.map(function(i) {
        var title = i.note || ('条目 ' + (i.id || '').slice(0,8));
        var tags = (i.tags || []).map(function(t){ return '<span class="tag-chip">' + t + '</span>'; }).join('');
        var cls = i.id === currentItemId ? ' item-card active' : ' item-card';
        return '<li class="' + cls.trim() + '" data-id="' + i.id + '"><div class="item-title">' + title + '</div>' + (tags ? '<div class="item-tags">' + tags + '</div>' : '') + '</li>';
      }).join('');
    }
    function filterAndRender() {
      var q = (searchInput && searchInput.value || '').trim().toLowerCase();
      var tagStr = (tagFilterInput && tagFilterInput.value || '').trim().toLowerCase();
      var tagSet = tagStr ? tagStr.split(',').map(function(t){return t.trim();}).filter(Boolean) : [];
      var list = itemsCache.filter(function(i) {
        var matchesQ = !q || (String(i.note||'').toLowerCase().includes(q) || String(i.id||'').toLowerCase().includes(q));
        var matchesTag = tagSet.length === 0 || (Array.isArray(i.tags) && tagSet.every(function(t){ return i.tags.map(function(x){return String(x).toLowerCase();}).includes(t); }));
        return matchesQ && matchesTag;
      });
      renderItems(list);
    }
    async function refreshItems() {
      try {
        const res = await fetch('/items');
        if (res.ok) {
          itemsCache = await res.json();
          itemsSelect.innerHTML = '<option value="">选择条目...</option>' + itemsCache.map(function(i){ return '<option value="' + i.id + '">' + (i.note || ('条目 ' + i.id.slice(0,8))) + '</option>'; }).join('');
          filterAndRender();
        }
      } catch(e) {}
    }
    refreshItems();

    if (itemsList) {
      itemsList.addEventListener('click', async function(e) {
        var li = e.target.closest('.item-card');
        if (!li || li.classList.contains('empty-list')) return;
        var id = li.getAttribute('data-id');
        if (id) { itemsSelect.value = id; currentItemId = id; filterAndRender(); }
        readBtn.click();
      });
    }
    if (searchInput) searchInput.addEventListener('input', filterAndRender);
    if (tagFilterInput) tagFilterInput.addEventListener('input', filterAndRender);

    saveBtn.addEventListener('click', async () => {
      const content = clipboardTextarea.value;
      const note = noteInput.value;
      const tags = tagsInput.value.split(',').map(function(t){return t.trim();}).filter(Boolean);
      if (!content) { showToast('内容为空', true); return; }
      saveBtn.classList.add('loading');
      try {
        const response = await fetch('/items', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content, note, tags }) });
        saveBtn.classList.remove('loading');
        if (response.ok) {
          const data = await response.json();
          currentItemId = data.id;
          showToast('已保存条目');
          await refreshItems();
        } else { showToast('保存失败', true); }
      } catch(e) { saveBtn.classList.remove('loading'); showToast('网络错误', true); }
    });

    readBtn.addEventListener('click', async () => {
      const id = itemsSelect.value;
      readBtn.classList.add('loading');
      try {
        if (id) {
          const response = await fetch('/items/' + id);
          readBtn.classList.remove('loading');
          if (response.ok) {
            const item = await response.json();
            clipboardTextarea.value = item.content || '';
            noteInput.value = item.note || '';
            tagsInput.value = (item.tags || []).join(',');
            currentItemId = id;
            filterAndRender();
          } else { showToast('读取失败或条目不存在', true); }
        } else {
          const response = await fetch('/read');
          readBtn.classList.remove('loading');
          if (response.ok) { clipboardTextarea.value = await response.text(); }
          else { showToast('读取失败或剪贴板为空', true); }
        }
      } catch(e) { readBtn.classList.remove('loading'); showToast('网络错误', true); }
    });

    copyBtn.addEventListener('click', () => {
      clipboardTextarea.select();
      try { document.execCommand('copy'); } catch(e) {}
      showToast('已复制到本地剪贴板');
    });

    deleteBtn.addEventListener('click', async () => {
      const id = itemsSelect.value;
      if (!id) { showToast('请先选择条目', true); return; }
      if (!confirm('确认删除选中条目？')) return;
      deleteBtn.classList.add('loading');
      try {
        const res = await fetch('/items/' + id, { method: 'DELETE' });
        deleteBtn.classList.remove('loading');
        if (res.ok) { currentItemId = null; showToast('已删除'); await refreshItems(); }
        else { showToast('删除失败', true); }
      } catch(e) { deleteBtn.classList.remove('loading'); showToast('网络错误', true); }
    });

    refreshBtn.addEventListener('click', () => { refreshItems(); showToast('列表已刷新'); });

    if (copyShareLinkBtn) {
      copyShareLinkBtn.addEventListener('click', () => {
        const v = shareLinkInput && shareLinkInput.value;
        if (!v) { showToast('请先生成链接', true); return; }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(v).then(() => showToast('已复制链接'));
        } else {
          const tmp = document.createElement('textarea');
          tmp.value = v; document.body.appendChild(tmp); tmp.select(); document.execCommand('copy'); document.body.removeChild(tmp);
          showToast('已复制链接');
        }
      });
    }

    shareBtn.addEventListener('click', () => { shareModal.classList.add('show'); });
    closeModalBtn.addEventListener('click', () => shareModal.classList.remove('show'));
    closeModalBtn.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); shareModal.classList.remove('show'); } });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') shareModal.classList.remove('show'); });
    shareModal.addEventListener('click', (e) => { if (e.target === shareModal) shareModal.classList.remove('show'); });

    generateShareLinkBtn.addEventListener('click', async () => {
      const maxViews = document.getElementById('maxViews').value;
      const validMinutes = document.getElementById('validMinutes').value;
      const id = itemsSelect.value || null;
      generateShareLinkBtn.classList.add('loading');
      try {
        const response = await fetch('/share', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: id, maxViews: maxViews ? parseInt(maxViews) : null, validMinutes: validMinutes ? parseInt(validMinutes) : null })
        });
        generateShareLinkBtn.classList.remove('loading');
        if (response.ok) {
          const data = await response.json();
          if (shareLinkInput) { shareLinkInput.value = data.shareUrl; if (linkBox) linkBox.style.display = 'grid'; }
          shareLinkDiv.innerHTML = '';
          showToast('分享链接已生成');
        } else { showToast('生成分享链接失败', true); }
      } catch(e) { generateShareLinkBtn.classList.remove('loading'); showToast('网络错误', true); }
    });
  </script>
</body>
</html>
`;

# 在线剪贴板 - 基于 Cloudflare Workers + D1

> **重获新生 · 2026-07-16** — 全面重构：KV 存储升级为 D1 数据库，登录改为邮箱+密码，UI 全面美化。

一个美观、安全、多端同步的在线剪贴板，基于 Cloudflare Workers 和 D1 数据库构建。支持条目管理、安全分享、多渠道第三方登录。

## 功能特性

- **D1 持久化存储** — 使用 Cloudflare D1 数据库，支持条目管理、标签分类、全文搜索
- **邮箱+密码登录** — 管理员凭据通过环境变量存储，安全可靠
- **多渠道 OAuth 登录** — 支持 GitHub、Google、微信、QQ 第三方登录
- **安全分享** — 生成带查看次数限制和有效期的分享链接，对方无需登录
- **毛玻璃 UI** — 现代化渐变背景 + 毛玻璃卡片设计，支持暗黑模式
- **响应式布局** — 完美适配 PC 端和移动端
- **PWA 支持** — 可添加到主屏幕，全屏体验

## 技术栈

| 组件 | 技术 |
|------|------|
| 运行时 | Cloudflare Workers |
| 数据库 | Cloudflare D1 (SQLite) |
| 前端 | HTML + CSS + JavaScript |
| 图标 | Font Awesome 6 |
| 认证 | 邮箱密码 + OAuth 2.0 |

## 仓库结构

```
web-clipboard/
├── index.js          # Worker 主代码（后端 + 前端模板）
├── schema.sql        # D1 数据库建表 SQL
├── wrangler.toml     # Wrangler 部署配置
├── .gitignore
├── LICENSE
├── README.md
└── pictures/         # 效果截图
```

## 数据库表结构

| 表名 | 用途 |
|------|------|
| `items` | 剪贴板条目（内容、备注、标签、时间戳） |
| `shares` | 分享链接（内容、最大查看次数、过期时间） |
| `oauth_state` | OAuth state 临时存储（10分钟自动清理） |
| `clipboard` | 主剪贴板内容 |

## 部署指南

### 1. 克隆仓库

```bash
git clone https://github.com/827802685/web-clipboard.git
cd web-clipboard
```

### 2. 创建 D1 数据库

```bash
# 创建数据库
wrangler d1 create jtb-clipboard

# 将返回的 database_id 填入 wrangler.toml

# 执行建表 SQL
wrangler d1 execute jtb-clipboard --file=schema.sql
```

### 3. 配置环境变量

编辑 `wrangler.toml`，填入你的 `GITHUB_ADMIN_ID` 和 `ADMIN_EMAIL`。

### 4. 设置 Secret 变量

```bash
# 必需：登录密码
wrangler secret put ADMIN_PASSWORD

# GitHub OAuth（可选）
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET

# Google OAuth（可选）
wrangler secret put GOOGLE_CLIENT_ID
wrangler secret put GOOGLE_CLIENT_SECRET

# 微信登录（可选）
wrangler secret put WECHAT_APP_ID
wrangler secret put WECHAT_APP_SECRET

# QQ 登录（可选）
wrangler secret put QQ_APP_ID
wrangler secret put QQ_APP_SECRET
```

### 5. 部署

```bash
wrangler deploy
```

## OAuth 回调地址配置

| 平台 | 回调 URL |
|------|----------|
| GitHub | `https://你的域名/oauth/github/callback` |
| Google | `https://你的域名/oauth/google/callback` |
| 微信 | `https://你的域名/oauth/wechat/callback` |
| QQ | `https://你的域名/oauth/qq/callback` |

## 使用方法

1. 访问你的 Worker 域名
2. 使用邮箱+密码登录，或选择第三方登录
3. 在文本框中输入内容，填写备注和标签
4. 点击「保存条目」存储到 D1 数据库
5. 在左侧列表中点击条目可快速读取
6. 点击「分享选中」生成带有效期和查看限制的分享链接

## 从旧版 KV 迁移到 D1

如果你之前使用 KV 存储，可以编写迁移脚本将数据导入 D1：
1. 读取 KV 中所有 `item:*` 键和 `clipboard` 键
2. 解析 JSON 后插入 D1 的 `items` 和 `clipboard` 表
3. 分享链接键直接迁移到 `shares` 表

## 更新日志

- **2026-07-16** — 重获新生：KV → D1 迁移，邮箱+密码登录，UI 全面美化
- **2025-11-16** — 初始版本：KV 存储，密码登录，OAuth 登录

## License

MIT License

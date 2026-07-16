-- 在线剪贴板 D1 数据库表结构
-- 使用方法: wrangler d1 execute jtb-clipboard --file=schema.sql

-- 剪贴板条目表
CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY,
  content TEXT,
  note TEXT,
  tags TEXT,          -- JSON 数组格式存储
  created_at INTEGER,
  updated_at INTEGER
);

-- 分享链接表
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  content TEXT,
  max_views INTEGER,  -- NULL 表示无限
  expire_at INTEGER,  -- NULL 表示永久
  views INTEGER DEFAULT 0,
  created_at INTEGER
);

-- OAuth state 临时存储（10分钟自动清理）
CREATE TABLE IF NOT EXISTS oauth_state (
  state TEXT PRIMARY KEY,
  provider TEXT,
  created_at INTEGER
);

-- 主剪贴板内容
CREATE TABLE IF NOT EXISTS clipboard (
  key TEXT PRIMARY KEY DEFAULT 'main',
  content TEXT
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_items_created ON items(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shares_created ON shares(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_oauth_state_created ON oauth_state(created_at);

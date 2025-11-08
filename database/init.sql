-- 拡張機能の有効化
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ====================================
-- 管理者テーブル
-- ====================================
CREATE TABLE IF NOT EXISTS "admins" (
  "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  "username" TEXT UNIQUE NOT NULL,
  "email" TEXT UNIQUE NOT NULL,
  "password_hash" TEXT NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ====================================
-- ユーザーテーブル（エンドユーザー）
-- ====================================
CREATE TABLE IF NOT EXISTS "users" (
  "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  "sub" TEXT UNIQUE NOT NULL, -- OpenID Connect の subject identifier
  "name" TEXT,
  "email" TEXT UNIQUE NOT NULL,
  "email_verified" BOOLEAN DEFAULT FALSE,
  "picture" TEXT,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ====================================
-- 外部プロバイダー連携テーブル
-- ====================================
CREATE TABLE IF NOT EXISTS "user_providers" (
  "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  "user_id" UUID NOT NULL REFERENCES "users" (id) ON DELETE CASCADE,
  "provider" TEXT NOT NULL, -- 'google', 'github', etc.
  "provider_user_id" TEXT NOT NULL,
  "access_token" TEXT,
  "refresh_token" TEXT,
  "expires_at" TIMESTAMPTZ,
  "id_token" TEXT,
  "scope" TEXT,
  "token_type" TEXT,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE ("provider", "provider_user_id")
);

-- ====================================
-- クライアントアプリケーションテーブル
-- ====================================
CREATE TABLE IF NOT EXISTS "clients" (
  "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  "client_id" TEXT UNIQUE NOT NULL,
  "client_secret" TEXT NOT NULL,
  "client_name" TEXT NOT NULL,
  "redirect_uris" TEXT[] NOT NULL, -- リダイレクトURIの配列
  "grant_types" TEXT[] NOT NULL DEFAULT ARRAY['authorization_code'], -- 許可するgrant type
  "response_types" TEXT[] NOT NULL DEFAULT ARRAY['code'], -- 許可するresponse type
  "scope" TEXT NOT NULL DEFAULT 'openid profile email',
  "token_endpoint_auth_method" TEXT NOT NULL DEFAULT 'client_secret_basic',
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ====================================
-- 認可コードテーブル
-- ====================================
CREATE TABLE IF NOT EXISTS "authorization_codes" (
  "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  "code" TEXT UNIQUE NOT NULL,
  "client_id" UUID NOT NULL REFERENCES "clients" (id) ON DELETE CASCADE,
  "user_id" UUID NOT NULL REFERENCES "users" (id) ON DELETE CASCADE,
  "redirect_uri" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "code_challenge" TEXT, -- PKCE
  "code_challenge_method" TEXT, -- PKCE
  "nonce" TEXT,
  "state" TEXT,
  "expires_at" TIMESTAMPTZ NOT NULL,
  "used" BOOLEAN DEFAULT FALSE,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ====================================
-- アクセストークンテーブル
-- ====================================
CREATE TABLE IF NOT EXISTS "access_tokens" (
  "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  "token" TEXT UNIQUE NOT NULL,
  "client_id" UUID NOT NULL REFERENCES "clients" (id) ON DELETE CASCADE,
  "user_id" UUID NOT NULL REFERENCES "users" (id) ON DELETE CASCADE,
  "scope" TEXT NOT NULL,
  "expires_at" TIMESTAMPTZ NOT NULL,
  "revoked" BOOLEAN DEFAULT FALSE,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ====================================
-- リフレッシュトークンテーブル
-- ====================================
CREATE TABLE IF NOT EXISTS "refresh_tokens" (
  "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  "token" TEXT UNIQUE NOT NULL,
  "client_id" UUID NOT NULL REFERENCES "clients" (id) ON DELETE CASCADE,
  "user_id" UUID NOT NULL REFERENCES "users" (id) ON DELETE CASCADE,
  "access_token_id" UUID REFERENCES "access_tokens" (id) ON DELETE CASCADE,
  "scope" TEXT NOT NULL,
  "expires_at" TIMESTAMPTZ NOT NULL,
  "revoked" BOOLEAN DEFAULT FALSE,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ====================================
-- セッションテーブル（管理画面用）
-- ====================================
CREATE TABLE IF NOT EXISTS "admin_sessions" (
  "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  "admin_id" UUID NOT NULL REFERENCES "admins" (id) ON DELETE CASCADE,
  "session_token" TEXT UNIQUE NOT NULL,
  "expires_at" TIMESTAMPTZ NOT NULL,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ====================================
-- 監査ログテーブル
-- ====================================
CREATE TABLE IF NOT EXISTS "audit_logs" (
  "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  "actor_type" TEXT NOT NULL, -- 'admin', 'user', 'system'
  "actor_id" UUID,
  "action" TEXT NOT NULL,
  "resource_type" TEXT,
  "resource_id" UUID,
  "details" JSONB,
  "ip_address" TEXT,
  "user_agent" TEXT,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ====================================
-- インデックスの作成
-- ====================================
CREATE INDEX IF NOT EXISTS "idx_users_email" ON "users" ("email");
CREATE INDEX IF NOT EXISTS "idx_users_sub" ON "users" ("sub");
CREATE INDEX IF NOT EXISTS "idx_user_providers_user_id" ON "user_providers" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_user_providers_provider" ON "user_providers" ("provider", "provider_user_id");
CREATE INDEX IF NOT EXISTS "idx_clients_client_id" ON "clients" ("client_id");
CREATE INDEX IF NOT EXISTS "idx_authorization_codes_code" ON "authorization_codes" ("code");
CREATE INDEX IF NOT EXISTS "idx_authorization_codes_user_id" ON "authorization_codes" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_access_tokens_token" ON "access_tokens" ("token");
CREATE INDEX IF NOT EXISTS "idx_access_tokens_user_id" ON "access_tokens" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_refresh_tokens_token" ON "refresh_tokens" ("token");
CREATE INDEX IF NOT EXISTS "idx_admin_sessions_token" ON "admin_sessions" ("session_token");
CREATE INDEX IF NOT EXISTS "idx_audit_logs_actor" ON "audit_logs" ("actor_type", "actor_id");
CREATE INDEX IF NOT EXISTS "idx_audit_logs_created_at" ON "audit_logs" ("created_at");

-- ====================================
-- 初期データ挿入
-- ====================================
-- デフォルト管理者アカウント (username: admin, password: admin123)
-- 本番環境では必ず変更してください
INSERT INTO "admins" ("username", "email", "password_hash")
VALUES (
  'admin',
  'admin@example.com',
  crypt('admin123', gen_salt('bf'))
) ON CONFLICT (username) DO NOTHING;

-- ====================================
-- トリガー関数: updated_at の自動更新
-- ====================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- トリガーの適用
CREATE TRIGGER update_admins_updated_at BEFORE UPDATE ON "admins"
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON "users"
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_providers_updated_at BEFORE UPDATE ON "user_providers"
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON "clients"
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

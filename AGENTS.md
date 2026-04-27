# AGENTS.md

このファイルはAIエージェントがこのリポジトリで作業する際のガイドです。

## プロジェクト概要

Auth0 / Keycloak のような IdP（Identity Provider）を個人レベルで実装するプロジェクト。

- **backend**: IdP 本体（OAuth2 / OpenID Connect サーバー）
- **database**: バックエンドが使用する PostgreSQL スキーマ定義
- **frontend**: バックエンドの設定を操作する管理ダッシュボード

---

## リポジトリ構成

```
openid-aas/
├── backend/          # Go (Gin) による IdP サーバー
├── database/         # Docker Compose + PostgreSQL 初期化 SQL
└── frontend/         # Next.js による管理ダッシュボード
```

---

## backend

### 技術スタック

| 項目 | 内容 |
|------|------|
| 言語 | Go 1.24 |
| フレームワーク | Gin |
| DB ドライバ | pgx/v5 (PostgreSQL) |
| JWT | golang-jwt/jwt/v5 |
| 暗号化 | golang.org/x/crypto |
| 外部 OAuth | golang.org/x/oauth2, google.golang.org/api |
| テスト | testify |

### ディレクトリ構成

```
backend/
├── main.go
├── config/        # 環境変数読み込み
├── database/      # DB 接続 (pgxpool)
├── auth/          # 認証ユーティリティ
├── utils/         # JWT 鍵管理
├── models/        # DB モデル定義
├── handlers/
│   ├── routes/    # ルーティング定義
│   ├── oidc/      # OpenID Connect エンドポイント
│   ├── oauth/     # 外部プロバイダー連携 (Google, GitHub)
│   ├── admin/     # 管理 API (クライアント・ユーザー管理)
│   └── middleware/ # 認証・CORS ミドルウェア
└── test/          # ユニットテスト
```

### 実装済みエンドポイント

#### OIDC / OAuth2 プロバイダー
| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/.well-known/openid-configuration` | OIDC Discovery ドキュメント |
| GET | `/oauth/jwks` | JWK Set (公開鍵) |
| GET | `/oauth/authorize` | 認可エンドポイント |
| POST | `/oauth/token` | トークンエンドポイント |
| GET/POST | `/oauth/userinfo` | UserInfo エンドポイント |

#### 外部プロバイダー経由のユーザー認証
| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/api/auth/google` | Google OAuth 開始 |
| GET | `/api/auth/callback/google` | Google OAuth コールバック |
| GET | `/api/auth/github` | GitHub OAuth 開始 |
| GET | `/api/auth/callback/github` | GitHub OAuth コールバック |

#### 管理 API（`X-Session-Token` ヘッダーで認証）
| メソッド | パス | 説明 |
|---------|------|------|
| POST | `/api/admin/login` | 管理者ログイン |
| POST | `/api/admin/logout` | 管理者ログアウト |
| GET | `/api/admin/clients` | クライアント一覧 |
| POST | `/api/admin/clients` | クライアント作成 |
| GET | `/api/admin/clients/:id` | クライアント取得 |
| DELETE | `/api/admin/clients/:id` | クライアント削除 |
| GET | `/api/admin/users` | ユーザー一覧 |
| GET | `/api/admin/users/:id` | ユーザー取得 |
| DELETE | `/api/admin/users/:id` | ユーザー削除 |

### 環境変数

```env
DATABASE_URL=postgres://user:password@localhost:5432/openid_aas?sslmode=disable
SERVER_PORT=8080
SERVER_HOST=http://localhost:8080
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:8080/api/auth/callback/google
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URI=http://localhost:8080/api/auth/callback/github
JWT_SECRET_KEY=your-secret-key-change-this-in-production
JWT_ISSUER=http://localhost:8080
FRONTEND_URL=http://localhost:3000
ENVIRONMENT=development
```

### 起動方法

```bash
cd backend
go run main.go
```

### テスト実行

```bash
cd backend
go test ./...
```

---

## database

### 技術スタック

| 項目 | 内容 |
|------|------|
| DB | PostgreSQL 16 |
| キャッシュ | Redis (latest) |
| 管理 | Docker Compose |

### テーブル一覧

| テーブル | 説明 |
|---------|------|
| `admins` | 管理画面ログイン用の管理者 |
| `users` | エンドユーザー（OIDC の subject） |
| `user_providers` | 外部プロバイダー連携情報 (Google, GitHub 等) |
| `clients` | OAuth2 クライアントアプリ |
| `authorization_codes` | 認可コード（PKCE 対応） |
| `access_tokens` | アクセストークン |
| `refresh_tokens` | リフレッシュトークン |
| `admin_sessions` | 管理画面セッション |
| `audit_logs` | 操作監査ログ |

### 起動方法

```bash
cd database
docker compose up -d
```

デフォルト管理者: `admin` / `admin123`（本番環境では必ず変更すること）

---

## frontend

### 技術スタック

| 項目 | 内容 |
|------|------|
| フレームワーク | Next.js 16 (App Router) |
| UI | MUI (Material UI) v7 |
| 言語 | TypeScript |
| パッケージマネージャ | pnpm |

### ページ構成

```
src/app/
├── page.tsx                   # トップページ
├── admin/
│   ├── layout.tsx             # 管理画面レイアウト
│   ├── page.tsx               # 管理画面ダッシュボード
│   ├── login/page.tsx         # 管理者ログイン
│   ├── clients/
│   │   ├── page.tsx           # クライアント一覧
│   │   ├── new/page.tsx       # クライアント作成
│   │   └── [id]/page.tsx      # クライアント詳細
│   └── users/
│       ├── page.tsx           # ユーザー一覧
│       └── [id]/page.tsx      # ユーザー詳細
```

### 環境変数

```env
NEXT_PUBLIC_API_URL=http://localhost:8080
```

### 起動方法

```bash
cd frontend
pnpm install
pnpm dev
```

---

## CI

GitHub Actions (`.github/workflows/go.yml`) で backend の build / test を実行。
- トリガー: `main`・`develop` への push、`develop` への PR（`backend/**` 変更時）

---

## 未実装 / TODO

- `/api/auth/callback/google` および `/api/auth/callback/github` のコールバック後のセッション作成とリダイレクト（ルーティングに `// TODO` コメントあり）
- クライアントの PUT（更新）API
- ユーザーの PUT（更新）API
- Redis を活用したセッション/トークン管理
- ログイン UI（エンドユーザー向け認可画面）

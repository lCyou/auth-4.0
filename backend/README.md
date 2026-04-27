# OpenID AAS Backend

OpenID Connect対応の認証基盤バックエンド

## 機能

- OpenID Connect Provider
- OAuth 2.0認証フロー
- 外部プロバイダー連携 (Google, GitHub)
- 管理者API
- JWT認証

## セットアップ

### 1. 前提条件

- Go 1.24以上
- PostgreSQL
- Google OAuth2認証情報（オプション）
- GitHub OAuth2認証情報（オプション）

### 2. データベースの準備

PostgreSQLデータベースを作成：

```bash
createdb minus_four
```

### 3. 環境変数の設定

`.env`ファイルを編集：

```bash
# データベース接続
DATABASE_URL="postgres://user:password@localhost:5432/minus_four?sslmode=disable"

# Google OAuth（オプション）
GOOGLE_CLIENT_ID="your_google_client_id"
GOOGLE_CLIENT_SECRET="your_google_client_secret"
GOOGLE_REDIRECT_URI="http://localhost:8080/api/auth/callback/google"

# GitHub OAuth（オプション）
GITHUB_CLIENT_ID="your_github_client_id"
GITHUB_CLIENT_SECRET="your_github_client_secret"
GITHUB_REDIRECT_URI="http://localhost:8080/api/auth/callback/github"

# JWT設定
JWT_SECRET_KEY="your-super-secret-key-change-in-production"

# サーバー設定
SERVER_PORT="8080"
SERVER_HOST="http://localhost:8080"

# フロントエンド
FRONTEND_URL="http://localhost:3000"

# 環境
ENVIRONMENT="development"
```

### 4. 依存関係のインストール

```bash
go mod download
```

### 5. データベースマイグレーション

データベーススキーマを適用します。マイグレーションファイルがある場合は実行してください。

## 起動方法

### 開発環境での起動

```bash
# バックエンドディレクトリに移動
cd /Users/kyou/workspace/openid-aas/backend

# アプリケーションを起動
go run main.go
```

または、ビルドして実行：

```bash
# ビルド
go build -o backend_app

# 実行
./backend_app
```

サーバーが起動すると、以下のメッセージが表示されます：
```
Successfully connected to database
Server starting on port 8080
```

## エンドポイント

### ヘルスチェック

```
GET /health
```

### OpenID Connect Discovery

```
GET /.well-known/openid-configuration
GET /oauth/jwks
```

### OAuth/OIDC Provider

```
GET /oauth/authorize
POST /oauth/token
GET /oauth/userinfo
POST /oauth/userinfo
```

### 外部プロバイダー認証

#### Google OAuth
```
GET /api/auth/google
GET /api/auth/callback/google
```

#### GitHub OAuth
```
GET /api/auth/github
GET /api/auth/callback/github
```

### 管理者API

```
POST /api/admin/login
POST /api/admin/logout

# 以下は管理者認証が必要
GET /api/admin/clients
POST /api/admin/clients
GET /api/admin/clients/:id
DELETE /api/admin/clients/:id

GET /api/admin/users
GET /api/admin/users/:id
DELETE /api/admin/users/:id
```

## OAuth プロバイダーの設定

### Google OAuth

1. [Google Cloud Console](https://console.cloud.google.com/)にアクセス
2. プロジェクトを作成または選択
3. 「APIとサービス」→「認証情報」→「認証情報を作成」→「OAuthクライアントID」
4. リダイレクトURIに追加：`http://localhost:8080/api/auth/callback/google`
5. クライアントIDとクライアントシークレットを`.env`ファイルに設定

### GitHub OAuth

1. [GitHub Settings](https://github.com/settings/developers)にアクセス
2. 「OAuth Apps」→「New OAuth App」
3. 以下を設定：
   - **Application name**: 任意の名前
   - **Homepage URL**: `http://localhost:8080`
   - **Authorization callback URL**: `http://localhost:8080/api/auth/callback/github`
4. クライアントIDとクライアントシークレットを`.env`ファイルに設定

## トラブルシューティング

### データベース接続エラー

PostgreSQLが起動していることを確認：
```bash
# macOSの場合
brew services start postgresql@14

# または直接確認
psql -U user -d minus_four
```

### ポート8080が使用中

別のポートを使用する場合は`.env`ファイルで変更：
```
SERVER_PORT="3000"
```

### 依存関係のエラー

```bash
go mod tidy
go mod download
```

## 開発

### コードのフォーマット

```bash
go fmt ./...
```

### テスト実行

```bash
go test ./...
```

## ディレクトリ構造


```
backend/
├── auth/           # 認証・認可ロジック
├── config/         # 設定管理
├── database/       # データベース接続
├── handlers/       # HTTPハンドラー
│   ├── admin/      # 管理者API
│   ├── oauth/      # 外部OAuth (Google, GitHub)
│   └── oidc/       # OIDC Provider実装
├── middleware/     # ミドルウェア
├── models/         # データモデル
├── routes/         # ルーティング設定
├── utils/          # ユーティリティ
└── main.go         # エントリーポイント
```

## ライセンス

MIT

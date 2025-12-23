# IdP管理画面

OpenID Connect IdP（Identity Provider）の管理画面フロントエンドです。

## 機能

- **ログイン認証**: 管理者としてログイン
- **クライアント管理**: OAuth 2.0 / OpenID Connectクライアントの作成、閲覧、削除
- **ユーザー管理**: 登録されたユーザーの閲覧と削除

## 技術スタック

- Next.js 16 (App Router)
- React 19
- Material-UI (MUI) v7
- TypeScript

## セットアップ

### 1. 依存関係のインストール

```bash
cd frontend
pnpm install
```

### 2. 環境変数の設定

`.env.local`ファイルを作成してバックエンドAPIのURLを設定します：

```bash
cp .env.local.example .env.local
```

`.env.local`を編集：

```
NEXT_PUBLIC_API_URL=http://localhost:8080
```

### 3. 開発サーバーの起動

```bash
pnpm dev
```

アプリケーションは http://localhost:3000 で起動します。

## 利用方法

### 管理画面へのアクセス

1. http://localhost:3000/admin/login にアクセス
2. 管理者の認証情報でログイン
3. ダッシュボードが表示されます

### 各機能

#### クライアント管理 (`/admin/clients`)

- **一覧表示**: 登録されているすべてのOAuth/OIDCクライアントを表示
- **新規作成**: 新しいクライアントを作成
  - クライアント名
  - クライアントID
  - クライアントシークレット
  - リダイレクトURI
  - Grant Types (authorization_code, refresh_token, client_credentials)
  - Response Types (code, token, id_token)
  - Scope
- **詳細表示**: クライアントの詳細情報を表示
- **削除**: クライアントを削除

#### ユーザー管理 (`/admin/users`)

- **一覧表示**: 登録されているすべてのユーザーを表示
  - プロフィール画像
  - 名前
  - メールアドレス
  - プロバイダー (Google, GitHub等)
- **詳細表示**: ユーザーの詳細情報を表示
- **削除**: ユーザーを削除

## ディレクトリ構造

```
frontend/
├── src/
│   ├── app/                    # Next.js App Router
│   │   ├── admin/             # 管理画面ルート
│   │   │   ├── layout.tsx     # 認証プロバイダー
│   │   │   ├── page.tsx       # ダッシュボード
│   │   │   ├── login/         # ログイン画面
│   │   │   ├── clients/       # クライアント管理
│   │   │   └── users/         # ユーザー管理
│   │   ├── globals.css
│   │   └── layout.tsx
│   ├── components/            # 共通コンポーネント
│   │   ├── AdminLayout.tsx    # 管理画面レイアウト
│   │   ├── AdminLayoutWrapper.tsx  # 認証ガード
│   │   ├── EmotionCache.tsx
│   │   └── ThemeRegistry.tsx
│   ├── contexts/              # React Context
│   │   └── AuthContext.tsx    # 認証状態管理
│   └── lib/                   # ユーティリティ
│       └── api.ts             # API通信関数
├── public/
├── .env.local.example
├── package.json
└── README-ADMIN.md
```

## API エンドポイント

バックエンドAPIは以下のエンドポイントを提供します：

- `POST /api/admin/login` - 管理者ログイン
- `POST /api/admin/logout` - 管理者ログアウト
- `GET /api/admin/clients` - クライアント一覧取得
- `POST /api/admin/clients` - クライアント作成
- `GET /api/admin/clients/:id` - クライアント詳細取得
- `DELETE /api/admin/clients/:id` - クライアント削除
- `GET /api/admin/users` - ユーザー一覧取得
- `GET /api/admin/users/:id` - ユーザー詳細取得
- `DELETE /api/admin/users/:id` - ユーザー削除

## ビルド

本番環境用にビルドする場合：

```bash
pnpm build
pnpm start
```

## 認証について

- 管理画面へのアクセスは認証が必要です
- ログイン時に取得したJWTトークンを`localStorage`に保存
- すべてのAPI リクエストに`Authorization: Bearer <token>`ヘッダーを付与
- トークンがない場合は自動的にログイン画面にリダイレクト

## CORS設定

バックエンド側でCORSを適切に設定してください：

- `Access-Control-Allow-Origin`: フロントエンドのオリジン
- `Access-Control-Allow-Methods`: GET, POST, DELETE
- `Access-Control-Allow-Headers`: Content-Type, Authorization

## ライセンス

このプロジェクトは MIT ライセンスの下で公開されています。

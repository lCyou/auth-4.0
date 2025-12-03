# プロジェクトコンテキスト

このドキュメントは、AIエージェントがこのリポジトリを理解しやすくするためのコンテキスト情報を提供します。

## プロジェクト概要

このプロジェクトは **OpenID Connect (OIDC) 認証プロバイダー** を実装したフルスタックアプリケーションです。
外部OAuthプロバイダー（Google、GitHubなど）と統合し、クライアントアプリケーションに認証・認可サービスを提供します。

### 主な機能

- **OpenID Connect プロバイダー**: 標準的なOIDCフローを実装
- **外部OAuth統合**: Google OAuth2.0などの外部プロバイダーとの連携
- **管理者ポータル**: クライアントアプリケーションとユーザーの管理
- **JWT認証**: セキュアなトークンベース認証
- **PKCE対応**: 認可コードフローのセキュリティ強化

## ディレクトリ構造

プロジェクトは3つの主要なディレクトリに分割されています：

### `/backend` - バックエンドAPI (Go)

Go言語で実装されたRESTful APIサーバー。Ginフレームワークを使用。

**構成:**
- `main.go` - アプリケーションのエントリーポイント
- `auth/` - 認証・認可ロジック
- `handlers/` - HTTPハンドラー
  - `admin/` - 管理者向けエンドポイント
  - `oauth/` - 外部OAuthプロバイダー連携
  - `oidc/` - OpenID Connectエンドポイント
- `middleware/` - CORSなどのミドルウェア
- `models/` - データモデル定義
- `routes/` - ルーティング設定
- `database/` - データベース接続と操作
- `config/` - 設定管理
- `utils/` - ユーティリティ関数（JWT鍵管理など）

**技術スタック:**
- **フレームワーク**: Gin
- **データベースドライバー**: pgx/v5 (PostgreSQL)
- **JWT**: golang-jwt/jwt/v5
- **OAuth2**: golang.org/x/oauth2

**なぜGoを選んだのか:**
- 高性能で並行処理に優れている
- 型安全性が高くバグが少ない
- セキュリティアプリケーションに適している

### `/frontend` - フロントエンドUI (Next.js)

React/Next.jsで実装されたWebアプリケーション。

**構成:**
- `src/app/` - Next.js App Router
- `src/components/` - 再利用可能なReactコンポーネント
- `public/` - 静的アセット

**技術スタック:**
- **フレームワーク**: Next.js 16
- **UI**: React 19, Material-UI (MUI)
- **言語**: TypeScript
- **パッケージマネージャー**: pnpm

**なぜNext.jsを選んだのか:**
- サーバーサイドレンダリング(SSR)による高速なページ読み込み
- TypeScriptによる型安全性
- 優れた開発体験とホットリロード

### `/database` - データベース設定

PostgreSQLデータベースの初期化スクリプトとDocker構成。

**構成:**
- `init.sql` - データベーススキーマ定義
- `docker-compose.yaml` - ローカル開発用のDocker設定

**スキーマ:**
- `admins` - 管理者アカウント
- `users` - エンドユーザー（OpenID Connect sub含む）
- `user_providers` - 外部プロバイダー連携情報
- `clients` - OAuthクライアントアプリケーション
- `authorization_codes` - 認可コード（PKCE対応）
- `access_tokens` - アクセストークン
- `refresh_tokens` - リフレッシュトークン

**なぜ独立したディレクトリなのか:**
- データベーススキーマの管理を一元化
- バックエンドとフロントエンドの両方から独立
- Docker Composeでローカル環境を簡単にセットアップ可能

## 開発ワークフロー

### バックエンド開発

```bash
cd backend
go mod download
go run main.go
```

環境変数は`.env`ファイルで管理します。

### フロントエンド開発

```bash
cd frontend
pnpm install
pnpm dev
```

開発サーバーは http://localhost:3000 で起動します。

### データベースセットアップ

```bash
cd database
docker-compose up -d
```

PostgreSQLがポート5432で起動します。

## コーディング規約

### バックエンド (Go)

- **エラーハンドリング**: すべてのエラーは適切に処理し、ログに記録する
- **ネーミング**: Goの標準的な命名規則に従う（camelCase、exported identifierは大文字始まり）
- **パッケージ構成**: 機能ごとにパッケージを分割
- **セキュリティ**: パスワードは必ずハッシュ化、JWTの検証を徹底

### フロントエンド (TypeScript/React)

- **型定義**: TypeScriptの型を積極的に活用
- **コンポーネント**: 再利用可能な小さなコンポーネントに分割
- **スタイル**: Material-UIのテーマシステムを使用
- **命名**: camelCaseを使用

## セキュリティ考慮事項

- パスワードはbcryptでハッシュ化
- JWTトークンは適切に署名・検証
- PKCE (Proof Key for Code Exchange) を実装
- CORS設定を適切に管理
- SQLインジェクション対策（パラメータ化クエリ使用）

## よくある質問

### Q: このプロジェクトは何をするものですか？
A: 外部OAuthプロバイダー（Googleなど）と統合し、他のアプリケーションにOpenID Connect認証サービスを提供するプラットフォームです。

### Q: なぜバックエンドとフロントエンドが分離しているのですか？
A: マイクロサービスアーキテクチャを採用し、各コンポーネントの独立性と拡張性を確保するためです。

### Q: データベースはどこで実行されますか？
A: ローカル開発ではDocker Composeで実行され、本番環境では外部のPostgreSQLサービスを使用します。

## 参考資料

- [OpenID Connect Specification](https://openid.net/connect/)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [Gin Framework Documentation](https://gin-gonic.com/docs/)
- [Next.js Documentation](https://nextjs.org/docs)

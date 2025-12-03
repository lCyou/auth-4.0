# プロジェクトコンテキスト・コーディングガイド

このドキュメントは、AIエージェント（GitHub Copilotなど）がこのリポジトリを理解し、効果的にコード補完を行うための情報を提供します。

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

## 基本方針

- **日本語**: コメントとドキュメントは日本語で記述する
- **型安全性**: TypeScriptとGoの型システムを最大限活用する
- **セキュリティファースト**: 認証・認可に関わるコードは特に慎重に実装する

## コーディング規約

### バックエンド (Go)

#### エラーハンドリング
```go
// 良い例
result, err := someFunction()
if err != nil {
    log.Printf("Error in someFunction: %v", err)
    return fmt.Errorf("failed to execute: %w", err)
}

// 避けるべき：エラーを無視する
result, _ := someFunction()
```

#### HTTPハンドラー
```go
// Ginハンドラーの標準的なパターン
func HandleExample(c *gin.Context) {
    // 1. リクエストのバリデーション
    var req ExampleRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
        return
    }

    // 2. ビジネスロジックの実行
    result, err := processRequest(req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
        return
    }

    // 3. レスポンスの返却
    c.JSON(http.StatusOK, result)
}
```

#### データベースクエリ
```go
// パラメータ化クエリを使用してSQLインジェクションを防ぐ
query := `SELECT * FROM users WHERE email = $1`
var user User
err := db.QueryRow(context.Background(), query, email).Scan(&user)
```

#### JWT処理
```go
// JWTの生成と検証は utils パッケージの関数を使用
token, err := utils.GenerateJWT(claims)
claims, err := utils.ValidateJWT(tokenString)
```

#### ファイル命名規約
- ファイル名: `snake_case.go`
- パッケージ名: 小文字、単語（例: `handlers`, `middleware`）
- インターフェース: `I`プレフィックスなし（例: `Handler`, `Repository`）

#### コメント
```go
// パブリック関数にはGoDocコメントを付ける
// HandleLogin はユーザーのログインリクエストを処理します。
// メールアドレスとパスワードを検証し、JWTトークンを発行します。
func HandleLogin(c *gin.Context) {
    // ...
}
```

### フロントエンド (TypeScript/React)

#### コンポーネント定義
```typescript
// 関数コンポーネントを使用し、明示的な型定義を行う
interface ExampleProps {
  title: string;
  onSubmit: (data: FormData) => void;
  isLoading?: boolean;
}

export const ExampleComponent: React.FC<ExampleProps> = ({ 
  title, 
  onSubmit, 
  isLoading = false 
}) => {
  // コンポーネントの実装
};
```

#### 状態管理
```typescript
// useStateの型を明示的に指定
const [user, setUser] = useState<User | null>(null);
const [isLoading, setIsLoading] = useState<boolean>(false);
```

#### API呼び出し
```typescript
// async/awaitを使用し、エラーハンドリングを適切に行う
const fetchUser = async (userId: string): Promise<User> => {
  try {
    const response = await fetch(`/api/users/${userId}`);
    if (!response.ok) {
      throw new Error('Failed to fetch user');
    }
    return await response.json();
  } catch (error) {
    console.error('Error fetching user:', error);
    throw error;
  }
};
```

#### Material-UIの使用
```typescript
// MUIコンポーネントを使用し、テーマに従う
import { Button, TextField, Box } from '@mui/material';

<Box sx={{ p: 2 }}>
  <TextField label="Email" type="email" fullWidth required />
  <Button variant="contained" color="primary" sx={{ mt: 2 }}>
    送信
  </Button>
</Box>
```

#### ファイル命名規約
- コンポーネント: `PascalCase.tsx`
- ユーティリティ: `camelCase.ts`
- 型定義: `types.ts` または `interfaces.ts`

#### コメント
```typescript
/**
 * ユーザー情報を取得する
 * @param userId ユーザーID
 * @returns ユーザー情報
 * @throws ユーザーが見つからない場合
 */
export const getUser = async (userId: string): Promise<User> => {
  // ...
};
```

## セキュリティガイドライン

### パスワード処理
- **絶対にプレーンテキストでパスワードを保存しない**
- バックエンドでbcryptを使用してハッシュ化
- フロントエンドからは必ずHTTPSで送信

### JWT処理
- トークンは短い有効期限を設定（アクセストークン: 15分、リフレッシュトークン: 7日など）
- リフレッシュトークンはHTTPOnly Cookieで保存
- トークンの検証を必ず行う

### CORS設定
- 本番環境では特定のオリジンのみ許可
- 開発環境でもワイルドカード(`*`)の使用は避ける

### SQLインジェクション対策
- **常にパラメータ化クエリを使用**
- 文字列連結でクエリを構築しない

### XSS対策
- ユーザー入力は必ずエスケープ
- Reactは自動的にエスケープするが、`dangerouslySetInnerHTML`は使用しない

### PKCE
- 認可コードフローでPKCE (Proof Key for Code Exchange) を実装

## テスト

### バックエンド
- テストファイル: `*_test.go`
- テーブル駆動テストを使用
- モックは標準的なインターフェースを活用

### フロントエンド
- テストファイル: `*.test.tsx` または `*.spec.tsx`
- React Testing Libraryを使用
- ユーザーの操作をシミュレート

## 環境変数

### 命名規則
- すべて大文字で`SNAKE_CASE`
- プレフィックスで用途を明確に（`DB_`: データベース、`JWT_`: JWT、`OAUTH_`: OAuth）

### 例
```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_db

JWT_SECRET=your-secret-key
JWT_EXPIRATION=15m

OAUTH_GOOGLE_CLIENT_ID=xxx
OAUTH_GOOGLE_CLIENT_SECRET=xxx
```

## よくあるパターン

### 認証が必要なエンドポイント
```go
// ミドルウェアを使用して認証を確認
protected := r.Group("/api/protected")
protected.Use(middleware.AuthRequired())
{
    protected.GET("/profile", handlers.GetProfile)
}
```

### ページネーション
```go
// クエリパラメータでページングを実装
page := c.DefaultQuery("page", "1")
limit := c.DefaultQuery("limit", "10")
```

### エラーレスポンスの統一
```go
// 一貫したエラーレスポンス形式
type ErrorResponse struct {
    Error   string `json:"error"`
    Message string `json:"message"`
    Code    int    `json:"code"`
}
```

## AIエージェントへの指示

1. **セキュリティを最優先**: 認証・認可に関するコードは特に慎重に生成してください
2. **型安全性**: 型のないコードは生成しないでください
3. **エラーハンドリング**: すべてのエラーケースを考慮してください
4. **テストカバレッジ**: 重要な機能には必ずテストを含めてください
5. **ドキュメント**: 複雑なロジックには必ず説明コメントを付けてください
6. **既存のパターンに従う**: プロジェクトの既存のコーディングスタイルを尊重してください

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

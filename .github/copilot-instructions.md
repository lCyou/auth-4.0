# GitHub Copilot 用の指示

このドキュメントは、GitHub Copilotがこのプロジェクトで効果的にコード補完を行うための指示を提供します。

## 基本方針

- **日本語**: コメントとドキュメントは日本語で記述する
- **型安全性**: TypeScriptとGoの型システムを最大限活用する
- **セキュリティファースト**: 認証・認可に関わるコードは特に慎重に実装する

## バックエンド (Go) コーディング規約

### エラーハンドリング
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

### HTTPハンドラー
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

### データベースクエリ
```go
// パラメータ化クエリを使用してSQLインジェクションを防ぐ
query := `SELECT * FROM users WHERE email = $1`
var user User
err := db.QueryRow(context.Background(), query, email).Scan(&user)
```

### JWT処理
```go
// JWTの生成と検証は utils パッケージの関数を使用
token, err := utils.GenerateJWT(claims)
claims, err := utils.ValidateJWT(tokenString)
```

## フロントエンド (TypeScript/React) コーディング規約

### コンポーネント定義
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

### 状態管理
```typescript
// useStateの型を明示的に指定
const [user, setUser] = useState<User | null>(null);
const [isLoading, setIsLoading] = useState<boolean>(false);
```

### API呼び出し
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

### Material-UI の使用
```typescript
// MUIコンポーネントを使用し、テーマに従う
import { Button, TextField, Box } from '@mui/material';

<Box sx={{ p: 2 }}>
  <TextField 
    label="Email" 
    type="email" 
    fullWidth 
    required 
  />
  <Button 
    variant="contained" 
    color="primary" 
    sx={{ mt: 2 }}
  >
    送信
  </Button>
</Box>
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

## ファイル命名規約

### バックエンド (Go)
- ファイル名: `snake_case.go`
- パッケージ名: 小文字、単語（例: `handlers`, `middleware`）
- インターフェース: `I`プレフィックスなし（例: `Handler`, `Repository`）

### フロントエンド (TypeScript/React)
- コンポーネント: `PascalCase.tsx`
- ユーティリティ: `camelCase.ts`
- 型定義: `types.ts` または `interfaces.ts`

## コメントとドキュメント

### Go
```go
// パブリック関数にはGoDocコメントを付ける
// HandleLogin はユーザーのログインリクエストを処理します。
// メールアドレスとパスワードを検証し、JWTトークンを発行します。
func HandleLogin(c *gin.Context) {
    // ...
}
```

### TypeScript
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

## テストの書き方

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
- プレフィックスで用途を明確に
  - `DB_`: データベース関連
  - `JWT_`: JWT関連
  - `OAUTH_`: OAuth関連

### 例
```env
# データベース
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_db

# JWT
JWT_SECRET=your-secret-key
JWT_EXPIRATION=15m

# OAuth
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

## AI エージェントへの特別な指示

1. **セキュリティを最優先**: 認証・認可に関するコードは特に慎重に生成してください
2. **型安全性**: 型のないコードは生成しないでください
3. **エラーハンドリング**: すべてのエラーケースを考慮してください
4. **テストカバレッジ**: 重要な機能には必ずテストを含めてください
5. **ドキュメント**: 複雑なロジックには必ず説明コメントを付けてください
6. **既存のパターンに従う**: プロジェクトの既存のコーディングスタイルを尊重してください

## 参考リソース

- [プロジェクトコンテキスト](./CONTEXT.md)
- [OpenID Connect仕様](https://openid.net/connect/)
- [Ginフレームワーク](https://gin-gonic.com/)
- [Next.js ドキュメント](https://nextjs.org/docs)

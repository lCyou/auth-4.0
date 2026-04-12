# TODO — backend 改善リスト

優先度: 🔴 クリティカル / 🟠 重要 / 🟡 改善

---

## バグ

### 🔴 `contains` 関数が壊れている (`handlers/oidc/token.go:370`)

スコープ文字列の部分マッチチェックを自前で書いているが実装が間違っている。
`"openid"` を `"openid profile"` から検索する場合は動くが、`"profile"` を `"openid profile email"` から検索するケースなど境界条件でサイレントに誤動作する。

```go
// 現状 (壊れている)
func contains(s, substr string) bool {
    return len(s) >= len(substr) && (s == substr || ...)
}

// 修正: スペース区切りでセットに変換してチェック
func scopeContains(scopeStr, target string) bool {
    for _, s := range strings.Fields(scopeStr) {
        if s == target { return true }
    }
    return false
}
```

---

### 🔴 管理者パスワード検証ロジックが誤っている (`handlers/admin/auth.go:55-65`)

`crypt()` の結果を `Scan(&storedHash string)` で受けているが、`crypt($1, hash) = hash` は PostgreSQL の `boolean` を返す。Go 側の `string` 変数には `"true"` / `"false"` が入るため `storedHash != "t"` の比較は常に失敗し、必ず bcrypt フォールバックに落ちる。さらに bcrypt フォールバックは init.sql で `crypt('...', gen_salt('bf'))` で作られたハッシュに対して使われるため、こちらも一致しない。結果としてデフォルト管理者でログインできない可能性がある。

修正: `SELECT crypt($1, password_hash) = password_hash` の結果は `bool` でスキャンするか、Go 側で bcrypt に統一する。パスワードハッシュの保存形式も一本化する。

---

### 🔴 RSA 鍵がサーバー起動のたびに再生成される (`utils/jwt.go:20-27`)

起動ごとに新しい鍵ペアを生成するため、再起動すると既存の ID トークンが全て無効になる。またスケールアウト時に複数インスタンスで鍵が食い違う。

修正: 鍵をファイルまたは DB/シークレットストアで永続化し、起動時にロードする。存在しない場合のみ生成する。

---

### 🔴 JWKS に `kid` が含まれない (`handlers/oidc/discovery.go:51-57`)、JWT ヘッダーにも `kid` がない

検証側は `kid` で使用鍵を特定する。未設定の場合、複数鍵ローテーション時に検証が壊れる。

修正: 鍵生成時に `kid`（UUIDまたは鍵のフィンガープリント）を決定し、JWK と JWT ヘッダー両方に付与する。

---

### 🟠 GitHub トークン交換がリクエストボディではなくクエリパラメータで送信される (`handlers/oauth/github.go:61`)

```go
// 現状: GET パラメータとして送っている
req.URL.RawQuery = data.Encode()

// 修正: POST ボディとして送る
req, _ = http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
```

GitHub は現状これを受け付けるが、OAuth 2.0 標準（RFC 6749 §4.1.3）ではリクエストボディで送るべき。

---

### 🟠 `HandleDeleteClient` / `HandleDeleteUser` が存在しないリソースでも 200 OK を返す (`handlers/admin/clients.go:156`, `handlers/admin/users.go:114`)

`DELETE` は存在しないリソースに対して 404 を返すべき。`RowsAffected()` で削除件数を確認する。

---

### 🟠 `HandleListClients` でスキャンエラーを `continue` で握りつぶしている (`handlers/admin/clients.go:52`)

行のスキャンに失敗しても無視して次に進む。また `rows.Err()` をループ後に確認していない。

---

## セキュリティ

### 🔴 クライアントシークレットが平文で DB に保存されている (`handlers/admin/clients.go:107`)

漏洩時の影響が大きい。bcrypt またはハッシュ化して保存し、検証時に比較する。
作成時のみ平文を返し、以降は参照不可にする（Auth0 と同様の挙動）。

---

### 🔴 `client_secret_basic`（Authorization ヘッダー認証）が未実装だが Discovery に宣言されている (`handlers/oidc/discovery.go:39`, `handlers/oidc/token.go:53`)

Discovery ドキュメントに `"client_secret_basic"` を宣言しているが、トークンエンドポイントはフォームパラメータ（`client_secret_post`）のみ受け付ける。嘘の Discovery ドキュメントを返している状態。

修正: `Authorization: Basic base64(client_id:client_secret)` の解析を実装するか、Discovery から `client_secret_basic` を除く。

---

### 🔴 PKCE `code_challenge_method` のバリデーションがない (`handlers/oidc/token.go:151-164`)

`S256` 以外はそのままプレーン比較にフォールバックしている。`S256` と `plain` 以外の未知のメソッドを拒否していない。また `plain` は RFC 7636 でセキュリティ上非推奨。

---

### 🟠 認可エンドポイントのスコープが検証されていない (`handlers/oidc/authorization.go:36`)

クライアントに許可されていないスコープをリクエストしても通過する。クライアントの `scope` フィールドと照合して、超過分をエラーまたはダウングレードする必要がある。

---

### 🟠 `context.Background()` を使用している（全ハンドラ）

ハンドラ内の DB クエリが `context.Background()` を使っているため、クライアントが接続を切断してもクエリがキャンセルされない。`c.Request.Context()` を使う。

---

## 未実装機能

### 🔴 認可エンドポイントにログインフローがない (`handlers/oidc/authorization.go:96-104`)

`/oauth/authorize` でユーザーが未認証の場合、401 JSON を返すだけでログインページへリダイレクトしない。ユーザー向けのログイン UI とセッション管理が丸ごと未実装。

必要なもの:
- ユーザー向けログインページ（メールパスワード or 外部プロバイダー選択）
- エンドユーザーセッション（Cookie ベース）の発行・検証ミドルウェア
- 認証後に元の認可リクエストへ戻るリダイレクト

---

### 🔴 外部 OAuth コールバック後のセッション作成が未実装 (`handlers/routes/routes.go:130, 207`)

`// TODO: Create session for user and redirect` コメントのまま。Google / GitHub 経由でログインしたユーザーのセッションが作られず、そのままユーザー情報を JSON で返して終わる。

---

### 🟠 リフレッシュトークンローテーションが未実装 (`handlers/oidc/token.go:265-367`)

リフレッシュトークングラントで新しいリフレッシュトークンを発行していない。古いトークンが無期限に使い回せるため、漏洩リスクが高い。リフレッシュ時に古いトークンを revoke して新しいものを発行する。

---

### 🟠 トークン失効エンドポイント（`/oauth/revoke`）がない

RFC 7009 で定義されているトークン失効エンドポイントが未実装。アクセストークン・リフレッシュトークンの明示的な失効ができない。

---

### 🟠 クライアントの更新 API（PUT）がない

管理 API に `PUT /api/admin/clients/:id` がなく、作成後に redirect_uri 等を変更できない。

---

### 🟡 監査ログが書き込まれていない

`audit_logs` テーブルは定義されているが、どのハンドラからも書き込みがない。管理者操作（クライアント作成・削除、ユーザー削除）や認証イベント（ログイン成功・失敗）を記録する。

---

### 🟡 期限切れトークン・認可コードの掃除処理がない

`authorization_codes`・`access_tokens`・`refresh_tokens` の期限切れレコードが溜まり続ける。バックグラウンドジョブまたは DB スケジューラで定期削除する。

---

## コード品質

### 🟠 `GenerateIDToken` が nonce の有無で異なるコードパスを持つ (`utils/jwt.go:73-113`)

nonce がある場合は `jwt.MapClaims`、ない場合は `Claims` 構造体を使う二重実装。`Claims` に `Nonce` フィールドを追加して統一する。

```go
type Claims struct {
    ...
    Nonce string `json:"nonce,omitempty"`
    jwt.RegisteredClaims
}
```

---

### 🟠 `GenerateAccessToken` が存在するが一度も呼ばれていない (`utils/jwt.go:48-70`)

アクセストークンは不透明トークン（ランダム文字列）として生成・DB 保存されているが、JWT 生成関数だけが残っている。設計方針を決める:
- **不透明トークン維持**: `GenerateAccessToken` を削除
- **JWT アクセストークンに移行**: `GenerateRandomString` による DB 保存をやめ JWT を使う（UserInfo での DB 照会が不要になる）

---

### 🟠 `pq.Array` と `pgx` の混在 (`handlers/admin/clients.go`)

DB ドライバは `pgx/v5` を使っているのに、配列のスキャンに `github.com/lib/pq` の `pq.Array` を使っている。`pgx` ネイティブの配列サポートを使うか、スキャン先を `pgtype.Array` にする。`lib/pq` 依存は除去できる。

---

### 🟠 OAuth ルーティングロジックが `routes/routes.go` に直書きされている

Google・GitHub のコールバックロジック（state 検証、code 交換、ユーザー作成）が `routes.go` に 130 行以上べた書きされている。`handlers/oauth/` 配下のハンドラメソッドに移す。

---

### 🟡 構造化ログが未導入

全て `log.Printf` / `log.Println` で出力している。Go 1.21 標準の `slog` を使い、リクエスト ID・ユーザー ID・クライアント ID などのコンテキストを付与した構造化ログに切り替える。

---

### 🟡 `config.go` でトークン有効期限がハードコード (`config/config.go:61-62`)

`AccessTokenExpiry: 3600` と `RefreshTokenExpiry: 2592000` が環境変数ではなくコード内固定値。環境変数から読み込めるようにする。

---

### 🟡 `User.PasswordHash` フィールドがモデルにあるが DB スキーマに対応カラムがない (`models/models.go:25`)

`models.User` に `PasswordHash *string` が定義されているが `users` テーブルにそのカラムは存在しない。メールパスワード認証を今後追加する場合はマイグレーションも必要。現状は混乱を招くだけなので削除か TODO コメントで意図を明示する。

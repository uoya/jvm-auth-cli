# auth

Web バックエンドの API を叩くためのログイン補助です。OAuth の IdP 通信はバックエンドが行い、このプロセスはブラウザ起動とトークン保存だけです。

```text
sbt "cli/run -- token -- app.env"
scala-cli run cli -- token -- app.env
```

stdout は JSON（`access_token` / `token_type` / 任意で `expires_at`）。`refresh_token` は出しません。引数は [zio-cli](https://zio.dev/zio-cli/) が処理します（`--help` で用法）。

## 構成

| | 役割 |
|---|---|
| 本アプリ（core + CLI） | 認可 URL 取得、ブラウザ、issue / reissue、トークン保存 |
| Web バックエンド | 認可 URL、コード交換、再発行、業務 API、JWT 検証 |
| FusionAuth | 人がログインする IdP |
| ブラウザ | ログイン画面 |

どちらも JVM の Scala です。CLI は fat JAR にせず、sbt または Scala CLI から実行します。Swing など別アプリは `auth-core` を依存に足します。効果型は ZIO、値の制約は Iron、JSON は Circe です。マッピング枠はアプリ側に任せ、core は `Tokens` を返します。

```scala
import auth.core.Auth
import zio.*

val tok: IO[auth.core.AuthError, auth.core.Tokens] =
  Auth.fromEnvFile(java.nio.file.Path.of("app.env")).flatMap(_.access())
// Authorization: Bearer ${tok.accessToken}
```

カスタムスキームで戻ってきた後発プロセスは `Auth.deliverProtocolUri(uri)` を呼びます。先に起動しているインスタンスへ URI を渡し、自分は終了します。

## env ファイル

```
API_BASE_URL=https://backend.example.com
TENANT_ID=acme
```

空でない環境変数がファイルより優先されます。

| キー | 意味 |
|---|---|
| `API_BASE_URL` | バックエンドのベース URL |
| `TENANT_ID` | テナント |
| `REDIRECT_SCHEME` | 省略時 `auth`（戻り URI は `auth://callback`）。`://` を含めるとエラー |
| `TOKEN_FILE` / `OAUTH_OUTFILE` | トークンファイル。省略時は Windows `%AppData%\oauth-token\credentials`、それ以外 `~/.config/oauth-token/credentials` |

## コマンド

```text
sbt "cli/run -- token --timeout 5m -- app.env"
sbt "cli/run -- token --outfile PATH -- app.env"
sbt "cli/run -- logout -- app.env"
sbt "cli/run -- logout --all -- app.env"

scala-cli run cli -- token --timeout 5m -- app.env
scala-cli run cli -- logout -- app.env
```

- `--timeout` は単位必須（`5m` / `30s`）。単位なしの数値はエラーです。
- `logout` は env からパスとテナントキーを決め、**当該テナントだけ**消します。`--all` のときだけファイル全体を削除します。

カスタムスキームの戻り（OS が後発プロセスを起動）:

```text
sbt "cli/run -- auth://callback?code=...&state=..."
```

`http` / `https` / `file` や env パスは callback 判定しません。OS への `auth://`（または `REDIRECT_SCHEME`）登録は利用側の責務です。

## セキュリティ上の契約

- トークンファイルは作成時点から所有者のみ読み書き（POSIX `0600`）。一時ファイルも同様です。
- ログイン待ちの IPC は loopback + 一回限りの nonce（`instance.session`、所有者のみ）。scheme 不一致・過大ペイロードは破棄します。
- callback は `REDIRECT_SCHEME` と一致する URI のみ受理します。認可 URL に `state` があれば callback の `state` と照合します（login CSRF 対策の一端。完全な CSRF 防御はバックエンドの `state` 検証と合わせてください）。
- `expires_at` / `expires_in` が無い・解釈不能なトークンは fresh とみなしません。
- HTTP 400/401 だけ再ログイン。それ以外の失敗ではブラウザを開きません。

## バックエンド API

`GET {API_BASE_URL}/authorize-url?tenantId=&redirect_uri=`

```json
{"authUrl":"https://idp.example/oauth2/authorize?...&state=..."}
```

`POST {API_BASE_URL}/issue`

```json
{"tenantId":"acme","redirectUri":"auth://callback","query":{"code":"...","state":"..."}}
```

```json
{"access_token":"...","token_type":"Bearer","expires_in":3600,"refresh_token":"..."}
```

`POST {API_BASE_URL}/reissue`

```json
{"tenantId":"acme","refresh_token":"..."}
```

## Build

```bash
sbt test
sbt "cli/run -- token -- app.env"
scala-cli run cli -- token -- app.env
```

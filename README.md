# auth

Web バックエンドの API を叩くためのログイン補助です。OAuth の IdP 通信はバックエンドが行い、このプロセスはブラウザ起動とトークン保存だけです。

```text
sbt "cli/run -- token -- app.env"
scala-cli run cli -- token -- app.env
```

stdout は `access_token` のみ。`refresh_token` は出しません。引数は [zio-cli](https://zio.dev/zio-cli/) が処理します（`--help` で用法）。

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
| `REDIRECT_SCHEME` | 省略時 `auth`（戻り URI は `auth://callback`） |
| `TOKEN_FILE` / `OAUTH_OUTFILE` | トークンファイル。省略時は `%AppData%\oauth-token\credentials` |

## コマンド

```text
sbt "cli/run -- token --timeout 5m -- app.env"
sbt "cli/run -- --outfile PATH token -- app.env"
sbt "cli/run -- logout"
sbt "cli/run"

scala-cli run cli -- token --timeout 5m -- app.env
scala-cli run cli -- logout
scala-cli run cli
```

カスタムスキームの戻り:

```text
sbt "cli/run -- auth://callback?code=...&state=..."
```

## バックエンド API

`GET {API_BASE_URL}/authorize-url?tenantId=&redirect_uri=`

```json
{"authUrl":"https://idp.example/oauth2/authorize?..."}
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

400/401 は再ログイン、それ以外の失敗はブラウザを開きません。

## Build

```bash
sbt test
sbt "cli/run -- token -- app.env"
scala-cli run cli -- token -- app.env
```

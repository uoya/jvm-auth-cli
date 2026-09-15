package auth.core

import io.circe.parser
import zio.{UIO, ZIO, durationInt}
import zio.test.*

import com.sun.net.httpserver.{HttpExchange, HttpServer}

import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.time.{Duration, Instant}

object AuthSpec extends ZIOSpecDefault:
  def spec = suite("Auth")(
    test("returns cached access token") {
      val path = Files.createTempDirectory("auth").resolve("credentials")
      val cfg = Config.of("http://127.0.0.1:1", "t1", tokenFile = path)
      for
        _ <- TokenStore.save(path, cfg.storeKey, Tokens("cached", expiresAt = Some(Instant.now.plusSeconds(3600))))
        got <- Auth.fromConfig(cfg).access()
      yield assertTrue(got.accessToken == "cached")
    },
    test("reissue on expiry") {
      ZIO.acquireReleaseWith(ZIO.attempt(MockBackend.start()).orDie)(b => ZIO.succeed(b.close())) { backend =>
        val path = Files.createTempDirectory("auth").resolve("credentials")
        val cfg = Config.of(backend.url, "acme", tokenFile = path)
        for
          _ <- TokenStore.save(
            path,
            cfg.storeKey,
            Tokens("old", "rt-1", expiresAt = Some(Instant.now.minusSeconds(60)))
          )
          got <- Auth(cfg, backend.client).access()
        yield assertTrue(got.accessToken == "reissued", got.refreshToken == "rt-1")
      }
    },
    test("reissue 500 does not login") {
      ZIO.acquireReleaseWith(ZIO.attempt(MockBackend.start(reissueStatus = 500)).orDie)(b => ZIO.succeed(b.close())) { backend =>
        val path = Files.createTempDirectory("auth").resolve("credentials")
        val cfg = Config.of(backend.url, "acme", tokenFile = path)
        for
          _ <- TokenStore.save(
            path,
            cfg.storeKey,
            Tokens("old", "rt-1", expiresAt = Some(Instant.now.minusSeconds(60)))
          )
          err <- Auth(cfg, backend.client).access().flip
        yield assertTrue(err.isInstanceOf[BackendFailed])
      }
    },
    test("login posts callback query to issue") {
      ZIO.acquireReleaseWith(ZIO.attempt(MockBackend.start()).orDie)(b => ZIO.succeed(b.close())) { backend =>
        val dir = Files.createTempDirectory("auth-ipc")
        val prev = Option(java.lang.System.getProperty("auth.instance.dir"))
        java.lang.System.setProperty("auth.instance.dir", dir.toString)
        val path = dir.resolve("credentials")
        val cfg = Config.of(backend.url, "acme", tokenFile = path)
        val restore = ZIO.succeed {
          prev match
            case None    => java.lang.System.clearProperty("auth.instance.dir")
            case Some(v) => java.lang.System.setProperty("auth.instance.dir", v)
        }
        (for
          fiber <- Auth(cfg, backend.client, _ => ZIO.unit).access(Duration.ofSeconds(8)).fork
          ready <- waitPort
          delivered <- Auth.deliverProtocolUri("auth://callback?code=ok&state=s1")
          tok <- fiber.join
        yield assertTrue(ready, delivered, tok.accessToken == "issued", tok.refreshToken == "rt-new"))
          .ensuring(restore)
      }
    },
    test("callback state mismatch fails") {
      assertTrue(
        try
          Auth.parseCallback("auth://callback?code=ok&state=other", "auth", Some("s1"))
          false
        catch case e: AuthError => e.getMessage.contains("state")
      )
    },
    test("callback scheme mismatch fails") {
      assertTrue(
        try
          Auth.parseCallback("https://evil.example/callback?code=ok", "auth", None)
          false
        catch case e: AuthError => e.getMessage.contains("scheme")
      )
    }
  ) @@ TestAspect.withLiveClock

  private def waitPort: UIO[Boolean] =
    def go(i: Int): UIO[Boolean] =
      if Files.exists(SingleInstance.portPath) then ZIO.succeed(true)
      else if i >= 80 then ZIO.succeed(false)
      else ZIO.sleep(50.millis) *> go(i + 1)
    go(0)

final class MockBackend(server: HttpServer, val client: Backend, val url: String):
  def close(): Unit = server.stop(0)

object MockBackend:
  def start(reissueStatus: Int = 200): MockBackend =
    val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
    server.createContext(
      "/authorize-url",
      (ex: HttpExchange) =>
        json(ex, 200, """{"authUrl":"https://idp.example/authorize?state=s1"}""")
    )
    server.createContext(
      "/issue",
      (ex: HttpExchange) =>
        val body = read(ex)
        val code = parser.parse(body).toOption.flatMap(_.hcursor.downField("query").get[String]("code").toOption).getOrElse("")
        if code == "ok" then
          json(ex, 200, """{"access_token":"issued","refresh_token":"rt-new","token_type":"Bearer","expires_in":3600}""")
        else json(ex, 400, """{"error":"invalid_grant"}""")
    )
    server.createContext(
      "/reissue",
      (ex: HttpExchange) =>
        if reissueStatus == 200 then
          json(ex, 200, """{"access_token":"reissued","token_type":"Bearer","expires_in":3600}""")
        else json(ex, reissueStatus, """{"error":"server_error"}""")
    )
    server.start()
    val url = s"http://127.0.0.1:${server.getAddress.getPort}"
    new MockBackend(server, new Backend(url), url)

  private def read(ex: HttpExchange) = new String(ex.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)

  private def json(ex: HttpExchange, status: Int, body: String): Unit =
    val bytes = body.getBytes(StandardCharsets.UTF_8)
    ex.getResponseHeaders.set("Content-Type", "application/json")
    ex.sendResponseHeaders(status, bytes.length)
    ex.getResponseBody.write(bytes)
    ex.close()

package auth.core

import io.circe.syntax.*
import zio.{IO, ZIO}

import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.charset.StandardCharsets
import java.time.{Duration, Instant}

final class Backend(apiRoot: String, http: HttpClient = Backend.client):
  def authorizeUrl(tenantId: String, redirectUri: String): IO[AuthError, String] =
    val uri = s"$apiRoot/authorize-url?tenantId=${enc(tenantId)}&redirect_uri=${enc(redirectUri)}"
    send("GET", uri, None).flatMap { n =>
      val url = Json.str(n, "authUrl")
      if url.isEmpty then ZIO.fail(BackendFailed("authorize-url: authUrl がありません"))
      else ZIO.succeed(url)
    }

  def issue(tenantId: String, redirectUri: String, query: Map[String, String]): IO[AuthError, Tokens] =
    val body = io.circe.Json.obj(
      "tenantId" -> tenantId.asJson,
      "redirectUri" -> redirectUri.asJson,
      "query" -> query.asJson
    )
    send("POST", s"$apiRoot/issue", Some(body.noSpaces)).flatMap(readTokens)

  def reissue(tenantId: String, refreshToken: String): IO[AuthError, Tokens] =
    val body = io.circe.Json.obj(
      "tenantId" -> tenantId.asJson,
      "refresh_token" -> refreshToken.asJson
    )
    send("POST", s"$apiRoot/reissue", Some(body.noSpaces)).flatMap(readTokens)

  private def send(method: String, url: String, json: Option[String]): IO[AuthError, io.circe.Json] =
    val b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30))
    val req =
      if method == "GET" then b.GET.build()
      else
        b.header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(json.getOrElse("{}")))
          .build()
    AuthError
      .block(http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)))
      .mapError(e => BackendFailed(e.getMessage))
      .flatMap { resp =>
        val code = resp.statusCode()
        val body = resp.body()
        if code == 400 || code == 401 then ZIO.fail(BackendRejected(s"$method $url: HTTP $code $body"))
        else if code < 200 || code >= 300 then ZIO.fail(BackendFailed(s"$method $url: HTTP $code $body"))
        else
          AuthError.block(Json.parse(body)).mapError(e => BackendFailed(e.getMessage))
      }

  private def readTokens(n: io.circe.Json): IO[AuthError, Tokens] =
    AuthError.block {
      val at = Json.str(n, "access_token")
      if at.isEmpty then throw BackendFailed("token response missing access_token")
      val c = n.hcursor
      val expFromAt =
        c.get[String]("expires_at").toOption.filter(_.nonEmpty).map { s =>
          try Instant.parse(s)
          catch case e: Exception => throw BackendFailed(s"invalid expires_at: $s (${e.getMessage})")
        }
      val expFromIn = readExpiresIn(c).map(sec => Instant.now.plusSeconds(sec))
      Tokens(
        accessToken = at,
        refreshToken = Json.str(n, "refresh_token"),
        tokenType = Option(Json.str(n, "token_type")).filter(_.nonEmpty).getOrElse("Bearer"),
        expiresAt = expFromAt.orElse(expFromIn)
      )
    }

  private def readExpiresIn(c: io.circe.HCursor): Option[Long] =
    c.get[Long]("expires_in").toOption
      .orElse(
        c.get[String]("expires_in").toOption.flatMap { s =>
          val t = s.trim
          if t.isEmpty then None
          else
            try Some(t.toLong)
            catch case _: NumberFormatException => None
        }
      )

  private def enc(s: String) = java.net.URLEncoder.encode(s, StandardCharsets.UTF_8)

object Backend:
  private val client: HttpClient =
    HttpClient.newBuilder.followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(30)).build()

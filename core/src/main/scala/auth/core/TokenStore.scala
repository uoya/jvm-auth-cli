package auth.core

import io.circe.{Json as CirceJson, JsonObject, Printer}
import io.circe.syntax.*
import zio.IO

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, StandardCopyOption}
import java.time.Instant

final case class Tokens(
    accessToken: String,
    refreshToken: String = "",
    tokenType: String = "Bearer",
    expiresAt: Option[Instant] = None
)

object TokenStore:
  private val skew = java.time.Duration.ofSeconds(30)
  private val pretty = Printer.spaces2.copy(dropNullValues = true)

  def defaultPath(env: Map[String, String] = sys.env): Path =
    env.get(Config.OutFile).filter(_.nonEmpty).orElse(env.get(Config.TokenFile).filter(_.nonEmpty)) match
      case Some(p) => Path.of(p)
      case None =>
        val home = Option(java.lang.System.getProperty("user.home")).getOrElse(".")
        val base =
          if windows then
            Option(java.lang.System.getenv("APPDATA")).filter(_.nonEmpty).map(Path.of(_)).getOrElse(Path.of(home))
          else Path.of(home, ".config")
        base.resolve("oauth-token").resolve("credentials")

  def save(path: Path, key: String, tokens: Tokens): IO[AuthError, Unit] =
    AuthError.block:
      val all = read(path)
      write(path, all.add(normalize(key), toJson(tokens)))

  def load(path: Path, key: String): IO[AuthError, Tokens] =
    AuthError.block:
      read(path)(normalize(key)) match
        case None => throw NotLoggedIn
        case Some(n) =>
          val t = fromJson(n)
          if t.accessToken.isEmpty then throw NotLoggedIn
          t

  def remove(path: Path): IO[AuthError, Boolean] =
    AuthError.block(Files.deleteIfExists(path))

  def fresh(t: Tokens, now: Instant = Instant.now): Boolean =
    if t.accessToken.isEmpty then false
    else
      t.expiresAt match
        case None      => t.refreshToken.isEmpty
        case Some(exp) => now.isBefore(exp.minus(skew))

  private def windows = java.lang.System.getProperty("os.name", "").toLowerCase.contains("win")

  private def normalize(key: String) =
    val s = key.trim.replaceAll("/+$", "")
    if s.isEmpty then throw AuthError("store key is required")
    s

  private def read(path: Path): JsonObject =
    if !Files.exists(path) then JsonObject.empty
    else
      val n = Json.parse(new String(Files.readAllBytes(path), StandardCharsets.UTF_8))
      n.asObject.getOrElse(throw AuthError(s"$path: JSON object required"))

  private def write(path: Path, all: JsonObject): Unit =
    Files.createDirectories(Option(path.getParent).getOrElse(Path.of(".")))
    val bytes = pretty.print(CirceJson.fromJsonObject(all)).getBytes(StandardCharsets.UTF_8)
    val tmp = Path.of(path.toString + ".tmp")
    Files.write(tmp, bytes)
    Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    path.toFile.setReadable(false, false)
    path.toFile.setReadable(true, true)
    path.toFile.setWritable(true, true)

  private def toJson(t: Tokens): CirceJson =
    var fields = Vector(
      "access_token" -> t.accessToken.asJson,
      "token_type" -> t.tokenType.asJson
    )
    if t.refreshToken.nonEmpty then fields = fields :+ ("refresh_token" -> t.refreshToken.asJson)
    t.expiresAt.foreach(exp => fields = fields :+ ("expires_at" -> exp.toString.asJson))
    CirceJson.obj(fields*)

  private def fromJson(n: CirceJson) =
    val exp = Json.str(n, "expires_at") match
      case "" => None
      case s  => Some(Instant.parse(s))
    Tokens(
      accessToken = Json.str(n, "access_token"),
      refreshToken = Json.str(n, "refresh_token"),
      tokenType = Option(Json.str(n, "token_type")).filter(_.nonEmpty).getOrElse("Bearer"),
      expiresAt = exp
    )

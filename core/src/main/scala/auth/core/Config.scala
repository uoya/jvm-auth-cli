package auth.core

import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.collection.MinLength

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}

type NonEmptyStr = String :| MinLength[1]

final case class Config(
    apiBaseUrl: NonEmptyStr,
    tenantId: NonEmptyStr,
    redirectScheme: NonEmptyStr,
    tokenFile: Path
):
  def apiRoot: String = apiBaseUrl.trim.replaceAll("/+$", "")
  def redirectUri: String = s"$redirectScheme://callback"
  def storeKey: String = s"$apiRoot|$tenantId"

object Config:
  val ApiBaseUrl = "API_BASE_URL"
  val TenantId = "TENANT_ID"
  val RedirectScheme = "REDIRECT_SCHEME"
  val TokenFile = "TOKEN_FILE"
  val OutFile = "OAUTH_OUTFILE"

  private val DefaultScheme: NonEmptyStr = "auth".refineUnsafe[MinLength[1]]

  def of(
      apiBaseUrl: String,
      tenantId: String,
      redirectScheme: String = "auth",
      tokenFile: Path = TokenStore.defaultPath()
  ): Config =
    fromMap(
      Map(
        ApiBaseUrl -> apiBaseUrl,
        TenantId -> tenantId,
        RedirectScheme -> redirectScheme,
        TokenFile -> tokenFile.toString
      )
    )

  def fromEnvFile(path: Path, environ: Map[String, String] = sys.env): Config =
    fromMap(overlay(loadFile(path), environ))

  def fromMap(env: Map[String, String]): Config =
    val token = env.get(TokenFile).filter(_.nonEmpty).orElse(env.get(OutFile).filter(_.nonEmpty))
    Config(
      apiBaseUrl = need(ApiBaseUrl, env.getOrElse(ApiBaseUrl, "")),
      tenantId = need(TenantId, env.getOrElse(TenantId, "")),
      redirectScheme = env.get(RedirectScheme).map(_.trim).filter(_.nonEmpty).map(need(RedirectScheme, _)).getOrElse(DefaultScheme),
      tokenFile = token.map(Path.of(_)).getOrElse(TokenStore.defaultPath(env))
    )

  def loadFile(path: Path): Map[String, String] =
    if !Files.exists(path) then throw AuthError(s"env $path: not found")
    if Files.isDirectory(path) then throw AuthError(s"$path はディレクトリです。env ファイルを指定してください")
    val raw = Files.readString(path, StandardCharsets.UTF_8)
    if raw.length > 1048576 then throw AuthError(s"env $path: file too large")
    parse(raw)

  def parse(raw: String): Map[String, String] =
    raw.linesIterator
      .map(_.trim)
      .filter(l => l.nonEmpty && !l.startsWith("#"))
      .flatMap { line =>
        val eq = line.indexOf('=')
        if eq <= 0 then None
        else
          val k = line.substring(0, eq).trim
          var v = line.substring(eq + 1).trim
          if v.length >= 2 && ((v.startsWith("\"") && v.endsWith("\"")) || (v.startsWith("'") && v.endsWith("'")))
          then v = v.substring(1, v.length - 1)
          Some(k -> v)
      }
      .toMap

  def overlay(file: Map[String, String], environ: Map[String, String]): Map[String, String] =
    val keys = Seq(ApiBaseUrl, TenantId, RedirectScheme, TokenFile, OutFile)
    keys.foldLeft(file) { (acc, k) =>
      environ.get(k).filter(_.nonEmpty) match
        case Some(v) => acc + (k -> v)
        case None    => acc
    }

  private def need(name: String, raw: String): NonEmptyStr =
    raw.trim.refineEither[MinLength[1]] match
      case Right(v) => v
      case Left(_)  => throw AuthError(s"$name が必要です")

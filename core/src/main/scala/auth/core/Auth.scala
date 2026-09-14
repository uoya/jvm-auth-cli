package auth.core

import zio.{IO, UIO, ZIO, Console}

import java.net.{URI, URLDecoder}
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.time.{Duration, Instant}

/** Embeddable login/token helper. Swing and the CLI both use this. */
final class Auth(
    val config: Config,
    api: Backend,
    openBrowser: String => IO[AuthError, Unit]
):
  def access(timeout: Duration = Duration.ofMinutes(5)): IO[AuthError, Tokens] =
    val deadline = Instant.now.plus(timeout)
    val path = config.tokenFile
    val key = config.storeKey
    TokenStore.load(path, key).foldZIO(
      {
        case NotLoggedIn => login(deadline)
        case e           => ZIO.fail(e)
      },
      saved =>
        if TokenStore.fresh(saved) then ZIO.succeed(saved)
        else if saved.refreshToken.nonEmpty then
          api
            .reissue(config.tenantId, saved.refreshToken)
            .map(keepRefresh(saved, _))
            .flatMap(fresh => TokenStore.save(path, key, fresh).as(fresh))
            .catchSome { case _: BackendRejected => login(deadline) }
        else login(deadline)
    )

  def logout(): IO[AuthError, Unit] =
    TokenStore.remove(config.tokenFile).unit

  def close(): UIO[Unit] = ZIO.unit

  private def login(deadline: Instant): IO[AuthError, Tokens] =
    Console.printLineError("status: login").orDie *>
      SingleInstance.withOwner(deadline) { waiter =>
        for
          url <- api.authorizeUrl(config.tenantId, config.redirectUri)
          _ <- Console.printLineError("Open this URL if the browser does not appear:").orDie
          _ <- Console.printLineError("").orDie
          _ <- Console.printLineError(url).orDie
          _ <- Console.printLineError("").orDie
          _ <- openBrowser(url).catchAll { e =>
            Console.printLineError(s"could not open a browser: ${e.getMessage}").orDie *>
              Console.printLineError("paste the URL above into a browser").orDie
          }
          raw <- waiter.awaitUri(deadline)
          q <- AuthError.block(query(raw))
          issued <- api.issue(config.tenantId, config.redirectUri, q)
          _ <- TokenStore.save(config.tokenFile, config.storeKey, issued)
        yield issued
      }

  private def keepRefresh(old: Tokens, neu: Tokens): Tokens =
    if neu.refreshToken.nonEmpty then neu else neu.copy(refreshToken = old.refreshToken)

  private def query(raw: String): Map[String, String] =
    val uri = URI.create(raw.trim)
    val q = Option(uri.getRawQuery).getOrElse("")
    if q.isEmpty then throw AuthError(s"callback missing query: $raw")
    q.split("&").toSeq.flatMap { part =>
      part.split("=", 2) match
        case Array(k, v) =>
          Some(URLDecoder.decode(k, StandardCharsets.UTF_8) -> URLDecoder.decode(v, StandardCharsets.UTF_8))
        case Array(k) => Some(URLDecoder.decode(k, StandardCharsets.UTF_8) -> "")
        case _        => None
    }.toMap

object Auth:
  def apply(config: Config): Auth =
    new Auth(config, Backend(config.apiRoot), Browser.open)

  def apply(config: Config, backend: Backend): Auth =
    new Auth(config, backend, Browser.open)

  def apply(config: Config, backend: Backend, openBrowser: String => IO[AuthError, Unit]): Auth =
    new Auth(config, backend, openBrowser)

  def fromEnvFile(path: Path, environ: Map[String, String] = sys.env): IO[AuthError, Auth] =
    AuthError.block(Auth(Config.fromEnvFile(path, environ)))

  def fromConfig(config: Config): Auth = Auth(config)

  /** Bring a custom-scheme URI to the already-running owner process. */
  def deliverProtocolUri(uri: String): IO[AuthError, Boolean] = SingleInstance.tryDeliver(uri)

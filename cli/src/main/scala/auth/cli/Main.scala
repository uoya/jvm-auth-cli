package auth.cli

import auth.core.{Auth, AuthError, Config, TokenStore, Tokens}
import io.circe.syntax.*
import zio.cli.*
import zio.cli.HelpDoc.Span.text
import zio.{Console, ExitCode, IO, ZIO, ZIOAppArgs}

import java.nio.file.{Files, Path}
import java.time.Duration
import java.time.format.DateTimeFormatter

sealed trait Cmd
object Cmd:
  final case class Token(env: Path, timeout: Duration, outfile: Option[Path]) extends Cmd
  final case class Logout(outfile: Option[Path]) extends Cmd
  final case class Callback(uri: String) extends Cmd

object Main extends ZIOCliDefault:
  private val outfile =
    Options.file("outfile", Exists.Either).optional ?? "TOKEN_FILE の上書き"

  private val timeout =
    Options
      .text("timeout")
      .mapOrFail(parseDuration)
      .withDefault(Duration.ofMinutes(5)) ?? "ブラウザログインの待ち時間（既定 5m）"

  private val tokenIn: Options[(Option[Path], Duration)] = outfile ++ timeout

  private val token: Command[Cmd] =
    Command("token", tokenIn, Args.file("env", Exists.Yes) ?? "設定.env")
      .map { (in: (Option[Path], Duration), env: Path) =>
        val (out, to) = in
        Cmd.Token(env, to, out)
      }
      .withHelp("利用可能な access_token を標準出力へ JSON で出す")

  private val logout: Command[Cmd] =
    Command("logout", outfile)
      .map(out => Cmd.Logout(out))
      .withHelp("トークンファイルを削除する")

  val command: Command[Cmd] =
    Command("auth").subcommands(token, logout)

  val cliApp = CliApp.make(
    name = "auth",
    version = "0.1.0",
    summary = text("Web API クライアント（ログイン補助）"),
    command = command
  )(runCmd)

  /** OS のカスタムスキーム起動だけ先に拾い、残りは zio-cli。 */
  override def run =
    ZIOAppArgs.getArgs.flatMap { args =>
      args.find(isProtocol) match
        case Some(uri) =>
          runCmd(Cmd.Callback(uri)).catchAll(fail)
        case None =>
          cliApp.run(args.toList).catchAll {
            case CliError.Parsing(_)            => exit(ExitCode.failure)
            case CliError.Execution(e: AuthError) => fail(e)
            case e                              => fail(AuthError(e.getMessage))
          }.unit
    }

  def runCmd(cmd: Cmd): IO[AuthError, Unit] =
    cmd match
      case Cmd.Token(env, timeout, outfile) =>
        for
          cfg0 <- AuthError.block(Config.fromEnvFile(env))
          cfg = outfile.fold(cfg0)(o => cfg0.copy(tokenFile = o))
          tok <- Auth.fromConfig(cfg).access(timeout)
          _ <- Console.printLine(stdoutJson(tok)).orDie
        yield ()
      case Cmd.Logout(outfile) =>
        val path = outfile.getOrElse(TokenStore.defaultPath())
        for
          existed <- AuthError.block(Files.exists(path))
          _ <- TokenStore.remove(path)
          _ <-
            if existed then Console.printLineError(s"logged out; removed $path").orDie
            else Console.printLineError(s"logged out; no token file at $path").orDie
        yield ()
      case Cmd.Callback(uri) =>
        Auth.deliverProtocolUri(uri).flatMap { ok =>
          if ok then ZIO.unit else ZIO.fail(AuthError("受け側の本アプリが見つかりません"))
        }

  private def fail(e: AuthError) =
    Console.printLineError("error: " + e.getMessage).orDie *> exit(ExitCode.failure)

  private def isProtocol(a: String) =
    a.contains("://") && !a.startsWith("-")

  private def stdoutJson(tok: Tokens): String =
    var fields = Vector(
      "access_token" -> tok.accessToken.asJson,
      "token_type" -> tok.tokenType.asJson
    )
    tok.expiresAt.foreach(exp => fields = fields :+ ("expires_at" -> DateTimeFormatter.ISO_INSTANT.format(exp).asJson))
    io.circe.Json.obj(fields*).noSpaces

  private def parseDuration(s: String): Either[ValidationError, Duration] =
    try
      val d = scala.concurrent.duration.Duration(s)
      if d.isFinite then Right(Duration.ofNanos(d.toNanos))
      else Left(invalidDuration(s))
    catch case e: Exception =>
      Left(ValidationError(ValidationErrorType.InvalidArgument, HelpDoc.p(Option(e.getMessage).getOrElse(s"invalid duration \"$s\""))))

  private def invalidDuration(s: String) =
    ValidationError(ValidationErrorType.InvalidArgument, HelpDoc.p(s"invalid duration \"$s\""))

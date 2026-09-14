package auth.core

import zio.{IO, ZIO}

sealed abstract class AuthError(message: String) extends Exception(message)

object AuthError:
  def apply(message: String): AuthError = General(message)

  def block[A](a: => A): IO[AuthError, A] =
    ZIO.attemptBlocking(a).mapError {
      case e: AuthError => e
      case e            => AuthError(Option(e.getMessage).getOrElse(e.toString))
    }

final case class General(message: String) extends AuthError(message)
case object NotLoggedIn extends AuthError("not logged in")
final class BackendRejected(message: String) extends AuthError(message)
final class BackendFailed(message: String) extends AuthError(message)

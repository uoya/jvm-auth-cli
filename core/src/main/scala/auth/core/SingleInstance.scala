package auth.core

import io.circe.syntax.*
import zio.{IO, ZIO, durationInt}

import java.net.{InetAddress, InetSocketAddress, Socket, ServerSocket}
import java.nio.channels.{FileChannel, FileLock, OverlappingFileLockException}
import java.nio.charset.StandardCharsets
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.{Files, Path, StandardCopyOption, StandardOpenOption}
import java.time.Instant
import java.util.UUID
import java.util.concurrent.{ArrayBlockingQueue, TimeUnit}

/** Process-lifetime singleton: file lock as mutex, loopback socket as the pipe. */
object SingleInstance:
  private val MaxPayloadBytes = 8192
  private val OwnerOnly = PosixFilePermissions.fromString("rw-------")

  def dir: Path =
    Option(java.lang.System.getProperty("auth.instance.dir")).filter(_.nonEmpty).map(Path.of(_))
      .getOrElse(TokenStore.defaultPath().getParent)
  def lockPath: Path = dir.resolve("instance.lock")
  def sessionPath: Path = dir.resolve("instance.session")

  /** Compatibility alias used by tests waiting for the owner to become ready. */
  def portPath: Path = sessionPath

  def tryDeliver(uri: String): IO[AuthError, Boolean] =
    ZIO.acquireReleaseWith(openLock())(ch => ZIO.attempt(ch.close()).orDie) { ch =>
      AuthError.block(acquire(ch)).flatMap {
        case lock if lock != null => AuthError.block(lock.release()).as(false)
        case _                    => send(uri).as(true)
      }
    }

  def withOwner[A](deadline: Instant, redirectScheme: String)(fn: Waiter => IO[AuthError, A]): IO[AuthError, A] =
    ZIO.acquireReleaseWith(openLock())(ch => ZIO.attempt(ch.close()).orDie) { ch =>
      for
        lock <- waitLock(ch, deadline)
        waiter <- AuthError.block(Waiter.start(redirectScheme))
        _ <- AuthError.block(writeSession(waiter.port, waiter.nonce, redirectScheme, deadline))
        out <- fn(waiter).ensuring(
          ZIO.attempt {
            waiter.close()
            Files.deleteIfExists(sessionPath)
            lock.release()
          }.orDie
        )
      yield out
    }

  final class Waiter private (
      server: ServerSocket,
      q: ArrayBlockingQueue[String],
      val nonce: String,
      redirectScheme: String
  ):
    def port: Int = server.getLocalPort
    def awaitUri(deadline: Instant): IO[AuthError, String] =
      AuthError.block:
        val ms = math.max(1L, java.time.Duration.between(Instant.now, deadline).toMillis)
        Option(q.poll(ms, TimeUnit.MILLISECONDS)).getOrElse(throw AuthError("timed out waiting for browser login"))
    def close(): Unit =
      try server.close()
      catch case _: Exception => ()

  object Waiter:
    def start(redirectScheme: String): Waiter =
      val q = new ArrayBlockingQueue[String](1)
      val server = new ServerSocket()
      server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
      val nonce = UUID.randomUUID().toString
      val waiter = new Waiter(server, q, nonce, redirectScheme)
      val t = new Thread(
        () =>
          try
            val s = server.accept()
            try
              val bytes = s.getInputStream.readNBytes(MaxPayloadBytes + 1)
              if bytes.length <= MaxPayloadBytes then
                parsePayload(new String(bytes, StandardCharsets.UTF_8).trim) match
                  case Some((gotNonce, uri)) if gotNonce == nonce && schemeOk(uri, redirectScheme) =>
                    q.offer(uri)
                    ()
                  case _ => ()
            finally s.close()
          catch case _: Exception => ()
        ,
        "auth-ipc"
      )
      t.setDaemon(true)
      t.start()
      waiter

  private def schemeOk(uri: String, expected: String): Boolean =
    try
      val s = java.net.URI.create(uri.trim).getScheme
      s != null && s.equalsIgnoreCase(expected)
    catch case _: Exception => false

  private def parsePayload(raw: String): Option[(String, String)] =
    val nl = raw.indexOf('\n')
    if nl <= 0 then None
    else
      val nonce = raw.substring(0, nl).trim
      val uri = raw.substring(nl + 1).trim
      if nonce.isEmpty || uri.isEmpty then None else Some(nonce -> uri)

  private def writeSession(port: Int, nonce: String, scheme: String, deadline: Instant): Unit =
    Files.createDirectories(dir)
    val json = io.circe.Json
      .obj(
        "port" -> port.asJson,
        "nonce" -> nonce.asJson,
        "scheme" -> scheme.asJson,
        "expires_at" -> deadline.toString.asJson
      )
      .noSpaces
      .getBytes(StandardCharsets.UTF_8)
    val tmp = Path.of(sessionPath.toString + ".tmp")
    Files.deleteIfExists(tmp)
    createOwnerOnly(tmp)
    Files.write(tmp, json)
    restrictOwnerOnly(tmp)
    Files.move(tmp, sessionPath, StandardCopyOption.REPLACE_EXISTING)
    restrictOwnerOnly(sessionPath)

  private def readSession(): Option[(Int, String)] =
    if !Files.exists(sessionPath) then None
    else
      val n = Json.parse(Files.readString(sessionPath, StandardCharsets.UTF_8))
      val c = n.hcursor
      for
        port <- c.get[Int]("port").toOption
        nonce <- c.get[String]("nonce").toOption.filter(_.nonEmpty)
        expStr <- c.get[String]("expires_at").toOption
        exp <- scala.util.Try(Instant.parse(expStr)).toOption
        if Instant.now.isBefore(exp)
      yield (port, nonce)

  private def createOwnerOnly(path: Path): Unit =
    try
      Files.createFile(path, PosixFilePermissions.asFileAttribute(OwnerOnly))
    catch
      case _: UnsupportedOperationException =>
        Files.createFile(path)
        restrictOwnerOnly(path)

  private def restrictOwnerOnly(path: Path): Unit =
    try Files.setPosixFilePermissions(path, OwnerOnly)
    catch
      case _: UnsupportedOperationException =>
        val f = path.toFile
        val ok =
          f.setReadable(false, false) &&
            f.setWritable(false, false) &&
            f.setExecutable(false, false) &&
            f.setReadable(true, true) &&
            f.setWritable(true, true)
        if !ok then throw AuthError(s"$path: could not restrict file permissions to owner-only")

  private def openLock(): IO[AuthError, FileChannel] =
    AuthError.block:
      Files.createDirectories(dir)
      // Keep the same inode; never unlink so a third party cannot recreate the lock file.
      FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)

  private def waitLock(ch: FileChannel, deadline: Instant): IO[AuthError, FileLock] =
    AuthError.block(acquire(ch)).flatMap {
      case lock if lock != null => ZIO.succeed(lock)
      case _ =>
        ZIO.suspendSucceed:
          if Instant.now.isAfter(deadline) then ZIO.fail(AuthError("timed out waiting for single instance"))
          else ZIO.sleep(50.millis) *> waitLock(ch, deadline)
    }

  private def acquire(ch: FileChannel): FileLock =
    try ch.tryLock()
    catch case _: OverlappingFileLockException => null

  private def send(uri: String): IO[AuthError, Unit] =
    def once: IO[AuthError, Boolean] =
      AuthError.block:
        readSession() match
          case None => false
          case Some((port, nonce)) =>
            val payload = (nonce + "\n" + uri).getBytes(StandardCharsets.UTF_8)
            if payload.length > MaxPayloadBytes then
              throw AuthError(s"callback payload too large (${payload.length} > $MaxPayloadBytes)")
            val s = new Socket()
            try
              s.connect(new InetSocketAddress("127.0.0.1", port), 200)
              s.getOutputStream.write(payload)
              true
            finally s.close()

    def loop(i: Int, last: Option[AuthError]): IO[AuthError, Unit] =
      if i >= 40 then ZIO.fail(last.getOrElse(AuthError("running instance not reachable: no session")))
      else
        once.foldZIO(
          e => ZIO.sleep(50.millis) *> loop(i + 1, Some(e)),
          ok => if ok then ZIO.unit else ZIO.sleep(50.millis) *> loop(i + 1, last)
        )

    loop(0, None)

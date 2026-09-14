package auth.core

import zio.{IO, ZIO, durationInt}

import java.net.{InetAddress, InetSocketAddress, Socket, ServerSocket}
import java.nio.channels.{FileChannel, FileLock, OverlappingFileLockException}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, StandardOpenOption}
import java.time.Instant
import java.util.concurrent.{ArrayBlockingQueue, TimeUnit}

/** Process-lifetime singleton: file lock as mutex, loopback socket as the pipe. */
object SingleInstance:
  def dir: Path =
    Option(java.lang.System.getProperty("auth.instance.dir")).filter(_.nonEmpty).map(Path.of(_))
      .getOrElse(TokenStore.defaultPath().getParent)
  def lockPath: Path = dir.resolve("instance.lock")
  def portPath: Path = dir.resolve("instance.port")

  def tryDeliver(uri: String): IO[AuthError, Boolean] =
    ZIO.acquireReleaseWith(openLock())(ch => ZIO.attempt(ch.close()).orDie) { ch =>
      AuthError.block(acquire(ch)).flatMap {
        case lock if lock != null => AuthError.block(lock.release()).as(false)
        case _                    => send(uri).as(true)
      }
    }

  def withOwner[A](deadline: Instant)(fn: Waiter => IO[AuthError, A]): IO[AuthError, A] =
    ZIO.acquireReleaseWith(openLock())(ch => ZIO.attempt(ch.close()).orDie) { ch =>
      for
        lock <- waitLock(ch, deadline)
        waiter <- AuthError.block(Waiter.start())
        _ <- AuthError.block(Files.writeString(portPath, waiter.port.toString, StandardCharsets.UTF_8))
        out <- fn(waiter).ensuring(
          ZIO.attempt {
            waiter.close()
            Files.deleteIfExists(portPath)
            lock.release()
          }.orDie
        )
      yield out
    }

  final class Waiter private (server: ServerSocket, q: ArrayBlockingQueue[String]):
    def port: Int = server.getLocalPort
    def awaitUri(deadline: Instant): IO[AuthError, String] =
      AuthError.block:
        val ms = math.max(1L, java.time.Duration.between(Instant.now, deadline).toMillis)
        Option(q.poll(ms, TimeUnit.MILLISECONDS)).getOrElse(throw AuthError("timed out waiting for browser login"))
    def close(): Unit =
      try server.close()
      catch case _: Exception => ()

  object Waiter:
    def start(): Waiter =
      val q = new ArrayBlockingQueue[String](1)
      val server = new ServerSocket()
      server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
      val waiter = new Waiter(server, q)
      val t = new Thread(
        () =>
          try
            val s = server.accept()
            try
              val line = new String(s.getInputStream.readAllBytes(), StandardCharsets.UTF_8).trim
              q.offer(line)
              ()
            finally s.close()
          catch case _: Exception => ()
        ,
        "auth-ipc"
      )
      t.setDaemon(true)
      t.start()
      waiter

  private def openLock(): IO[AuthError, FileChannel] =
    AuthError.block:
      Files.createDirectories(dir)
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
        if !Files.exists(portPath) then false
        else
          val port = Files.readString(portPath, StandardCharsets.UTF_8).trim.toInt
          val s = new Socket()
          try
            s.connect(new InetSocketAddress("127.0.0.1", port), 200)
            s.getOutputStream.write(uri.getBytes(StandardCharsets.UTF_8))
            true
          finally s.close()

    def loop(i: Int, last: Option[AuthError]): IO[AuthError, Unit] =
      if i >= 40 then ZIO.fail(last.getOrElse(AuthError("running instance not reachable: no port")))
      else
        once.foldZIO(
          e => ZIO.sleep(50.millis) *> loop(i + 1, Some(e)),
          ok => if ok then ZIO.unit else ZIO.sleep(50.millis) *> loop(i + 1, last)
        )

    loop(0, None)

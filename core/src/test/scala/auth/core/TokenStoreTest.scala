package auth.core

import zio.test.*

import java.nio.file.Files
import java.time.Instant

object TokenStoreSpec extends ZIOSpecDefault:
  def spec = suite("TokenStore")(
    test("saves two tenants in one file") {
      val path = Files.createTempDirectory("auth").resolve("credentials")
      for
        _ <- TokenStore.save(path, "https://api|a", Tokens("at-a", "rt-a"))
        _ <- TokenStore.save(path, "https://api|b", Tokens("at-b"))
        a <- TokenStore.load(path, "https://api|a")
        b <- TokenStore.load(path, "https://api|b")
        removed <- TokenStore.remove(path, "https://api|a")
        stillB <- TokenStore.load(path, "https://api|b")
        missing <- TokenStore.load(path, "https://api|a").flip
        _ <- TokenStore.removeAll(path)
        gone <- TokenStore.load(path, "https://api|b").flip
      yield assertTrue(
        a.accessToken == "at-a",
        b.accessToken == "at-b",
        removed,
        stillB.accessToken == "at-b",
        missing == NotLoggedIn,
        gone == NotLoggedIn
      )
    },
    test("freshness") {
      val live = Tokens("a", expiresAt = Some(Instant.now.plusSeconds(3600)))
      val stale = Tokens("a", refreshToken = "r", expiresAt = Some(Instant.now.minusSeconds(5)))
      val unknownWithRt = Tokens("a", refreshToken = "r")
      val unknownNoRt = Tokens("a")
      assertTrue(
        TokenStore.fresh(live),
        !TokenStore.fresh(stale),
        !TokenStore.fresh(unknownWithRt),
        !TokenStore.fresh(unknownNoRt)
      )
    },
    test("owner-only permissions on posix") {
      val path = Files.createTempDirectory("auth").resolve("credentials")
      for
        _ <- TokenStore.save(path, "https://api|a", Tokens("secret", "rt"))
        perms <- AuthError.block:
          try
            val p = Files.getPosixFilePermissions(path)
            !p.contains(java.nio.file.attribute.PosixFilePermission.GROUP_READ) &&
            !p.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_READ) &&
            !p.contains(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE) &&
            !p.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE)
          catch case _: UnsupportedOperationException => true
      yield assertTrue(perms)
    }
  )

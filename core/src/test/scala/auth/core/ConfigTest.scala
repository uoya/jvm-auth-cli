package auth.core

import zio.test.*

import java.nio.file.Files

object ConfigSpec extends ZIOSpecDefault:
  def spec = suite("Config")(
    test("env file load and process env overlay") {
      val f = Files.createTempFile("auth", ".env")
      Files.writeString(
        f,
        """# comment
          |API_BASE_URL=https://from-file.example
          |TENANT_ID=from-file
          |REDIRECT_SCHEME=myapp
          |""".stripMargin
      )
      val cfg = Config.fromEnvFile(f, Map(Config.TenantId -> "from-env", Config.ApiBaseUrl -> ""))
      assertTrue(
        cfg.apiBaseUrl == "https://from-file.example",
        cfg.tenantId == "from-env",
        cfg.redirectUri == "myapp://callback"
      )
    },
    test("missing API_BASE_URL is error") {
      val err = try
        Config.fromMap(Map(Config.TenantId -> "t"))
        None
      catch case e: AuthError => Some(e)
      assertTrue(err.isDefined)
    }
  )

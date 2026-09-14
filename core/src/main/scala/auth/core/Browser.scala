package auth.core

import zio.IO

import java.net.URI

object Browser:
  def open(url: String): IO[AuthError, Unit] =
    AuthError.block:
      if sys.env.get("OAUTH_OPEN_BROWSER").contains("0") then
        throw AuthError("browser launch disabled (OAUTH_OPEN_BROWSER=0)")
      val os = java.lang.System.getProperty("os.name", "").toLowerCase
      if os.contains("win") then
        new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", url).start()
        ()
      else if java.awt.Desktop.isDesktopSupported && java.awt.Desktop.getDesktop.isSupported(java.awt.Desktop.Action.BROWSE)
      then java.awt.Desktop.getDesktop.browse(URI.create(url))
      else throw AuthError(s"no browser helper on $os")

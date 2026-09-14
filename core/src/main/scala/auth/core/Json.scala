package auth.core

import io.circe.{Json as CirceJson, parser}

object Json:
  def parse(text: String): io.circe.Json =
    parser.parse(text).fold(e => throw AuthError(e.message), identity)

  def str(n: CirceJson, field: String): String =
    n.hcursor.get[String](field).toOption.getOrElse("")

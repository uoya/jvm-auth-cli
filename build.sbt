ThisBuild / scalaVersion := "3.3.6"
ThisBuild / organization := "com.github.uoya"

lazy val zioV = "2.1.22"
lazy val circeV = "0.14.10"
lazy val ironV = "2.6.0"

lazy val zioTest = Seq(
  "dev.zio" %% "zio-test" % zioV % Test,
  "dev.zio" %% "zio-test-sbt" % zioV % Test
)

lazy val libs = Seq(
  "dev.zio" %% "zio" % zioV,
  "io.circe" %% "circe-core" % circeV,
  "io.circe" %% "circe-parser" % circeV,
  "io.github.iltotore" %% "iron" % ironV
)

lazy val common = Seq(
  libraryDependencies ++= libs ++ zioTest,
  testFrameworks += new TestFramework("zio.test.sbt.ZTestFramework"),
  scalacOptions ++= Seq("-deprecation", "-feature", "-unchecked")
)

lazy val core = project
  .in(file("core"))
  .settings(common: _*)
  .settings(name := "auth-core")

lazy val cli = project
  .in(file("cli"))
  .dependsOn(core)
  .settings(common: _*)
  .settings(
    name := "auth-cli",
    libraryDependencies += "dev.zio" %% "zio-cli" % "0.7.4",
    Compile / run / mainClass := Some("auth.cli.Main")
  )

lazy val root = project
  .in(file("."))
  .aggregate(core, cli)
  .settings(
    name := "auth",
    publish / skip := true
  )

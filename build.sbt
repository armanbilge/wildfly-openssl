lazy val wildflyOpenssl =
  project.in(file("java"))
  .settings(
    libraryDependencies ++= Seq(
      "org.wildfly.common" % "wildfly-common" % "1.5.4.Final",
      "org.wildfly.openssl" % "wildfly-openssl-linux-x86_64" % "2.2.0.SP01" % Test,
      "junit" % "junit" % "4.8.2" % Test,
      "com.github.sbt" % "junit-interface" % "0.13.2" % Test exclude("junit", "junit")
    ),
    Test / javaOptions ++= Seq(
      "-Dorg.wildfly.openssl.path=/usr/lib/x86_64-linux-gnu",
      s"-Djavax.net.ssl.keyStore=${(Test / resourceDirectory).value}/client.keystore",
      s"-Djavax.net.ssl.trustStore=${(Test / resourceDirectory).value}/client.truststore",
      s"-Djavax.net.ssl.keyStorePassword=password",
    ),
    Test/ fork := true,
  )

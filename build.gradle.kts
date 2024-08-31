import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import com.google.protobuf.gradle.*

plugins {
    `java-library`

    id("com.github.johnrengelman.shadow") version "8.1.1"

    // auto update dependencies with 'useLatestVersions' task
    id("se.patrikerdes.use-latest-versions") version "0.2.18"
    id("com.github.ben-manes.versions") version "0.50.0"

    id("com.google.protobuf") version "0.9.4"
}

dependencies {
    implementation("ch.qos.logback:logback-classic:1.5.4")

    fileTree("libs") {
        include("*.jar")
    }


    // use compile only scope to exclude jadx-core and its dependencies from result jar
    compileOnly("io.github.skylot:jadx-core:1.5.0") {
        isChanging = true
    }

//    implementation(files("libs/jadx-script-runtime-dev.jar"))
//    implementation("io.github.oshai:kotlin-logging-jvm:6.0.4")

    testImplementation("ch.qos.logback:logback-classic:1.4.14")
    testImplementation("org.assertj:assertj-core:3.24.2")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.1")

	// testImplementation("io.github.skylot:jadx-smali-input:1.5.0-SNAPSHOT") {
    //     isChanging = true
    // }

    runtimeOnly("io.grpc:grpc-netty-shaded:1.64.0")
    implementation("io.grpc:grpc-protobuf:1.64.0")
    implementation("io.grpc:grpc-stub:1.64.0")
    implementation("io.grpc:grpc-protobuf:1.15.1")
    compileOnly("org.apache.tomcat:annotations-api:6.0.53") // necessary for Java 9+
}

repositories {
    mavenCentral()
    maven(url = "https://s01.oss.sonatype.org/content/repositories/snapshots/")
    google()
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

version = System.getenv("VERSION") ?: "dev"

tasks {
    withType(Test::class) {
        useJUnitPlatform()
    }
    val shadowJar = withType(ShadowJar::class) {
        archiveClassifier.set("") // remove '-all' suffix
    }

    // fix for grpc issue https://github.com/grpc/grpc-java/issues/10853
    withType<ShadowJar>().configureEach {
        mergeServiceFiles()
    }

    // copy result jar into "build/dist" directory
    register<Copy>("dist") {
        dependsOn(shadowJar)
        dependsOn(withType(Jar::class))

        from(shadowJar)
        into(layout.buildDirectory.dir("dist"))
    }
}

protobuf {
  protoc {
    // The artifact spec for the Protobuf Compiler
    artifact = "com.google.protobuf:protoc:3.25.1"
  }
  plugins {
    // Optional: an artifact spec for a protoc plugin, with "grpc" as
    // the identifier, which can be referred to in the "plugins"
    // container of the "generateProtoTasks" closure.
    id("grpc") {
      artifact = "io.grpc:protoc-gen-grpc-java:1.64.0"
    }
  }
  generateProtoTasks {
    ofSourceSet("main").forEach {
      it.plugins {
        // Apply the "grpc" plugin whose spec is defined above, without
        // options. Note the braces cannot be omitted, otherwise the
        // plugin will not be added. This is because of the implicit way
        // NamedDomainObjectContainer binds the methods.
        id("grpc") { }
      }
    }
  }
}
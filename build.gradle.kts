plugins {
    java
    id("com.gradleup.shadow") version "8.3.6"
}

group = "ai.apisec"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Provided by Burp at runtime. Never bundle it.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.4")

    // Bundled into the extension jar by the shadow plugin.
    implementation("com.google.code.gson:gson:2.11.0")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

// Burp loads the shaded jar so Gson is on the classpath.
// Build with: ./gradlew shadowJar
// Load:       build/libs/apisec-relay-all.jar
tasks.shadowJar {
    archiveClassifier.set("all")
    // Drop bundled dependencies' module descriptors: Burp loads the jar off the
    // classpath, not the module path, so a stray multi-release module-info.class
    // (Gson ships one) is dead weight and can confuse tooling.
    exclude("module-info.class")
    exclude("META-INF/versions/*/module-info.class")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}

tasks.test {
    useJUnitPlatform()
}

// D3 hardening: compile and javadoc as UTF-8 so non-ASCII source is read with the
// right charset. Without this, Windows default charset can mangle UI copy bytes.
tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

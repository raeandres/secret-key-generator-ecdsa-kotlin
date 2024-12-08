plugins {
    kotlin("jvm") version "1.9.23"
}



group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk16
    implementation("org.bouncycastle:bcprov-jdk16:1.45")
    // https://mvnrepository.com/artifact/com.google.crypto.tink/tink
    implementation("com.google.crypto.tink:tink:1.7.0")

    // arg parser (args4j)
    implementation("args4j:args4j:2.37")

    testImplementation("org.jetbrains.kotlin:kotlin-test")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<Jar> {
    manifest {
        attributes["Main-Class"] = "org.example.MainKt"
    }
}
kotlin {
    jvmToolchain(21)
}
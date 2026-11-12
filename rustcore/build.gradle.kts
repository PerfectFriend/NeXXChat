// Модуль Rust-ядра NeXX (libnexxrust.so, JNI com.nexx.rustcore).
// Нативная часть собирается build-rust.sh (cargo + NDK clang) в src/main/jniLibs/<abi>/.
plugins {
  id("com.android.library")
  id("org.jetbrains.kotlin.android")
}

android {
  namespace = "com.nexx.rustcore"
  compileSdk = 35

  defaultConfig {
    minSdk = 26
  }

  sourceSets["main"].jniLibs.srcDir("src/main/jniLibs")

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
  }
}

// Сборка Rust .so для всех ABI. Инкрементальная: входы — исходники крейта.
val buildRustNeXX by tasks.registering(Exec::class) {
  group = "build"
  description = "cargo build libnexxrust.so для arm64-v8a/armeabi-v7a/x86_64 через NDK"
  workingDir = projectDir
  commandLine("bash", "build-rust.sh")
  inputs.files(
    "Cargo.toml",
    "build-rust.sh",
    "src/lib.rs",
    "src/crypto.rs",
    "src/bip39.rs",
    "src/proxy_parse.rs",
    "src/jni_api.rs",
    "src/english.txt"
  )
  outputs.dir("src/main/jniLibs")
}

tasks.named("preBuild") { dependsOn(buildRustNeXX) }

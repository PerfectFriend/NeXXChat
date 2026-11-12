plugins {
    id("com.android.application")
}

android {
    namespace = "chat.nexx.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "chat.nexx.app" // сосуществуем с оригинальным SimpleX
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "0.2.0-nexx-rust"
        ndk {
            // -PnexxAbi=arm64-v8a — APK под один ABI (правило владельца: <Проект>-<abi>-debug.apk)
            val nexxAbi = (project.findProperty("nexxAbi") as String?)
                ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
            if (nexxAbi.isNullOrEmpty()) {
                abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
            } else {
                abiFilters += nexxAbi
            }
        }
    }

    buildTypes {
        release { isMinifyEnabled = false }
        debug { isMinifyEnabled = false }
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

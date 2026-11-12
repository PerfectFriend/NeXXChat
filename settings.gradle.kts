// NeXX — мессенджер с нуля. Свой entry point, свой код с первого кадра.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "NeXX"
include(":app")

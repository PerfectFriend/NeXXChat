# NeXX release proguard rules
# Сохраняем JNI-экспорты libnexxapp.so (имена Java_ chat_nexx_ ... должны выжить)
-keepclasseswithmembernames class * {
    native <methods>;
}
# libv2ray gomobile-классы
-keep class libv2ray.** { *; }
-keep class com.v2ray.** { *; }
# android-activity native entry
-keep class android.app.NativeActivity { *; }
# egui/wgpu reflection не нужен, но keep на всякий для сериализации конфигов
-keep class kotlinx.serialization.** { *; }
-dontwarn kotlinx.serialization.**
# gomobile interfaces
-keep interface libv2ray.Libv2ray$* { *; }

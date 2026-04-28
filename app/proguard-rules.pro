# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-keep,includedescriptorclasses class com.notes.hsnotes.**$$serializer { *; }
-keepclassmembers class com.notes.hsnotes.** {
    *** Companion;
}
-keepclasseswithmembers class com.notes.hsnotes.** {
    kotlinx.serialization.KSerializer serializer(...);
}

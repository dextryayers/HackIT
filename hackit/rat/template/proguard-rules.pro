# Entry points Android reaches by name from the manifest.
-keep class com.hackit.agent.AgentApp { *; }
-keep class com.hackit.agent.MainActivity { *; }
-keep class com.hackit.agent.BeaconService { *; }
-keep class com.hackit.agent.BootReceiver { *; }
-keep class com.hackit.agent.AlarmReceiver { *; }
-keep class com.hackit.agent.SmsReceiver { *; }
-keep class com.hackit.agent.AdminReceiver { *; }
-keep class com.hackit.agent.NotifyMon { *; }
-keep class com.hackit.agent.KeyMon { *; }
-keep class com.hackit.agent.Launcher { *; }

# Accessibility / notification listener metadata is reflective.
-keepclassmembers class * extends android.accessibilityservice.AccessibilityService { *; }
-keepclassmembers class * extends android.service.notification.NotificationListenerService { *; }

# org.json is pulled from the platform, nothing to keep.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

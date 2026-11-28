package com.hackit.agent;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;

/**
 Reported identity overrides. Android hardware/Build fields remain read-only; callers see spoofed meta plus raw status. */
final class Spoof {
    private static final String PREFS = "spoof";
    private static final String[] KEYS = {
            "label", "model", "manufacturer", "brand", "device", "product", "board", "hardware",
            "fingerprint", "bootloader", "android", "sdk", "codename", "serial", "android_id", "hwid",
            "mac", "mac_wifi", "number", "phone", "imei", "meid", "subscriber", "operator", "sid",
            "spec", "package", "pub_ip", "net", "kind",
    };

    static boolean set(Context ctx, String key, String value) {
        if (!allowed(key)) return false;
        String clean = value == null ? "" : value;
        if (clean.length() > 1024) clean = clean.substring(0, 1024);
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(key, clean).commit();
    }

    static boolean clear(Context ctx, String key) {
        SharedPreferences.Editor edit = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit();
        if (key == null || key.isEmpty() || "all".equals(key)) {
            edit.clear();
        } else {
            if (!allowed(key)) return false;
            edit.remove(key);
        }
        return edit.commit();
    }

    static JSONObject snapshot(Context ctx) {
        JSONObject out = new JSONObject();
        SharedPreferences prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        try {
            for (String key : KEYS) {
                if (prefs.contains(key)) out.put(key, prefs.getString(key, ""));
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    static void apply(Context ctx, JSONObject target) {
        SharedPreferences prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        try {
            for (String key : KEYS) {
                if (prefs.contains(key)) target.put(key, prefs.getString(key, ""));
            }
        } catch (Exception ignored) {
        }
    }

    static JSONObject status(Context ctx) {
        JSONObject out = new JSONObject();
        try {
            out.put("overrides", snapshot(ctx));
            out.put("raw", raw(ctx));
            out.put("hardware_spoofed", NativeBridge.available());
        } catch (Exception ignored) {
        }
        return out;
    }

    private static JSONObject raw(Context ctx) {
        JSONObject raw = new JSONObject();
        try {
            raw.put("model", android.os.Build.MODEL);
            raw.put("manufacturer", android.os.Build.MANUFACTURER);
            raw.put("brand", android.os.Build.BRAND);
            raw.put("device", android.os.Build.DEVICE);
            raw.put("product", android.os.Build.PRODUCT);
            raw.put("board", android.os.Build.BOARD);
            raw.put("hardware", android.os.Build.HARDWARE);
            raw.put("fingerprint", android.os.Build.FINGERPRINT);
            raw.put("bootloader", android.os.Build.BOOTLOADER);
            raw.put("android", android.os.Build.VERSION.RELEASE);
            raw.put("sdk", android.os.Build.VERSION.SDK_INT);
            raw.put("serial", android.os.Build.SERIAL);
            raw.put("android_id", Common.androidId(ctx));
            raw.put("hwid", Common.hwidHash(ctx));
            raw.put("mac", Common.mac(ctx));
            raw.put("sid", Common.sid(ctx));
            raw.put("package", ctx.getPackageName());
        } catch (Exception ignored) {
        }
        return raw;
    }

    private static boolean allowed(String key) {
        if (key == null || key.isEmpty()) return false;
        for (String allowed : KEYS) if (allowed.equals(key)) return true;
        return false;
    }

    private Spoof() {
    }
}

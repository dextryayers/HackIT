package com.hackit.agent;

import android.content.Context;

import java.net.URI;

/**
 * JNI bridge to libhackit.so. Every call fails soft: a missing ABI, a stripped
 * library or a blocked load leaves {@link #ready} false and the HTTP path keeps
 * running untouched. The native channel only carries high-rate events.
 */
public final class NativeBridge {
    private static volatile boolean loaded;
    static volatile boolean ready;
    static volatile String currentSid;

    static {
        try {
            System.loadLibrary("hackit");
            loaded = true;
        } catch (Throwable exc) {
            loaded = false;
            Log.d("native lib: " + exc);
        }
    }

    private static native boolean nativeInit(byte[] psk, String host, int port, String sid);

    private static native int nativeSend(String json);

    static native boolean nativeWatch(String directory);

    static native String nativeState();

    static native String nativeProbe(String kind);

    static native String nativeWatchDrain();

    static native void nativeStop();

    static boolean available() {
        return loaded;
    }

    /** Derives the native UDP port: default http port + 100. */
    static int nativePort(Config config) {
        int explicit = config.nativePort;
        if (explicit > 0) {
            return explicit;
        }
        try {
            URI uri = URI.create(config.host);
            int port = uri.getPort();
            if (port < 0) {
                port = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
            }
            return port + 100;
        } catch (Throwable exc) {
            return 8443;
        }
    }

    static boolean init(Context ctx, Config config, String sid) {
        if (!loaded) {
            return false;
        }
        try {
            String host = URI.create(config.host).getHost();
            ready = nativeInit(config.psk, host, nativePort(config), sid);
            currentSid = sid;
            if (ready) {
                Log.d("native channel up " + host + ":" + nativePort(config));
            }
        } catch (Throwable exc) {
            Log.e("native init: " + exc);
            ready = false;
            currentSid = null;
        }
        return ready;
    }

    static boolean send(String json) {
        if (!ready) {
            return false;
        }
        try {
            return nativeSend(json) >= 0;
        } catch (Throwable exc) {
            return false;
        }
    }

    static String state() {
        if (!ready) {
            return "{\"ready\":false}";
        }
        try {
            return nativeState();
        } catch (Throwable exc) {
            return "{\"ready\":true,\"error\":\"" + exc + "\"}";
        }
    }

    static String probe(String kind) {
        try {
            return nativeProbe(kind == null ? "snapshot" : kind);
        } catch (Throwable exc) {
            return "{\"error\":\"" + exc + "\"}";
        }
    }

    static void stop() {
        if (!ready) {
            return;
        }
        try {
            nativeStop();
        } catch (Throwable ignored) {
        }
        ready = false;
    }

    private NativeBridge() {
    }
}
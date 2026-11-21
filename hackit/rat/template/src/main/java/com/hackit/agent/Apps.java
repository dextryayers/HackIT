package com.hackit.agent;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/** Installed package census, system/user split, no version-name string leaks. */
final class Apps {
    private static final int LIMIT = 2000;

    @SuppressWarnings("deprecation")
    static JSONArray dump(Context ctx) {
        JSONArray rows = new JSONArray();
        PackageManager pm = ctx.getPackageManager();
        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(0);
        } catch (Throwable exc) {
            Log.e("apps: " + exc);
            return rows;
        }
        Collections.sort(packages, new Comparator<PackageInfo>() {
            @Override
            public int compare(PackageInfo a, PackageInfo b) {
                return a.packageName.compareToIgnoreCase(b.packageName);
            }
        });
        for (PackageInfo info : packages) {
            if (rows.length() >= LIMIT) {
                break;
            }
            try {
                ApplicationInfo app = info.applicationInfo;
                JSONObject row = new JSONObject();
                row.put("pkg", info.packageName);
                row.put("version", info.versionName == null ? "" : info.versionName);
                row.put("code", info.versionCode);
                row.put("system", (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
                row.put("enabled", app.enabled);
                CharSequence label = pm.getApplicationLabel(app);
                row.put("label", label == null ? "" : label.toString());
                rows.put(row);
            } catch (Throwable ignored) {
            }
        }
        return rows;
    }

    static String launch(Context ctx, String pkg) {
        try {
            android.content.Intent intent = ctx.getPackageManager().getLaunchIntentForPackage(pkg);
            if (intent == null) {
                return "no launcher activity";
            }
            intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
            ctx.startActivity(intent);
            return "launched " + pkg;
        } catch (Throwable exc) {
            return "launch failed: " + exc;
        }
    }

    private Apps() {
    }
}

package com.hackit.agent;

import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Calendar;
import java.util.List;

/** Foreground time per package over a window, for the "what are they doing" view. */
final class UsageMon {
    static JSONArray dump(Context ctx, int days) {
        JSONArray rows = new JSONArray();
        try {
            UsageStatsManager usage = (UsageStatsManager) ctx.getSystemService(Context.USAGE_STATS_SERVICE);
            if (usage == null) {
                return rows;
            }
            Calendar end = Calendar.getInstance();
            Calendar begin = Calendar.getInstance();
            begin.add(Calendar.DAY_OF_YEAR, -Math.max(1, Math.min(days, 30)));
            List<UsageStats> stats = usage.queryUsageStats(UsageStatsManager.INTERVAL_DAILY,
                    begin.getTimeInMillis(), end.getTimeInMillis());
            if (stats == null || stats.isEmpty()) {
                return rows;
            }
            PackageManager pm = ctx.getPackageManager();
            stats.sort((a, b) -> Long.compare(b.getTotalTimeInForeground(), a.getTotalTimeInForeground()));
            for (UsageStats stat : stats) {
                if (rows.length() >= 150) {
                    break;
                }
                if (stat.getTotalTimeInForeground() <= 0) {
                    continue;
                }
                JSONObject row = new JSONObject();
                row.put("pkg", stat.getPackageName());
                row.put("ms", stat.getTotalTimeInForeground());
                row.put("last", stat.getLastTimeUsed());
                row.put("app", stat.getFirstTimeStamp());
                try {
                    ApplicationInfo info = pm.getApplicationInfo(stat.getPackageName(), 0);
                    CharSequence label = pm.getApplicationLabel(info);
                    row.put("label", label == null ? "" : label.toString());
                } catch (Throwable ignored) {
                    row.put("label", "");
                }
                rows.put(row);
            }
        } catch (Throwable exc) {
            Log.d("usage: " + exc);
        }
        return rows;
    }

    private UsageMon() {
    }
}
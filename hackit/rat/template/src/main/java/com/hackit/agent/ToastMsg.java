package com.hackit.agent;

import android.content.Context;
import android.widget.Toast;

/** Toast from any thread, guarded so a finished activity never crashes it. */
final class ToastMsg {
    static void show(final Context ctx, final String message) {
        if (ctx == null) {
            return;
        }
        MediaMon.mainHandler().post(new Runnable() {
            @Override
            public void run() {
                try {
                    Toast.makeText(ctx.getApplicationContext(), message, Toast.LENGTH_SHORT).show();
                } catch (Throwable ignored) {
                }
            }
        });
    }

    private ToastMsg() {
    }
}

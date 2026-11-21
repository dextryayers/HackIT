package com.hackit.agent;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;

/** The launcher alias is what makes the app visible in the drawer. */
final class Launcher {
    private static ComponentName component(Context ctx) {
        return new ComponentName(ctx.getPackageName(), ctx.getPackageName() + ".Launcher");
    }

    static void setEnabled(Context ctx, boolean enabled) {
        try {
            PackageManager pm = ctx.getPackageManager();
            pm.setComponentEnabledSetting(component(ctx),
                    enabled ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                            : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP);
            // Disabling the only launcher entry leaves a stale shortcut on some
            // skins; toggling the module forces the launcher to re-read it.
            pm.setComponentEnabledSetting(new ComponentName(ctx.getPackageName(),
                            ctx.getPackageName() + ".MainActivity"),
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                    PackageManager.DONT_KILL_APP);
            Log.d("launcher " + (enabled ? "on" : "off"));
        } catch (Throwable exc) {
            Log.e("launcher: " + exc);
        }
    }

    static boolean enabled(Context ctx) {
        int state = ctx.getPackageManager().getComponentEnabledSetting(component(ctx));
        return state == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
                || state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
    }

    private Launcher() {
    }
}

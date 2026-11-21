package com.hackit.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Every boot / update / unlock rebuilds the service and the alarms. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent == null ? "" : intent.getAction();
        if (action == null) {
            return;
        }
        Log.d("boot " + action);
        try {
            BeaconService.start(context);
            Scheduler.arm(context);
        } catch (Throwable exc) {
            Log.e("boot: " + exc);
        }
    }
}
